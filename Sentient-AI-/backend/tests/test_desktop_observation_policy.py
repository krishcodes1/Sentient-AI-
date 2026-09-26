"""Tests for the latest-observation policy on desktop rounds: only the newest
desktop outline (a desktop.observe outline, or the ``then`` of a desktop.act)
stays in the model's context, and every older one shrinks to one line of facts
that says its refs no longer work. Refusals, errors and app or window lists are
never shrunk; a stale outline takes its own screenshot with it but no other
picture; browser rounds and desktop rounds leave each other's results alone;
turns with neither are sent exactly as before. The measurements show what a
ten-round desktop task sends per round with and without the policy on an
engine that runs acts unattended, and what it saves under the real permission
policy, where every desktop.act ends the turn at its approval card.

Why it exists: one outline is up to ~7,000 chars of JSON (18,000 when the model
asks for the widest), and without this every desktop round resends every older
outline, so a task's cost grows with the square of its step count. Every test
runs the real ComputerToolkit on the in-memory fake desktop and a scripted fake
model: nothing clicks, types or reads the real screen, and no LLM is called.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import pytest

from core.config import settings
from services.agent import cancel
from services.agent import runtime as runtime_module
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    GENERIC_CLOSING_LINE,
    AgentRuntime,
    PermissionEngine,
    Tool,
    compact_desktop_observation,
    desktop_outline_of,
    keep_newest_desktop_outline,
)
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.tools.computer import backend as computer_backend
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.toolkit import ComputerToolkit
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider
from tests.test_browser_runtime import BROWSER_TOOL, WEB_TOOL, outline_result
from tests.test_computer_control_wiring import _gate

U1 = "user-1"
STALE = "A newer outline replaced this one, so its refs no longer work."
WEB_SCREENSHOT_TOOL = Tool(
    name="web.screenshot",
    description="screenshot",
    parameters={"type": "object", "properties": {"url": {"type": "string"}}},
    connector_type="web",
)
DESKTOP_TOOLS = [
    Tool(
        name="desktop.observe",
        description="observe",
        parameters={"type": "object", "properties": {"action": {"type": "string"}}},
        connector_type="desktop",
    ),
    Tool(
        name="desktop.act",
        description="act",
        parameters={"type": "object", "properties": {"action": {"type": "string"}}},
        connector_type="desktop",
    ),
]


# ── helpers ──────────────────────────────────────────────────────────────────


def mail_desktop(rows: int = 0) -> FakeBackend:
    """Mail in front with a compose window (4 outline lines: the window, the
    subject, Send and a password field) plus *rows* message-list rows, and
    TextEdit behind it."""
    listing = tuple(
        make_node("row", f"Message {i} from sender{i}@example.com: weekly project update")
        for i in range(rows)
    )
    return FakeBackend(
        [
            FakeApp(
                "Mail",
                101,
                [
                    FakeWindow(
                        "New Message",
                        (
                            make_node("text field", "Subject", handle="subject", value="Hi"),
                            make_node("button", "Send", handle="send"),
                            make_node("text field", "Password", handle="pw", secure=True),
                            *listing,
                        ),
                    )
                ],
            ),
            FakeApp(
                "TextEdit",
                102,
                [FakeWindow("Notes.txt", (make_node("text area", "Document", handle="doc"),))],
            ),
        ],
        frontmost="Mail",
        focused="subject",
    )


class DesktopExecutor:
    """desktop.observe and desktop.act run on a real ComputerToolkit over the
    fake desktop; any other tool answers from *others*. Before every desktop
    call the Mail window is retitled "Draft <n>", so each outline and each
    summary line names the call it came from."""

    def __init__(
        self,
        fake: FakeBackend,
        others: Optional[list[dict[str, Any]]] = None,
        image: Optional[str] = None,
    ) -> None:
        self.fake = fake
        self.kit = ComputerToolkit(
            fake, cancel_flag=lambda uid: False, image_source=(lambda: image) if image else None
        )
        self.others = list(others or [])
        self.desktop_calls = 0

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        if tool_name in ("desktop.observe", "desktop.act"):
            self.desktop_calls += 1
            self.fake.apps["Mail"].windows[0].title = f"Draft {self.desktop_calls}"
            return await self.kit.execute(tool_name.split(".", 1)[1], arguments, user_id=user_id)
        return self.others.pop(0) if self.others else {"ok": True, "results": []}


def runtime_for(provider: RecordingProvider, executor: Any) -> AgentRuntime:
    # The approve-all stub engine: every desktop.act parks for approval under
    # the real policy (test_computer_control_wiring.py), and this file is
    # about what the loop sends once results exist, not about the policy.
    runtime = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
        tool_executor=executor,
    )
    use_provider(runtime, provider)
    return runtime


def calls(*steps: tuple[str, dict[str, Any]]) -> LLMResponse:
    """One model reply calling every (tool, arguments) in *steps*."""
    return LLMResponse(
        content="",
        tool_calls=[
            ToolCall(id=f"c{i}", name=name, arguments=args) for i, (name, args) in enumerate(steps)
        ],
    )


def observe(**args: Any) -> tuple[str, dict[str, Any]]:
    return ("desktop.observe", {"action": "outline", **args})


def act(**args: Any) -> tuple[str, dict[str, Any]]:
    return ("desktop.act", args)


def text_of(message: dict[str, Any]) -> str:
    content = message["content"]
    return content if isinstance(content, str) else content[0]["text"]


def follow_ups(call: dict[str, Any]) -> list[dict[str, Any]]:
    """The follow-up (tool result) messages of one model request, oldest first."""
    return [
        m
        for m in call["messages"]
        if m["role"] == "user" and text_of(m).startswith("Tool execution finished.")
    ]


def tool_messages(call: dict[str, Any]) -> list[str]:
    """The text of those follow-ups."""
    return [text_of(m) for m in follow_ups(call)]


def picture(letter: str) -> str:
    """A screenshot data URL whose payload is *letter* repeated, so a test
    can tell which result an image block came from."""
    return "data:image/jpeg;base64," + letter * 400


def pictures(message: dict[str, Any]) -> list[str]:
    """The first letter of every image block's payload in *message*."""
    content = message["content"]
    if isinstance(content, str):
        return []
    return [block["data"][0] for block in content if block.get("type") == "image"]


async def run(
    provider: RecordingProvider, executor: Any, tools: list[Tool], *, max_rounds: int = 8
) -> None:
    runtime = runtime_for(provider, executor)
    runtime._max_tool_rounds = max_rounds  # settings.MAX_TOOL_ROUNDS, 8 by default
    await runtime.chat(
        messages=[{"role": "user", "content": "Tidy up the draft in Mail."}],
        tools=tools,
        user_id=U1,
    )


# ── the policy on desktop.observe and desktop.act ────────────────────────────


@pytest.mark.asyncio
async def test_only_the_newest_of_three_outlines_stays_in_full():
    provider = RecordingProvider(
        [calls(observe()), calls(observe()), calls(observe()), LLMResponse(content="done")]
    )
    await run(provider, DesktopExecutor(mail_desktop()), DESKTOP_TOOLS)

    # Refs carry on across outlines: d1-d4, d5-d8, d9-d12.
    second = tool_messages(provider.calls[2])
    assert "[ref=d1]" not in second[0] and STALE in second[0]
    assert "[ref=d5]" in second[1] and "[ref=d8]" in second[1] and STALE not in second[1]

    third = tool_messages(provider.calls[3])
    assert len(third) == 3
    assert "[ref=d9]" in third[2] and "[ref=d12]" in third[2] and STALE not in third[2]
    for n, old in enumerate(third[:2], start=1):
        assert "[ref=d" not in old  # no line of the old outline is left
        assert old.count(STALE) == 1
        assert (
            f'"summary":"outline of Mail, window \\"Draft {n}\\", 4 lines, 4 refs. {STALE}"' in old
        )
    # Only the newest outline's lines are anywhere in the request.
    everything = "\n".join(text_of(m) for m in provider.calls[3]["messages"])
    assert everything.count("[ref=d") == 4


@pytest.mark.asyncio
async def test_act_results_shrink_to_what_they_did_and_their_outline_facts():
    fake = mail_desktop()
    # observe: d1-d4 (Send is d3); the click's then: d5-d8 (Subject is d6);
    # the typing's then: d9-d12.
    provider = RecordingProvider(
        [
            calls(observe()),
            calls(act(action="click", ref="d3")),
            calls(act(action="type", ref="d6", text="hello")),
            LLMResponse(content="done"),
        ]
    )
    await run(provider, DesktopExecutor(fake), DESKTOP_TOOLS)
    assert fake.events == [("click", "send", False), ("type", "hello", "subject")]

    observed, clicked, typed = tool_messages(provider.calls[3])
    assert "[ref=d" not in observed and "outline of Mail" in observed
    assert "[ref=d" not in clicked
    assert (
        '"summary":"did click button \\"Send\\" in Mail; then outline of Mail, '
        f'window \\"Draft 2\\", 4 lines, 4 refs. {STALE}"'
    ) in clicked
    # The newest act keeps its sentence and its whole fresh outline.
    assert '"did":"type 5 characters into text field \\"Subject\\" in Mail"' in typed
    assert "[ref=d9]" in typed and "[ref=d12]" in typed and "Hihello" in typed
    assert STALE not in typed


@pytest.mark.asyncio
async def test_refusals_errors_and_app_lists_are_never_shrunk():
    provider = RecordingProvider(
        [
            calls(observe()),  # d1-d4; the password field is d4
            calls(act(action="type", ref="d4", text="hunter2")),  # refused
            calls(act(action="click", ref="d99")),  # not in the outline
            calls(("desktop.observe", {"action": "apps"})),
            calls(observe()),  # d5-d8
            LLMResponse(content="done"),
        ]
    )
    executor = DesktopExecutor(mail_desktop())
    await run(provider, executor, DESKTOP_TOOLS)
    assert executor.fake.events == []

    observed, refused, failed, apps, newest = tool_messages(provider.calls[5])
    assert STALE in observed and "[ref=d1]" not in observed
    assert '"refused":true' in refused and '"rule":"secure_field"' in refused
    assert "Crawler never types into one" in refused
    assert "d99 is not in the latest outline" in failed and '"stale_ref":true' in failed
    assert '"name":"TextEdit"' in apps and '"name":"Mail"' in apps
    assert "[ref=d5]" in newest
    for kept in (refused, failed, apps, newest):
        assert STALE not in kept


@pytest.mark.asyncio
async def test_an_outlines_screenshot_leaves_context_with_it():
    provider = RecordingProvider(
        [calls(observe(for_model_image=True)), calls(observe()), LLMResponse(content="done")]
    )
    provider.supports_vision = True
    await run(provider, DesktopExecutor(mail_desktop(), image=picture("A")), DESKTOP_TOOLS)
    assert pictures(provider.calls[1]["messages"][-1]) == ["A"]  # sent in round 1
    # Gone in round 2: no message of the request has an image left.
    assert all(isinstance(m["content"], str) for m in provider.calls[2]["messages"])


async def browser_picture_then_desktop_round() -> RecordingProvider:
    """Round 1: a browser.read screenshot for the model and Mail's outline;
    round 2: a newer outline only."""
    executor = DesktopExecutor(
        mail_desktop(), others=[outline_result(1, image=picture("B"), notes=[])]
    )
    provider = RecordingProvider(
        [
            calls(("browser.read", {"action": "screenshot", "for_model": True}), observe()),
            calls(observe()),
            LLMResponse(content="done"),
        ]
    )
    provider.supports_vision = True
    await run(provider, executor, [*DESKTOP_TOOLS, BROWSER_TOOL])
    return provider


@pytest.mark.asyncio
async def test_the_newest_browser_picture_outlives_a_newer_desktop_outline(monkeypatch):
    """The page is still the newest browser observation, so its picture
    stays with its outline and task_facts, as it did before desktop outlines
    were shrunk; only the stale desktop outline goes."""
    provider = await browser_picture_then_desktop_round()
    assert pictures(follow_ups(provider.calls[1])[0]) == ["B"]
    first, _ = follow_ups(provider.calls[2])
    assert pictures(first) == ["B"]
    assert "[ref=e1]" in text_of(first) and "<task_facts>" in text_of(first)
    assert "[ref=d1]" not in text_of(first) and STALE in text_of(first)

    # The same turn without the desktop policy sends the same picture.
    monkeypatch.setattr(runtime_module, "desktop_outline_of", lambda name, result: None)
    provider = await browser_picture_then_desktop_round()
    assert pictures(follow_ups(provider.calls[2])[0]) == ["B"]


@pytest.mark.asyncio
async def test_a_web_screenshot_beside_an_outline_stays_after_newer_outlines():
    executor = DesktopExecutor(
        mail_desktop(), others=[{"ok": True, "image": picture("C")}], image=picture("A")
    )
    provider = RecordingProvider(
        [
            calls(observe(for_model_image=True), ("web.screenshot", {"url": "http://site/grades"})),
            calls(observe()),
            calls(observe()),
            LLMResponse(content="done"),
        ]
    )
    provider.supports_vision = True
    await run(provider, executor, [*DESKTOP_TOOLS, WEB_SCREENSHOT_TOOL])
    assert pictures(follow_ups(provider.calls[1])[0]) == ["A", "C"]
    for later in provider.calls[2:]:
        first = follow_ups(later)[0]
        assert pictures(first) == ["C"] and STALE in text_of(first)


@pytest.mark.asyncio
async def test_a_rewrite_never_brings_in_a_picture_the_round_did_not_send():
    """Round 1 has three pictures: Mail's outline (A), a browser.read page
    (B) and a web.screenshot (C); the per-message cap sends A and B. A newer
    outline takes A away and leaves B without letting C in. A newer browser
    round then makes round 1 text only, as it always did."""
    executor = DesktopExecutor(
        mail_desktop(),
        others=[
            outline_result(1, image=picture("B"), notes=[]),
            {"ok": True, "image": picture("C")},
            outline_result(2, notes=[]),
        ],
        image=picture("A"),
    )
    provider = RecordingProvider(
        [
            calls(
                observe(for_model_image=True),
                ("browser.read", {"action": "screenshot", "for_model": True}),
                ("web.screenshot", {"url": "http://site/grades"}),
            ),
            calls(observe()),
            calls(("browser.read", {"action": "snapshot"})),
            LLMResponse(content="done"),
        ]
    )
    provider.supports_vision = True
    await run(provider, executor, [*DESKTOP_TOOLS, BROWSER_TOOL, WEB_SCREENSHOT_TOOL])

    assert pictures(follow_ups(provider.calls[1])[0]) == ["A", "B"]
    assert pictures(follow_ups(provider.calls[2])[0]) == ["B"]
    first = follow_ups(provider.calls[3])[0]
    assert isinstance(first["content"], str)
    assert "[ref=e1]" not in first["content"] and "<task_facts>" not in first["content"]


@pytest.mark.asyncio
async def test_two_outlines_in_one_round_keep_only_the_second():
    provider = RecordingProvider(
        [calls(observe(), observe(app="TextEdit")), LLMResponse(content="done")]
    )
    await run(provider, DesktopExecutor(mail_desktop()), DESKTOP_TOOLS)
    [message] = tool_messages(provider.calls[1])
    assert "[ref=d1]" not in message  # Mail's outline, replaced by TextEdit's
    assert '"summary":"outline of Mail, window \\"Draft 1\\", 4 lines, 4 refs.' in message
    assert '"app":"TextEdit"' in message and "[ref=d5]" in message and "[ref=d6]" in message


# ── browser and desktop rounds leave each other alone ────────────────────────


@pytest.mark.asyncio
async def test_browser_and_desktop_rounds_only_shrink_their_own_kind():
    executor = DesktopExecutor(
        mail_desktop(),
        others=[
            outline_result(1, notes=["Homework 1 is missing"]),
            outline_result(2, notes=["Homework 1 is missing"]),
        ],
    )
    provider = RecordingProvider(
        [
            calls(observe()),  # desktop d1-d4
            calls(("browser.read", {"action": "open", "url": "http://site/grades"})),  # e1
            calls(("browser.read", {"action": "snapshot"})),  # e2
            calls(observe()),  # desktop d5-d8
            LLMResponse(content="Homework 1 is missing."),
        ]
    )
    await run(provider, executor, [*DESKTOP_TOOLS, BROWSER_TOOL])

    # After the second browser round: the first page shrank, the desktop
    # outline (still the newest one) did not.
    desk, page1, page2 = tool_messages(provider.calls[3])
    assert "[ref=d1]" in desk and STALE not in desk
    assert "[ref=e1]" not in page1 and "[step 1] open site/grades" in page1
    assert "[ref=e2]" in page2 and "<task_facts>" in page2

    # After the second desktop round: the first outline shrank, the newest
    # page kept its outline, its task_facts block and its closing line.
    desk, page1, page2, desk2 = tool_messages(provider.calls[4])
    assert "[ref=d1]" not in desk and STALE in desk
    assert "[ref=e2]" in page2 and "Homework 1 is missing" in page2
    assert page2.rstrip().endswith(
        "Continue the task; call the next browser action or answer when done."
    )
    assert "[ref=d5]" in desk2 and desk2.rstrip().endswith(GENERIC_CLOSING_LINE)


@pytest.mark.asyncio
async def test_a_round_with_both_kinds_shrinks_each_when_its_own_kind_is_replaced():
    executor = DesktopExecutor(
        mail_desktop(), others=[outline_result(1, notes=[]), outline_result(2, notes=[])]
    )
    provider = RecordingProvider(
        [
            calls(("browser.read", {"action": "snapshot"}), observe()),  # e1 and d1-d4
            calls(observe()),  # d5-d8
            calls(("browser.read", {"action": "snapshot"})),  # e2
            LLMResponse(content="done"),
        ]
    )
    await run(provider, executor, [*DESKTOP_TOOLS, BROWSER_TOOL])

    mixed, desk2 = tool_messages(provider.calls[2])
    assert "[ref=d1]" not in mixed and STALE in mixed
    assert "[ref=e1]" in mixed and "<task_facts>" in mixed
    assert "[ref=d5]" in desk2

    mixed, desk2, page2 = tool_messages(provider.calls[3])
    assert "[ref=e1]" not in mixed and "[ref=d1]" not in mixed and STALE in mixed
    assert "<task_facts>" not in mixed
    assert "[ref=d5]" in desk2 and STALE not in desk2
    assert "[ref=e2]" in page2 and "<task_facts>" in page2


@pytest.mark.asyncio
async def test_concurrent_turns_on_one_runtime_keep_their_own_outlines():
    """The slots live in each turn, not on the runtime, so two owners'
    turns at once never shrink each other's outlines. Each turn is on its
    own model so each has its own record of what it was sent."""
    providers = [
        RecordingProvider(
            [calls(observe()), calls(observe()), calls(observe()), LLMResponse(content="done")]
        )
        for _ in range(2)
    ]
    runtime = runtime_for(providers[0], DesktopExecutor(mail_desktop()))
    for n, provider in enumerate(providers):
        use_provider(runtime, provider, pair=("openai", f"model-{n}"))
    await asyncio.gather(
        *(
            runtime.chat(
                messages=[{"role": "user", "content": "Tidy up the draft in Mail."}],
                tools=DESKTOP_TOOLS,
                user_id=f"user-{n}",
                llm_provider="openai",
                llm_model=f"model-{n}",
            )
            for n in range(2)
        )
    )
    for provider in providers:
        assert len(provider.calls) == 4
        assert [STALE in m for m in tool_messages(provider.calls[3])] == [True, True, False]
        # Each owner's toolkit numbers refs from d1, so both see d9-d12 last.
        assert "[ref=d9]" in tool_messages(provider.calls[3])[2]


@pytest.mark.asyncio
async def test_turns_without_a_desktop_outline_are_never_rewritten():
    """Web rounds, app lists and window lists: every request is the previous
    one plus the new messages, byte for byte."""
    provider = RecordingProvider(
        [
            calls(("web.search", {"query": "flights"})),
            calls(("desktop.observe", {"action": "apps"})),
            calls(("desktop.observe", {"action": "windows"})),
            calls(("web.search", {"query": "hotels"})),
            LLMResponse(content="done"),
        ]
    )
    await run(provider, DesktopExecutor(mail_desktop()), [*DESKTOP_TOOLS, WEB_TOOL])
    for earlier, later in zip(provider.calls, provider.calls[1:], strict=False):
        assert later["messages"][: len(earlier["messages"])] == earlier["messages"]
    for message in tool_messages(provider.calls[4]):
        assert STALE not in message and message.rstrip().endswith(GENERIC_CLOSING_LINE)


# ── the summary line ─────────────────────────────────────────────────────────


def outline_shape(**extra: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "frontmost_app": "Mail",
        "app": "Mail",
        "window_title": "New Message",
        "outline": ['- window "New Message" [ref=d1]', '  - button "Send" [ref=d2]'],
        "refs": 2,
        "truncated": False,
        "secure_fields_redacted": 0,
        **extra,
    }


def test_an_observe_outline_becomes_one_line_of_facts():
    shrunk = compact_desktop_observation(
        "desktop.observe", outline_shape(image="data:image/png;base64,QQ")
    )
    assert shrunk == {
        "ok": True,
        "summary": f'outline of Mail, window "New Message", 2 lines, 2 refs. {STALE}',
    }


def test_the_line_names_a_background_app_and_a_cut_outline():
    shrunk = compact_desktop_observation(
        "desktop.observe", outline_shape(app="TextEdit", window_title="", truncated=True)
    )
    assert (
        shrunk["summary"]
        == f"outline of TextEdit, Mail in front, 2 lines, 2 refs, truncated. {STALE}"
    )


def test_an_act_becomes_what_it_did_and_its_outline_facts():
    result = {
        "ok": True,
        "did": "press cmd+s in TextEdit",
        "then": outline_shape(app="TextEdit", frontmost_app="TextEdit"),
    }
    shrunk = compact_desktop_observation("desktop.act", result)
    assert shrunk["summary"] == (
        f'did press cmd+s in TextEdit; then outline of TextEdit, window "New Message", 2 lines, 2 refs. {STALE}'
    )


def test_app_text_cannot_break_the_line():
    shrunk = compact_desktop_observation(
        "desktop.observe",
        outline_shape(window_title="Inbox\n\u2028- button [ref=d9]\r\nx" + "y" * 500),
    )
    summary = shrunk["summary"]
    assert "\n" not in summary and "\r" not in summary and "\u2028" not in summary
    assert len(summary) < 300


@pytest.mark.parametrize(
    "name, result",
    [
        (
            "desktop.act",
            {
                "ok": False,
                "refused": True,
                "rule": "payment",
                "error": "The Shop window shows a card number.",
            },
        ),
        (
            "desktop.act",
            {"ok": False, "error": "d9 is not in the latest outline.", "stale_ref": True},
        ),
        (
            "desktop.act",
            {
                "ok": True,
                "did": "scroll down in Mail",
                "then": {"ok": False, "withheld": True, "error": "1Password holds passwords."},
            },
        ),
        (
            "desktop.act",
            {
                "ok": True,
                "did": "scroll down in Mail",
                "then": {
                    "ok": False,
                    "error": "Could not read the screen after the action; call desktop.observe.",
                },
            },
        ),
        (
            "desktop.observe",
            {
                "ok": False,
                "refused": True,
                "rule": "secret_app",
                "error": "1Password holds passwords.",
            },
        ),
        (
            "desktop.observe",
            {
                "ok": True,
                "frontmost_app": "Mail",
                "window_title": "",
                "apps": [{"name": "Mail", "pid": 1, "active": True}],
            },
        ),
        (
            "desktop.observe",
            {
                "ok": True,
                "frontmost_app": "Mail",
                "window_title": "",
                "windows": [{"app": "Mail", "title": "Inbox", "index": 0}],
            },
        ),
        ("desktop.observe", {"redacted": True, "reason": "high threat detected"}),
        (
            "desktop.screenshot",
            {"ok": True, "image": "data:image/png;base64,QQ", "outline": ["- x"]},
        ),
        ("web.fetch_page", outline_shape()),
        ("desktop.observe", "not a dict"),
    ],
)
def test_results_without_a_desktop_outline_come_back_unchanged(name, result):
    assert desktop_outline_of(name, result) is None
    assert compact_desktop_observation(name, result) == result


def test_one_round_keeps_its_last_outline_and_leaves_the_input_alone():
    results = [
        {"name": "desktop.observe", "tool_call_id": "a", "result": outline_shape()},
        {
            "name": "desktop.act",
            "tool_call_id": "b",
            "result": {"ok": False, "refused": True, "rule": "blocked_key", "error": "no"},
        },
        {
            "name": "desktop.act",
            "tool_call_id": "c",
            "result": {"ok": True, "did": "scroll down in Mail", "then": outline_shape()},
        },
    ]
    kept = keep_newest_desktop_outline(results)
    assert STALE in kept[0]["result"]["summary"]
    assert kept[1] is results[1] and kept[2] is results[2]
    assert results[0]["result"]["outline"]  # the caller's list is untouched
    assert keep_newest_desktop_outline(results[1:]) == results[1:]


# ── what a ten-round desktop task sends ─────────────────────────────────────


async def chars_per_request(rounds: int) -> list[int]:
    """Chars of every model request in a desktop task of *rounds* tool rounds
    (one observe, then acts that each return a fresh outline) on a Mail
    window whose default outline fills the toolkit's 6,000-char cap.

    It runs on the approve-all stub engine, so every act runs inside the
    turn: the upper bound, for an engine that ran acts unattended. Crawler's
    own policy parks every act (the tests after this one)."""
    steps = [calls(observe())] + [
        calls(act(action="scroll", direction="down") if i % 2 else act(action="key", keys="down"))
        for i in range(rounds - 1)
    ]
    provider = RecordingProvider([*steps, LLMResponse(content="done")])
    executor = DesktopExecutor(mail_desktop(rows=100))
    await run(provider, executor, DESKTOP_TOOLS, max_rounds=rounds)
    assert len(executor.fake.events) == rounds - 1  # every act ran
    return [sum(len(text_of(m)) for m in call["messages"]) for call in provider.calls]


@pytest.mark.asyncio
async def test_a_ten_round_desktop_task_sends_one_outline_per_request(monkeypatch):
    after = await chars_per_request(10)
    # Without the policy: what the runtime sent before it (no desktop result
    # is ever recognised as an outline, so nothing shrinks).
    monkeypatch.setattr(runtime_module, "desktop_outline_of", lambda name, result: None)
    before = await chars_per_request(10)

    print("\nrequest  before  after")
    for n, (b, a) in enumerate(zip(before, after, strict=True), start=1):
        print(f"{n:>7}  {b:>6}  {a:>6}")
    print(f"  total  {sum(before):>6}  {sum(after):>6}")

    assert len(before) == len(after) == 11
    assert before[:2] == pytest.approx(after[:2], abs=40)  # one outline: nothing to shrink
    # Each round adds a whole outline without the policy, one line with it.
    before_growth = [b2 - b1 for b1, b2 in zip(before[1:], before[2:], strict=False)]
    after_growth = [a2 - a1 for a1, a2 in zip(after[1:], after[2:], strict=False)]
    assert min(before_growth) > 6000
    assert max(after_growth) < 1500
    assert after[-1] < before[-1] / 3
    # Totals over what the rounds add on top of the first request: that one
    # (system prompt, user message) is sent unchanged in every request of
    # both runs and is not what the policy shrinks, so a longer prompt must
    # not move this ratio.
    assert sum(a - after[0] for a in after) < sum(b - before[0] for b in before) / 3


# ── under the real permission policy ─────────────────────────────────────────


@pytest.fixture
def computer_control_ready(monkeypatch):
    """The platform backend answers as an available fake, so the owner's
    computer_control switch reports on; no stop request is left over."""
    monkeypatch.setattr(
        computer_backend, "select_backend", lambda name: FakeBackend(available=(True, ""))
    )
    cancel.clear(U1)
    yield
    cancel.clear(U1)


async def parked_turn(steps: list[LLMResponse]) -> tuple[list[int], FakeBackend, list[str]]:
    """Run *steps* on the real policy and executor (computer_control on, the
    account default auto_approve, the most permissive there is) over a Mail
    window of 100 message rows. Returns the chars of every model request,
    the fake desktop, and the tools left waiting for approval."""
    fake = mail_desktop(rows=100)
    gate = _gate("computer_control")
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate),
        tool_executor=ConnectorToolExecutor(
            session_factory=None,
            capability_gate=gate,
            computer_toolkit=ComputerToolkit(fake, cancel_flag=cancel.is_cancelled),
        ),
        approval_store=InMemoryApprovalStore(),
    )
    provider = RecordingProvider([*steps, LLMResponse(content="done")])
    use_provider(runtime, provider)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Copy the subject in Mail into Notes.txt."}],
        tools=build_tools(
            [],
            user_default_tier="auto_approve",
            enabled_capabilities=frozenset({"computer_control"}),
        ),
        user_id=U1,
    )
    return (
        [sum(len(text_of(m)) for m in call["messages"]) for call in provider.calls],
        fake,
        [pending.tool_name for pending in response.pending_approvals],
    )


async def parked_turn_without_the_policy(steps: list[LLMResponse]) -> list[int]:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(runtime_module, "desktop_outline_of", lambda name, result: None)
        sent, _, _ = await parked_turn(steps)
    return sent


@pytest.mark.asyncio
async def test_under_the_real_policy_an_act_ends_the_turn_at_its_card(computer_control_ready):
    """The ten-round script above on the real policy: the first act parks and
    the turn ends after two requests with nothing run. One outline leaves
    nothing to shrink, so the requests are the same as without the policy.
    After approval the act runs outside the turn, and its result reaches the
    resumed turn as the decision message (cut to 2,000 chars), which this
    policy does not touch."""
    steps = [calls(observe())] + [calls(act(action="scroll", direction="down")) for _ in range(9)]
    sent, fake, parked = await parked_turn(steps)
    assert fake.events == [] and parked == ["desktop.act"]
    assert len(sent) == 2
    assert sent == await parked_turn_without_the_policy(steps)


@pytest.mark.asyncio
async def test_under_the_real_policy_a_turn_that_reads_several_outlines_saves(
    computer_control_ready,
):
    """What the policy saves in real use: a turn that lists the apps, reads
    Mail, then reads TextEdit before its act parks. Its last request carries
    TextEdit's outline in full and Mail's as one line."""
    steps = [
        calls(("desktop.observe", {"action": "apps"})),
        calls(observe()),
        calls(observe(app="TextEdit")),
        calls(act(action="type", text="Hi")),
    ]
    after, fake, parked = await parked_turn(steps)
    before = await parked_turn_without_the_policy(steps)

    print("\nrequest  before  after  (real policy; the act parks)")
    for n, (b, a) in enumerate(zip(before, after, strict=True), start=1):
        print(f"{n:>7}  {b:>6}  {a:>6}")
    print(f"  total  {sum(before):>6}  {sum(after):>6}")

    assert fake.events == [] and parked == ["desktop.act"]
    assert len(before) == len(after) == 4
    assert before[:3] == after[:3]  # at most one outline so far
    assert before[3] - after[3] > 6000  # Mail's outline, now one line
