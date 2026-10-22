"""Tests for the Slack scam check (services/scam_check/channels.py,
SlackScamChecks) with a faked Slack Web API and a real ScamCheckService over
fakes: "scam ...", "scam check ...", "is this a scam ..." and "is it a scam
..." check the rest of the DM while "scammers ..." still goes to the chat; a
screenshot shared with "scam" is fetched with the bot token and checked as a
picture, never read as a document; a bare "scam" arms the DM for two minutes;
Slack's own link markup with another label is a mismatch; "stop", "pending"
and "new" still come first and the handler sits before the audio and files
handlers; the switch and the size caps refuse before any download; audio gets
its own reply; the check is saved in the Slack thread with its usage.

Why it exists: a Slack DM that says "scam" carries someone else's message,
often with a screenshot the document reader would otherwise take. The handler
must run before the files handler, fetch only from Slack's own file host with
the bot token, and never turn the pasted message into a chat turn.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

import core.network_security as netsec
from services.agent.shared_content import outside_fences, untrusted_spans
from services.connectors import registry as _connector_registry  # noqa: F401 - registers the network policies
from services.connectors.slack import SlackConnector
from services.notifications import slack as slack_mod
from services.scam_check.channels import (
    CHECKING,
    FILE_TOO_LARGE,
    PICTURE_TOO_LARGE,
    SLACK_ARMED,
    SLACK_DOWNLOAD_FAILED,
    TEXT_UNSUPPORTED_MEDIA,
    SlackScamChecks,
    register_slack,
)
from services.scam_check.verdict import headline
from services.scam_check.web import NO_SERVICE
from tests.conftest import make_user
from tests.test_scam_check_service import (
    PNG,
    SCAM_TEXT,
    USAGE,
    Clock,
    FakeFiles,
    FakeLinks,
    FakeRuntime,
    FakeSettings,
    gate_for,
    scam_rows,
)
from tests.test_scam_check_telegram import scam_service

TEAM = "T0TEAM001"
BOT = "U0BOT0001"
LINKED = "U0HUMAN01"
DM = "D0DM00001"
BOT_TOKEN = "xoxb-scam-test-token"
SHOT_URL = "https://files.slack.com/files-pri/T0TEAM001-F1/download/shot.png"
PDF_URL = "https://files.slack.com/files-pri/T0TEAM001-F2/download/invoice.pdf"
CLIP_URL = "https://files.slack.com/files-pri/T0TEAM001-F3/download/clip.m4a"
PDF = b"%PDF-1.4\n" + b"0" * 64
ON = gate_for({"scam_check": True})


class SlackWeb:
    """Slack's Web API and file host: posts answer ok, files.slack.com serves
    the bytes registered for an address (404 for one marked as gone)."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.files: dict[str, bytes] = {SHOT_URL: PNG, PDF_URL: PDF, CLIP_URL: b"audio"}
        self.gone: set[str] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "files.slack.com":
            if str(request.url) in self.gone:
                return httpx.Response(404, json={"ok": False})
            return httpx.Response(200, content=self.files[str(request.url)])
        return httpx.Response(200, json={"ok": True, "channel": DM, "ts": "1.000100"})

    def posts(self) -> list[str]:
        return [json.loads(r.content)["text"] for r in self.requests if r.url.path.endswith("chat.postMessage")]

    def downloads(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == "files.slack.com"]


class RecordingChat:
    """The chat applier with its file gate: records every turn and gate call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.gate_calls = 0

        async def file_gate():
            self.gate_calls += 1
            return None

        self.file_gate = file_gate

    async def __call__(self, user_id, text, *, new_conversation=False, stop_mark=None, files=None):
        self.calls.append((text, {"new": new_conversation, "files": files}))
        return {"content": "A chat turn answered."}


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True, resolved_ips=("3.3.3.3",)))


def slack_channel(session_factory, web: SlackWeb, user, scam, chat=None) -> slack_mod.SlackChannel:
    connector = SlackConnector.from_credentials({"bot_token": BOT_TOKEN, "app_token": "xapp-test"})
    assert isinstance(connector, SlackConnector)
    connector.set_network_policy("slack")
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(web),
        event_hooks={"request": [connector._enforce_network_policy]},
    )
    channel = slack_mod.SlackChannel(
        connector_id=str(uuid.uuid4()),
        user_id=str(user.id),
        bot_token=BOT_TOKEN,
        app_token="xapp-test",
        session_factory=session_factory,
        chat=chat if chat is not None else RecordingChat(),
        connector=connector,
    )
    channel.team_id, channel.bot_user_id = TEAM, BOT
    link = SimpleNamespace(team_id=TEAM, slack_user_id=LINKED, link_code_hash=None, link_expires_at=None)

    async def load_link():
        return link

    async def no_pause(_seconds):
        return None

    channel._load_link = load_link  # type: ignore[method-assign]
    channel._sleep = no_pause
    channel.scam_check = scam
    return channel


def checks_of(channel) -> SlackScamChecks:
    (handler,) = [h for h in channel._text_handlers if getattr(h, "__name__", "") == "_keyword_scam"]
    return handler.__self__


def dm(text: str, files: list[dict] | None = None) -> dict:
    event = {"type": "message", "channel": DM, "user": LINKED, "ts": "1.2", "channel_type": "im", "text": text}
    if files is not None:
        event["subtype"] = "file_share"
        event["files"] = files
    return {"type": "event_callback", "team_id": TEAM, "event_id": f"Ev{uuid.uuid4().hex[:12]}", "event": event}


def shared(url: str = SHOT_URL, *, name: str = "shot.png", mimetype: str = "image/png", size: int | None = None) -> dict:
    data = SlackWeb().files.get(url, b"")
    return {
        "id": f"F{abs(hash(url)) % 10_000}",
        "name": name,
        "mimetype": mimetype,
        "size": size if size is not None else len(data),
        "url_private_download": url,
    }


async def say(channel, payload: dict) -> None:
    await channel._on_events_api(payload)
    await channel.wait_idle()


def review_text(runtime) -> str:
    return runtime.calls[0]["messages"][0]["content"][0]["text"]


def review_images(runtime) -> list[dict]:
    return runtime.calls[0]["messages"][0]["content"][1:]


def usage_line() -> str:
    from services.usage import format_turn_usage_line

    return format_turn_usage_line(USAGE, "anthropic", "claude-test")


async def slack_rows(session_factory, user_id):
    from models.conversation import Conversation, Message

    async with session_factory() as session:
        conversations = (
            await session.execute(
                select(Conversation).where(Conversation.user_id == user_id).order_by(Conversation.created_at)
            )
        ).scalars().all()
        rows = {
            c.id: (
                await session.execute(
                    select(Message).where(Message.conversation_id == c.id).order_by(Message.created_at)
                )
            ).scalars().all()
            for c in conversations
        }
    return conversations, rows


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "prefix",
    ["scam ", "Scam: ", "scam check ", "SCAM CHECK - ", "is this a scam? ", "Is it a scam, ", "is this scam ", "scam\n"],
)
async def test_scam_and_is_this_a_scam_check_the_rest_of_the_message(session_factory, prefix):
    user, _ = await make_user(session_factory, f"slack-scam-{uuid.uuid4().hex[:8]}@example.com")
    web, chat, runtime, links = SlackWeb(), RecordingChat(), FakeRuntime(), FakeLinks()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime, links=links), chat)
    await say(channel, dm(prefix + SCAM_TEXT))
    assert chat.calls == [] and len(runtime.calls) == 1
    assert untrusted_spans(review_text(runtime)) == [SCAM_TEXT]
    checking, verdict = web.posts()
    assert checking == CHECKING
    assert verdict.startswith(headline("likely_scam")) and verdict.endswith("\n\n" + usage_line())
    (row,) = await scam_rows(session_factory, user.id)
    assert row.endpoint == "slack:scam" and row.reasoning_chain["event"] == "scam_check_ran"
    await channel._connector.close()


@pytest.mark.asyncio
async def test_scammers_mid_sentence_still_goes_to_the_chat(session_factory):
    user, _ = await make_user(session_factory, "slack-scammers@example.com")
    web, chat, runtime = SlackWeb(), RecordingChat(), FakeRuntime()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime), chat)
    texts = ["scammers are awful", "scamming people is a crime", "I think it's a scam", "scampi for dinner?", "is this ok?"]
    for text in texts:
        await say(channel, dm(text))
    assert [text for text, _ in chat.calls] == texts
    assert runtime.calls == [] and CHECKING not in web.posts()
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_screenshot_shared_with_scam_is_fetched_with_the_bot_token_and_checked(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-shot@example.com")
    web, runtime = SlackWeb(), FakeRuntime()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime, links=FakeLinks()))
    await say(channel, dm("scam", files=[shared()]))
    (download,) = web.downloads()
    assert download.url.path.startswith("/files-pri/")
    assert download.headers["Authorization"] == f"Bearer {BOT_TOKEN}"
    assert "The user sent only pictures." in review_text(runtime)
    assert [(b["type"], b["media_type"]) for b in review_images(runtime)] == [("image", "image/png")]
    (row,) = await scam_rows(session_factory, user.id)
    assert row.reasoning_chain["image_sha256"] == [hashlib.sha256(PNG).hexdigest()]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_screenshot_shared_with_scam_never_reaches_document_intake(session_factory, monkeypatch):
    user, _ = await make_user(session_factory, "slack-scam-intake@example.com")
    web, chat, runtime = SlackWeb(), RecordingChat(), FakeRuntime()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    file_turns: list[object] = []

    async def file_turn(message, fresh, stop_mark):
        file_turns.append(message)

    monkeypatch.setattr(channel, "_run_file_turn", file_turn)
    await say(channel, dm("is this a scam? my bank texted me this", files=[shared()]))
    assert file_turns == [] and chat.calls == [] and chat.gate_calls == 0
    assert untrusted_spans(review_text(runtime)) == ["my bank texted me this"]
    assert len(review_images(runtime)) == 1
    # Without the keyword the same share is a document turn as before.
    await say(channel, dm("what is this?", files=[shared()]))
    assert len(file_turns) == 1 and len(runtime.calls) == 1
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_bare_scam_arms_the_dm_and_the_next_message_is_checked(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-armed@example.com")
    web, chat, runtime = SlackWeb(), RecordingChat(), FakeRuntime()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await say(channel, dm("scam"))
    assert web.posts() == [SLACK_ARMED]
    await say(channel, dm(SCAM_TEXT))
    assert chat.calls == [] and untrusted_spans(review_text(runtime)) == [SCAM_TEXT]
    # One message only: the next one is a chat turn again.
    await say(channel, dm("thanks!"))
    assert [text for text, _ in chat.calls] == ["thanks!"]
    # An armed DM takes a shared screenshot with no words too.
    await say(channel, dm("Scam?"))
    await say(channel, dm("", files=[shared()]))
    assert len(runtime.calls) == 2 and len(runtime.calls[1]["messages"][0]["content"]) == 2
    assert [text for text, _ in chat.calls] == ["thanks!"]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_the_armed_dm_expires_after_two_minutes(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-expire@example.com")
    web, chat, runtime = SlackWeb(), RecordingChat(), FakeRuntime()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime), chat)
    clock = Clock()
    checks_of(channel)._clock = clock
    await say(channel, dm("scam"))
    clock.now += 121
    await say(channel, dm("is the library open?"))
    assert [text for text, _ in chat.calls] == ["is the library open?"] and runtime.calls == []
    await channel._connector.close()


@pytest.mark.asyncio
async def test_slack_link_markup_with_another_label_is_a_mismatch(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-markup@example.com")
    web, runtime, links = SlackWeb(), FakeRuntime(), FakeLinks()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime, links=links))
    # Slack wraps every address it sees in <...>: a plain one is still a link, and only the
    # one whose label names another site is a mismatch.
    text = (
        "scam Your account is locked. Sign in: <https://evil-login.example/x|paypal.com> "
        "or see <https://help.evil-login.example/faq> and <http://shop.example|shop.example>"
    )
    await say(channel, dm(text))
    assert links.calls[0]["urls"] == [
        "https://evil-login.example/x",
        "https://help.evil-login.example/faq",
        "http://shop.example",
    ]
    (row,) = await scam_rows(session_factory, user.id)
    assert "anchor_mismatch" in row.reasoning_chain["signals"]
    verdict = web.posts()[-1]
    assert "A link shows paypal" in verdict
    # Defanged: no address in the reply is a link.
    assert "evil-login.example" not in verdict and "paypal.com" not in verdict and "https://" not in verdict
    await channel._connector.close()


@pytest.mark.asyncio
async def test_stop_pending_and_new_still_come_first_and_scam_sits_before_audio_and_files(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-order@example.com")
    web, runtime = SlackWeb(), FakeRuntime(sleep=30)
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime, links=FakeLinks()))
    names = [h.__name__ for h in channel._text_handlers]
    assert names[:6] == [
        "_keyword_stop",
        "_keyword_pending",
        "_keyword_new",
        "_keyword_scam",
        "_keyword_audio",
        "_keyword_files",
    ]
    assert names.count("_keyword_scam") == 1
    register_slack(channel)
    assert [h.__name__ for h in channel._text_handlers].count("_keyword_scam") == 1

    # "stop" cancels a running check: no verdict, nothing saved.
    await channel._on_events_api(dm(f"scam {SCAM_TEXT}"))
    for _ in range(500):
        if runtime.calls:
            break
        await asyncio.sleep(0.01)
    assert runtime.calls
    await say(channel, dm("stop"))
    assert web.posts()[-1].startswith("\u23f9 Stopped.")
    assert not any(post.startswith(headline("likely_scam")) for post in web.posts())
    conversations, _ = await slack_rows(session_factory, user.id)
    assert conversations == []
    await channel._connector.close()


@pytest.mark.asyncio
async def test_the_check_is_saved_in_the_slack_thread_with_usage_columns(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-saved@example.com")
    web = SlackWeb()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, links=FakeLinks()))
    await say(channel, dm(f"scam {SCAM_TEXT}"))
    await say(channel, dm("new"))
    await say(channel, dm("scam Your parcel is held, pay the fee at https://parcel-fee.example/"))
    conversations, rows = await slack_rows(session_factory, user.id)
    assert [c.title for c in conversations] == ["Slack", "Slack"]
    asked, answer = rows[conversations[0].id]
    assert asked.content.startswith("scam\n")
    assert untrusted_spans(asked.content) == [SCAM_TEXT]
    assert SCAM_TEXT not in outside_fences(asked.content)
    assert answer.content.startswith(headline("likely_scam")) and usage_line() not in answer.content
    assert (answer.input_tokens, answer.output_tokens) == (USAGE["input_tokens"], USAGE["output_tokens"])
    assert len(rows[conversations[1].id]) == 2 and channel._fresh is False
    await channel._connector.close()


# ── Refusals before any download ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_switch_off_refuses_in_slack_before_any_download(session_factory):
    from services.capabilities.scam_check import CAPABILITY

    user, _ = await make_user(session_factory, "slack-scam-off@example.com")
    web, chat, runtime = SlackWeb(), RecordingChat(), FakeRuntime()
    off = scam_service(session_factory, gate=gate_for({"scam_check": False}), runtime=runtime)
    channel = slack_channel(session_factory, web, user, off, chat)
    await say(channel, dm("scam", files=[shared()]))
    await say(channel, dm("scam"))
    assert web.posts() == [CAPABILITY.when_denied, CAPABILITY.when_denied]
    assert web.downloads() == [] and runtime.calls == []
    # A refused bare "scam" does not arm the DM.
    await say(channel, dm("hello"))
    assert [text for text, _ in chat.calls] == ["hello"]
    rows = await scam_rows(session_factory, user.id)
    assert [r.reasoning_chain["reason"] for r in rows] == ["capability_off", "capability_off"]
    await channel._connector.close()

    # The owner's daily cap refuses the second check before its download.
    web = SlackWeb()
    capped = scam_service(session_factory, runtime=runtime, settings=FakeSettings(per_day=1))
    channel = slack_channel(session_factory, web, user, capped, chat)
    await say(channel, dm(f"scam {SCAM_TEXT}"))
    await say(channel, dm("scam", files=[shared()]))
    assert "today's 1 scam checks" in web.posts()[-1] and web.downloads() == []
    await channel._connector.close()


@pytest.mark.asyncio
async def test_an_audio_clip_shared_with_scam_gets_the_unsupported_reply_and_is_never_downloaded(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-audio@example.com")
    web, chat, runtime = SlackWeb(), RecordingChat(), FakeRuntime()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime), chat)
    await say(channel, dm("scam", files=[shared(CLIP_URL, name="clip.m4a", mimetype="audio/mp4")]))
    assert web.posts() == [TEXT_UNSUPPORTED_MEDIA]
    assert web.downloads() == [] and runtime.calls == [] and chat.calls == []
    (row,) = await scam_rows(session_factory, user.id)
    assert row.reasoning_chain["reason"] == "unsupported_media"
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_screenshot_over_five_megabytes_is_refused_without_a_download(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-big@example.com")
    web, runtime = SlackWeb(), FakeRuntime()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime))
    await say(channel, dm("scam", files=[shared(size=6 * 1024 * 1024)]))
    await say(channel, dm("scam", files=[shared(PDF_URL, name="invoice.pdf", mimetype="application/pdf", size=21 * 1024 * 1024)]))
    assert web.posts() == [PICTURE_TOO_LARGE, FILE_TOO_LARGE]
    assert web.downloads() == [] and runtime.calls == []
    rows = await scam_rows(session_factory, user.id)
    assert [r.reasoning_chain["reason"] for r in rows] == ["too_large", "too_large"]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_screenshot_that_streams_past_five_megabytes_or_cannot_be_fetched_is_refused(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-stream@example.com")
    web, runtime = SlackWeb(), FakeRuntime()
    web.files[SHOT_URL] = PNG + b"\x00" * (5 * 1024 * 1024)
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime))
    # Slack said it was small; the bytes say otherwise.
    await say(channel, dm("scam", files=[shared(size=len(PNG))]))
    web.gone.add(PDF_URL)
    await say(channel, dm("scam", files=[shared(PDF_URL, name="invoice.pdf", mimetype="application/pdf")]))
    assert web.posts() == [CHECKING, PICTURE_TOO_LARGE, CHECKING, SLACK_DOWNLOAD_FAILED]
    assert runtime.calls == []
    rows = await scam_rows(session_factory, user.id)
    assert [r.reasoning_chain["reason"] for r in rows] == ["too_large", "download_failed"]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_non_image_file_shared_with_scam_is_looked_up_by_fingerprint_only(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-pdf@example.com")
    web, runtime, files = SlackWeb(), FakeRuntime(), FakeFiles()
    channel = slack_channel(session_factory, web, user, scam_service(session_factory, runtime=runtime, files=files))
    await say(channel, dm("scam", files=[shared(PDF_URL, name="invoice.pdf", mimetype="application/pdf")]))
    assert [sha for _, sha, _ in files.calls] == [hashlib.sha256(PDF).hexdigest()]
    assert not hasattr(files, "upload") and runtime.calls == []
    assert "1 file (by fingerprint)" in web.posts()[-1]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_scam_without_a_wired_service_says_so_and_never_starts_a_turn(session_factory):
    user, _ = await make_user(session_factory, "slack-scam-unwired@example.com")
    web, chat = SlackWeb(), RecordingChat()
    channel = slack_channel(session_factory, web, user, None, chat)
    await say(channel, dm(f"scam {SCAM_TEXT}"))
    await say(channel, dm("scam"))
    assert web.posts() == [NO_SERVICE, NO_SERVICE] and chat.calls == []
    assert checks_of(channel)._armed_until is None
    await channel._connector.close()


def test_register_slack_inserts_once_before_audio_else_files_else_at_the_end():
    def named(name):
        def handler(message):
            return None

        handler.__name__ = name
        return handler

    for before, expected in (
        (["_keyword_stop", "_keyword_audio", "_keyword_files"], 1),
        (["_keyword_stop", "_keyword_files"], 1),
        (["_keyword_stop", "_keyword_tutor"], 2),
    ):
        channel = SimpleNamespace(_text_handlers=[named(n) for n in before])
        register_slack(channel)
        register_slack(channel)
        names = [h.__name__ for h in channel._text_handlers]
        assert names.index("_keyword_scam") == expected and names.count("_keyword_scam") == 1
    register_slack(SimpleNamespace())  # no handler list: nothing to do


def test_the_slack_keyword_needs_whitespace_punctuation_or_the_end_after_it():
    from services.scam_check.channels import SLACK_RE

    for text, rest in (
        ("scam", ""),
        ("scam check: hi", "hi"),
        ("Is this a scam?? hi", "hi"),
        ("is it scam - hi", "hi"),
        ("scam!hi", "hi"),
    ):
        match = SLACK_RE.match(text)
        assert match is not None and match.group("rest") == rest, text
    for text in ("scammers are awful", "scamp", "this is a scam", "is this a scammer?", "scam_check"):
        assert SLACK_RE.match(text) is None, text
