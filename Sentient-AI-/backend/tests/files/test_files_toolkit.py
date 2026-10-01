"""Tests for the files.* toolkit and its executor wiring: read windows and
paging, page jumps, the registry's tmp_ documents (hit, expiry, LRU), list
(metadata only), forget's precheck, card sentence and approved delete,
unknown and foreign ids, and the user id always being the executor's.

Why it exists: files.read is how every document reaches the model, so its
windows must fit the runtime's budget and continue exactly where they
stopped, and nobody may read or forget another user's file.
"""

from __future__ import annotations

import json

import pytest

from services.agent.tool_registry import ConnectorToolExecutor
from services.files.documents import read_document
from services.files.limits import CONNECTOR
from services.files.registry import DocumentRegistry
from services.files.sandbox import InProcessSandbox
from services.files.store import UserFileStore
from services.tools.files import FILES_RULE_POLICY, FilesToolkit
from services.tools.text_budget import shown_length
from tests.conftest import make_user
from tests.files import builders as b


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def toolkit(session_factory, registry=None) -> FilesToolkit:
    sandbox = InProcessSandbox()
    return FilesToolkit(
        session_factory,
        store=UserFileStore(session_factory, sandbox=sandbox),
        registry=registry if registry is not None else DocumentRegistry(),
        sandbox=sandbox,
    )


def long_pdf(pages: int = 12) -> bytes:
    return b.make_pdf([f"Page {n} " + ("lorem ipsum dolor sit amet " * 90) for n in range(1, pages + 1)])


async def upload(kit: FilesToolkit, user, data=None, name="deck.pdf"):
    return await kit.store.ingest(str(user.id), data=data or long_pdf(), name=name, declared_mime=None, source="web")


@pytest.mark.asyncio
async def test_read_returns_a_window_that_fits_and_continues(session_factory):
    user, _ = await make_user(session_factory, "window@example.com")
    kit = toolkit(session_factory)
    info = await upload(kit, user)
    first = await kit.execute("read", {"file_id": info.id}, str(user.id))
    assert first["ok"] is True and first["start"] == 1
    assert shown_length(first["sections"]) <= 12000
    assert first["next_start"] == len(first["sections"]) + 1
    assert "files.read" in first["hint"]
    second = await kit.execute("read", {"file_id": info.id, "start": first["next_start"]}, str(user.id))
    assert second["sections"][0]["n"] == first["next_start"]
    seen = [s["n"] for s in first["sections"]] + [s["n"] for s in second["sections"]]
    assert seen == list(range(1, len(seen) + 1))


@pytest.mark.asyncio
async def test_page_jumps_and_start_wins_over_page(session_factory):
    user, _ = await make_user(session_factory, "page@example.com")
    kit = toolkit(session_factory)
    info = await upload(kit, user)
    jumped = await kit.execute("read", {"file_id": info.id, "page": 7}, str(user.id))
    assert jumped["sections"][0]["page"] == 7
    started = await kit.execute("read", {"file_id": info.id, "page": 7, "start": 2}, str(user.id))
    assert started["sections"][0]["n"] == 2
    past = await kit.execute("read", {"file_id": info.id, "page": 99}, str(user.id))
    assert past["ok"] is True and past["sections"] == [] and "page 99" in past["hint"]


@pytest.mark.asyncio
async def test_max_chars_is_clamped_and_measured_as_shown(session_factory):
    user, _ = await make_user(session_factory, "clamp@example.com")
    kit = toolkit(session_factory)
    info = await upload(kit, user)
    small = await kit.execute("read", {"file_id": info.id, "max_chars": 10}, str(user.id))
    assert shown_length(small["sections"]) <= 1000
    assert small["sections"][0].get("clipped") is True
    assert small["next_start"] == 2


@pytest.mark.asyncio
async def test_bad_arguments_are_results_not_exceptions(session_factory):
    user, _ = await make_user(session_factory, "badargs@example.com")
    kit = toolkit(session_factory)
    assert (await kit.execute("read", {}, str(user.id)))["ok"] is False
    assert (await kit.execute("read", {"file_id": "x", "start": 0}, str(user.id)))["ok"] is False
    assert (await kit.execute("list", {"limit": "many"}, str(user.id)))["ok"] is False
    assert (await kit.execute("shred", {}, str(user.id)))["ok"] is False


@pytest.mark.asyncio
async def test_a_tmp_document_is_read_from_the_registry_and_expires(session_factory):
    user, _ = await make_user(session_factory, "tmp@example.com")
    clock = Clock()
    registry = DocumentRegistry(clock=clock)
    kit = toolkit(session_factory, registry)
    opened = await read_document(
        long_pdf(6), name="paper.pdf", declared_mime="application/pdf", source="web",
        preset=CONNECTOR, user_id=str(user.id), registry=registry, sandbox=kit.sandbox,
    )
    doc_id = opened["doc_id"]
    assert doc_id.startswith("tmp_") and opened["next_start"]
    more = await kit.execute("read", {"file_id": doc_id, "start": opened["next_start"]}, str(user.id))
    assert more["ok"] is True and more["source"] == "web"
    clock.now += 31 * 60
    gone = await kit.execute("read", {"file_id": doc_id}, str(user.id))
    assert gone["ok"] is False and gone["code"] == "not_found"
    assert gone["hint"] == "open it again with the tool that opened it"


@pytest.mark.asyncio
async def test_the_registry_is_per_user_and_least_recently_used_goes_first(session_factory):
    from services.files.sections import Extraction, Section

    registry = DocumentRegistry(max_per_user=2)
    doc = Extraction("pdf", "application/pdf", "", 1, (Section("Page 1", 1, "x"),), False)
    a = registry.put("u1", doc, name="a", source="web")
    b_id = registry.put("u1", doc, name="b", source="web")
    assert registry.get("u2", a) is None
    registry.get("u1", a)  # a is now the most recently used
    registry.put("u1", doc, name="c", source="web")
    assert registry.get("u1", b_id) is None and registry.get("u1", a) is not None


@pytest.mark.asyncio
async def test_list_returns_metadata_only(session_factory):
    user, _ = await make_user(session_factory, "list@example.com")
    kit = toolkit(session_factory)
    await upload(kit, user, b.make_pdf(["Secret syllabus text"]), "syllabus.pdf")
    listed = await kit.execute("list", {}, str(user.id))
    assert listed["count"] == 1
    row = listed["files"][0]
    assert row["name"] == "syllabus.pdf" and row["kind"] == "pdf" and row["pages"] == 1
    assert "Secret syllabus text" not in json.dumps(listed)


@pytest.mark.asyncio
async def test_another_users_file_is_not_found_and_a_user_id_argument_is_ignored(session_factory):
    alice, _ = await make_user(session_factory, "alice-kit@example.com")
    bob, _ = await make_user(session_factory, "bob-kit@example.com")
    kit = toolkit(session_factory)
    info = await upload(kit, alice)
    stolen = await kit.execute("read", {"file_id": info.id, "user_id": str(alice.id)}, str(bob.id))
    assert stolen["ok"] is False and stolen["code"] == "not_found"
    assert (await kit.execute("forget", {"file_id": info.id}, str(bob.id)))["ok"] is False
    assert (await kit.execute("read", {"file_id": info.id}, str(alice.id)))["ok"] is True


# -- forget through the executor --------------------------------------------------


def executor(session_factory, kit) -> ConnectorToolExecutor:
    return ConnectorToolExecutor(session_factory=session_factory, files_toolkit=kit)


@pytest.mark.asyncio
async def test_forget_precheck_refuses_unknown_and_foreign_ids(session_factory):
    alice, _ = await make_user(session_factory, "alice-forget@example.com")
    bob, _ = await make_user(session_factory, "bob-forget@example.com")
    kit = toolkit(session_factory)
    info = await upload(kit, alice)
    ex = executor(session_factory, kit)
    for args, user in (({"file_id": info.id}, bob), ({"file_id": "nope"}, alice)):
        refusal = await ex.precheck_approval("files.forget", args, str(user.id))
        assert refusal is not None and refusal.policy == FILES_RULE_POLICY
        assert refusal.result["refused"] is True
    assert await ex.precheck_approval("files.forget", {"file_id": info.id}, str(alice.id)) is None


@pytest.mark.asyncio
async def test_forget_card_states_facts_and_runs_only_approved(session_factory):
    user, _ = await make_user(session_factory, "card@example.com")
    kit = toolkit(session_factory)
    info = await upload(kit, user, b.make_pdf(["a"] * 12), "syllabus.pdf")
    ex = executor(session_factory, kit)
    assert await ex.precheck_approval("files.forget", {"file_id": info.id}, str(user.id)) is None
    sentence = ex.describe_approval("files.forget", {"file_id": info.id}, str(user.id))
    assert sentence == (
        'Forget "syllabus.pdf" (12 pages): delete the text Crawler extracted from it. '
        "Your original file is not touched."
    )
    refused = await ex.execute("files.forget", {"file_id": info.id}, str(user.id))
    assert refused["ok"] is False and refused["requires_approval"] is True
    assert await kit.store.get_info(str(user.id), info.id) is not None
    done = await ex.execute("files.forget", {"file_id": info.id}, str(user.id), approved=True)
    assert done["ok"] is True and done["forgotten"] == info.id
    assert await kit.store.get_info(str(user.id), info.id) is None


@pytest.mark.asyncio
async def test_forget_card_without_facts_stays_generic(session_factory):
    kit = toolkit(session_factory)
    ex = executor(session_factory, kit)
    sentence = ex.describe_approval("files.forget", {"file_id": "00000000-0000-0000-0000-000000000001"}, "u")
    assert sentence is not None and sentence.startswith("Forget one of your uploaded files")


@pytest.mark.asyncio
async def test_read_runs_unattended_through_the_executor(session_factory):
    user, _ = await make_user(session_factory, "exec-read@example.com")
    kit = toolkit(session_factory)
    info = await upload(kit, user, b.make_pdf(["hello"]))
    result = await executor(session_factory, kit).execute("files.read", {"file_id": info.id}, str(user.id))
    assert result["ok"] is True and result["sections"][0]["text"] == "hello"


@pytest.mark.asyncio
async def test_a_pdf_past_the_page_cap_says_which_pages_were_read(session_factory):
    from services.files.documents import limit_notes, page_cap
    from services.files.limits import MAX_PDF_PAGES

    user, _ = await make_user(session_factory, "page-cap@example.com")
    pages = MAX_PDF_PAGES + 2
    registry = DocumentRegistry()
    opened = await read_document(
        b.make_pdf([f"Page {n} text." for n in range(1, pages + 1)]),
        name="manual.pdf",
        declared_mime=None,
        source="web",
        preset=CONNECTOR,
        user_id=str(user.id),
        registry=registry,
        sandbox=InProcessSandbox(),
    )
    assert opened["ok"] is True and opened["pages_total"] == pages and opened["truncated"] is True
    expected = f"Only pages 1-{MAX_PDF_PAGES} of {pages} were read (Crawler reads at most {MAX_PDF_PAGES} pages of a PDF)"
    assert expected in opened["hint"]
    assert "a size or time limit" not in opened["hint"]  # the page cap is the only limit here
    extraction = registry.get(str(user.id), opened["doc_id"]).extraction
    assert page_cap(extraction) == MAX_PDF_PAGES and f"page_cap:{MAX_PDF_PAGES}" in extraction.warnings

    kit = FilesToolkit(session_factory, registry=registry, sandbox=InProcessSandbox())
    last = await kit.execute("read", {"file_id": opened["doc_id"], "page": MAX_PDF_PAGES}, str(user.id))
    assert last["ok"] is True and expected in last["hint"]
    # A document cut by another limit too keeps the general sentence.
    from dataclasses import replace

    both = replace(extraction, warnings=(*extraction.warnings, "truncated_at_chars"))
    assert any("a size or time limit" in note for note in limit_notes(both))
