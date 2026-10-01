"""Tests for the document path of web.fetch_page and web.research: a PDF
response is read as sections with a doc_id, a generic binary is confirmed by
its magic bytes, a document over 15 MB is refused, the switch being off gives
its sentence, research reads at most two documents (text layer only, under
its own preset), and the egress guard still refuses a private host on a
redirect. All through httpx's MockTransport; no network.

Why it exists: web documents are the most hostile files Crawler reads (anyone
can host one), so they must take exactly the sandboxed, gated, capped path.
"""

from __future__ import annotations

import httpx
import pytest

from services.files.context import DocumentContext, bind
from services.files.registry import DocumentRegistry
from services.files.sandbox import InProcessSandbox
from services.tools.web import WebToolkit, _research_candidates
from tests.files import builders as b
from tests.test_web_research import FakeWeb, hosts_of
from tests.test_web_tools import PUBLIC_ADDRESS, resolver_for

URL = "https://papers.example.org/paper.pdf"


class Recorder(InProcessSandbox):
    def __init__(self) -> None:
        super().__init__()
        self.presets: list[str] = []

    async def run(self, data, *, kind, preset, delimiter=",", cancelled=None):
        self.presets.append(preset.name)
        return await super().run(data, kind=kind, preset=preset, delimiter=delimiter, cancelled=cancelled)


def context(refusal=None, sandbox=None, registry=None) -> DocumentContext:
    async def gate():
        return refusal

    return DocumentContext(
        user_id="user-1",
        registry=registry if registry is not None else DocumentRegistry(),
        sandbox=sandbox if sandbox is not None else InProcessSandbox(),
        gate=gate,
    )


def toolkit(handler, hosts=None) -> WebToolkit:
    return WebToolkit(transport=httpx.MockTransport(handler), resolver=resolver_for(hosts or {"papers.example.org": (PUBLIC_ADDRESS,)}))


def pdf_reply(data: bytes, content_type: str = "application/pdf"):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=data, headers={"content-type": content_type})

    return handler


@pytest.mark.asyncio
async def test_a_pdf_comes_back_as_sections_with_a_doc_id():
    registry = DocumentRegistry()
    pages = [f"Finding {n}: " + "evidence " * 300 for n in range(1, 6)]
    with bind(context(registry=registry)):
        result = await toolkit(pdf_reply(b.make_pdf(pages))).fetch_page(URL)
    assert result["ok"] is True and result["url"] == URL
    assert result["kind"] == "pdf" and result["pages_total"] == 5
    assert result["sections"][0]["label"] == "Page 1"
    assert result["doc_id"].startswith("tmp_") and result["next_start"] >= 2
    assert "files.read" in result["hint"]
    assert registry.get("user-1", result["doc_id"]) is not None
    assert result["title"] == "paper.pdf"


@pytest.mark.asyncio
async def test_octet_stream_is_read_when_the_magic_bytes_say_pdf():
    with bind(context()):
        result = await toolkit(pdf_reply(b.make_pdf(["binary served"]), "application/octet-stream")).fetch_page(URL)
    assert result["ok"] is True and result["sections"][0]["text"] == "binary served"


@pytest.mark.asyncio
async def test_octet_stream_that_is_not_a_document_is_still_refused():
    with bind(context()):
        result = await toolkit(pdf_reply(b"\x00\x01binary", "application/octet-stream")).fetch_page(URL)
    assert result["ok"] is False and "application/octet-stream" in result["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type",
    ["application/octet-stream", "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint"],
)
async def test_a_legacy_office_file_gets_the_save_as_sentence_and_no_worker(content_type):
    from services.files import messages

    sandbox = Recorder()
    with bind(context(sandbox=sandbox)):
        result = await toolkit(pdf_reply(b.OLE_HEADER + b"\0" * 4096, content_type)).fetch_page(URL)
    assert result["ok"] is False and result["code"] == "legacy_office"
    assert result["error"] == messages.LEGACY_OFFICE
    assert sandbox.calls == []


@pytest.mark.asyncio
async def test_a_password_protected_office_file_gets_the_never_send_the_password_sentence():
    from services.files import messages

    locked = b.OLE_HEADER + b"\0" * 2048 + "EncryptionInfo".encode("utf-16-le") + b"\0" * 512
    sandbox = Recorder()
    with bind(context(sandbox=sandbox)):
        result = await toolkit(pdf_reply(locked, "application/octet-stream")).fetch_page(URL)
    assert result["ok"] is False and result["code"] == "encrypted"
    assert result["error"] == messages.ENCRYPTED
    assert sandbox.calls == []


def test_the_too_large_sentence_never_rounds_a_file_down_to_the_limit():
    from services.files.limits import MB
    from services.files.messages import too_large

    cap = 15 * MB
    assert too_large(15_864_875, cap).startswith("That file is 15.1 MB; Crawler reads files up to 15 MB.")
    assert too_large(cap + 1, cap).startswith("That file is 15.1 MB;")  # rounded up, never "15.0"
    assert too_large(cap + MB // 10 * 2, cap).startswith("That file is 15.2 MB;")
    assert too_large(20 * MB, cap).startswith("That file is 20 MB;")
    assert too_large(int(5.3 * MB), 5 * MB).startswith("That file is 5.3 MB;")
    assert too_large(5 * MB + 1, 5 * MB).startswith("That file is 5.1 MB;")  # not "5 MB"
    assert too_large(None, cap).startswith("That file is too large; Crawler reads files up to 15 MB.")


@pytest.mark.asyncio
async def test_a_document_over_15_mb_is_refused():
    big = b"%PDF-1.4\n" + b"0" * (15 * 1024 * 1024 + 10)
    sandbox = Recorder()
    with bind(context(sandbox=sandbox)):
        result = await toolkit(pdf_reply(big)).fetch_page(URL)
    assert result["ok"] is False and result["code"] == "too_large"
    assert "15 MB" in result["error"]
    assert sandbox.calls == []


@pytest.mark.asyncio
async def test_file_reading_off_answers_with_its_sentence_and_downloads_nothing():
    served: list[str] = []

    def handler(request):
        served.append(str(request.url))
        return httpx.Response(200, content=b.make_pdf(["x"]), headers={"content-type": "application/pdf"})

    off = "Reading files is turned off. The owner can turn on 'Read files and documents' in Settings → Permissions."
    with bind(context(refusal=off)):
        result = await toolkit(handler).fetch_page(URL)
    assert result == {"ok": False, "error": off, "url": URL, "capability": "file_reading"}


@pytest.mark.asyncio
async def test_html_is_unchanged():
    def handler(request):
        return httpx.Response(200, html="<html><title>T</title><body><p>Plain page</p></body></html>")

    with bind(context()):
        result = await toolkit(handler).fetch_page("https://papers.example.org/page")
    assert result["ok"] is True and "Plain page" in result["text"] and "sections" not in result


@pytest.mark.asyncio
async def test_the_guard_refuses_a_private_host_on_redirect():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://127.0.0.1/secret.pdf"})

    with bind(context()):
        result = await toolkit(handler).execute("fetch_page", {"url": URL})
    assert result["ok"] is False and result.get("blocked") is True


def test_research_candidates_keep_at_most_two_document_links_when_allowed():
    rows = [
        {"url": "https://a.example.org/one.pdf"},
        {"url": "https://b.example.org/two.docx"},
        {"url": "https://c.example.org/three.pptx"},
        {"url": "https://d.example.org/old.doc"},
        {"url": "https://e.example.org/clip.mp4"},
        {"url": "https://f.example.org/page"},
    ]
    kept = [r["url"] for r in _research_candidates(rows, documents=True)]
    assert kept == ["https://a.example.org/one.pdf", "https://b.example.org/two.docx", "https://f.example.org/page"]
    assert [r["url"] for r in _research_candidates(rows)] == ["https://f.example.org/page"]


@pytest.mark.asyncio
async def test_research_reads_documents_text_only_under_its_preset():
    pdf_urls = [f"https://p{n}.example.org/doc" for n in range(3)]
    pages = {url: httpx.Response(200, content=b.make_pdf([f"doc {url}"]), headers={"content-type": "application/pdf"}) for url in pdf_urls}
    fake = FakeWeb([(url, f"Doc {n}") for n, url in enumerate(pdf_urls)], pages)
    sandbox = Recorder()
    web = WebToolkit(transport=httpx.MockTransport(fake), resolver=resolver_for(hosts_of(*pdf_urls)))
    with bind(context(sandbox=sandbox)):
        result = await web.research("papers", max_sources=3)
    read = [s for s in result["results"] if s["ok"]]
    refused = [s for s in result["results"] if not s["ok"]]
    assert len(read) == 2 and len(refused) == 1
    assert "at most 2 documents" in refused[0]["error"]
    assert all(s["doc_id"].startswith("tmp_") and s["excerpt"].startswith("[Page 1]") for s in read)
    assert sandbox.presets == ["web_research", "web_research"]


@pytest.mark.asyncio
async def test_research_without_a_document_context_skips_document_links():
    url = "https://docs.example.org/manual.pdf"
    fake = FakeWeb([(url, "Manual")], {})
    web = WebToolkit(transport=httpx.MockTransport(fake), resolver=resolver_for(hosts_of(url)))
    result = await web.research("manual")
    assert fake.page_requests == [] and result["results"] == []
