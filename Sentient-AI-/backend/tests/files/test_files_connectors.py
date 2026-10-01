"""Tests for the connector document path: Drive (alt=media, the byte cap),
Gmail (a PDF attachment, the size check before the fetch), OneDrive (the
/content redirect followed without Authorization), Outlook ($value), and the
Canvas course-file actions (list, the modules fallback, InstFS and S3 hops
without the bearer, an off-list redirect host refused, a download address on
another host refused before any request, a locked file refused).

Why it exists: a connector document is a file from someone else's service,
downloaded with the user's token; the token must never follow a redirect off
the provider, and every refusal must happen before bytes are fetched.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

import core.network_security as netsec
from services.connectors.base import ConnectorError
from services.connectors.canvas import CanvasConnector
from services.files.context import DocumentContext, bind
from services.files.registry import DocumentRegistry
from services.files.sandbox import InProcessSandbox
from tests.connectors.test_google_workspace_support import TOKEN as GOOGLE_TOKEN
from tests.connectors.test_google_workspace_support import make as make_google
from tests.connectors.test_microsoft import TOKEN as MS_TOKEN
from tests.connectors.test_microsoft import make_connector as make_microsoft
from tests.files import builders as b

PDF = b.make_pdf(["Week 5 readings: chapter 3"])


@pytest.fixture
def no_dns(monkeypatch):
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True, resolved_ips=("93.184.216.34",)))


@pytest.fixture
def documents():
    registry = DocumentRegistry()

    async def gate():
        return None

    with bind(DocumentContext(user_id="user-9", registry=registry, sandbox=InProcessSandbox(), gate=gate)):
        yield registry


# -- Google Drive ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drive_reads_a_pdf_with_alt_media(no_dns, documents):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("alt") == "media":
            return httpx.Response(200, content=PDF)
        return httpx.Response(200, json={"id": "f1", "name": "Week 5.pdf", "mimeType": "application/pdf", "size": str(len(PDF))})

    connector, seen = make_google(handler)
    result = await connector.get_file_text("f1")
    assert result["kind"] == "pdf" and result["sections"][0]["text"] == "Week 5 readings: chapter 3"
    assert documents.get("user-9", result["doc_id"]).source == "google_drive"
    assert seen[1].url.params["alt"] == "media"
    assert seen[1].headers["Authorization"] == f"Bearer {GOOGLE_TOKEN}"


@pytest.mark.asyncio
async def test_drive_refuses_a_document_over_the_cap_before_downloading(no_dns, documents):
    connector, seen = make_google(
        lambda r: httpx.Response(200, json={"id": "f1", "name": "huge.pdf", "mimeType": "application/pdf", "size": str(30 * 1024 * 1024)})
    )
    with pytest.raises(ConnectorError, match="20 MB"):
        await connector.get_file_text("f1")
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_drive_text_files_keep_offset_paging(no_dns, documents):
    def handler(request):
        if request.url.params.get("alt") == "media":
            return httpx.Response(200, content=b"plain notes")
        return httpx.Response(200, json={"id": "f1", "name": "n.txt", "mimeType": "text/plain", "size": "11"})

    connector, _ = make_google(handler)
    result = await connector.get_file_text("f1")
    assert result["text"] == "plain notes" and "doc_id" not in result


# -- Gmail --------------------------------------------------------------------------


def _gmail_message(part):
    return {"id": "m1", "threadId": "t1", "payload": {"mimeType": "multipart/mixed", "parts": [part]}}


@pytest.mark.asyncio
async def test_gmail_reads_a_pdf_attachment(no_dns, documents):
    part = {"partId": "2", "mimeType": "application/pdf", "filename": "reading.pdf", "body": {"attachmentId": "att", "size": len(PDF)}}

    def handler(request):
        if request.url.path.endswith("/attachments/att"):
            return httpx.Response(200, json={"data": base64.urlsafe_b64encode(PDF).decode().rstrip("=")})
        return httpx.Response(200, json=_gmail_message(part))

    connector, seen = make_google(handler)
    result = await connector.get_attachment_text("m1", "2")
    assert result["filename"] == "reading.pdf" and result["kind"] == "pdf"
    assert result["sections"][0]["text"].startswith("Week 5")


@pytest.mark.asyncio
async def test_gmail_checks_the_size_before_fetching(no_dns, documents):
    part = {"partId": "2", "mimeType": "application/pdf", "filename": "big.pdf", "body": {"attachmentId": "att", "size": 25 * 1024 * 1024}}
    connector, seen = make_google(lambda r: httpx.Response(200, json=_gmail_message(part)))
    with pytest.raises(ConnectorError, match="20 MB"):
        await connector.get_attachment_text("m1", "2")
    assert len(seen) == 1


# -- OneDrive and Outlook ---------------------------------------------------------------


_DOCX = b.make_docx()
_ONEDRIVE_META = {
    "id": "f1",
    "name": "Week 5 Notes.docx",
    "size": len(_DOCX),
    "file": {"mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "webUrl": "https://onedrive.live.com/x",
}


@pytest.mark.asyncio
async def test_onedrive_follows_content_to_sharepoint_without_the_token(no_dns, documents):
    def handler(request):
        if request.url.host == "graph.microsoft.com" and request.url.path.endswith("/content"):
            return httpx.Response(302, headers={"Location": "https://contoso-my.sharepoint.com/personal/ann/download.aspx?tempauth=x"})
        if request.url.host == "graph.microsoft.com":
            return httpx.Response(200, json=_ONEDRIVE_META)
        return httpx.Response(200, content=_DOCX)

    connector, seen = make_microsoft(handler, hooked=True)
    result = await connector.get_file_text("f1")
    assert result["kind"] == "docx" and "Midterm" in result["sections"][0]["text"]
    assert seen[1].headers["Authorization"] == f"Bearer {MS_TOKEN}"
    assert seen[2].url.host == "contoso-my.sharepoint.com"
    assert "authorization" not in seen[2].headers
    await connector.close()


@pytest.mark.asyncio
async def test_outlook_reads_an_attachment_through_value(no_dns, documents):
    meta = {"@odata.type": "#microsoft.graph.fileAttachment", "id": "a1", "name": "slides.pdf", "contentType": "application/pdf", "size": len(PDF)}

    def handler(request):
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=PDF)
        return httpx.Response(200, json=meta)

    connector, seen = make_microsoft(handler, hooked=True)
    result = await connector.get_attachment_text("m1", "a1")
    assert result["kind"] == "pdf" and seen[1].url.path.endswith("/attachments/a1/$value")
    await connector.close()


@pytest.mark.asyncio
async def test_connector_documents_need_file_reading(no_dns):
    async def off():
        return "Reading files is turned off."

    connector, seen = make_microsoft(lambda r: httpx.Response(200, json=_ONEDRIVE_META))
    with bind(DocumentContext(user_id="u", registry=DocumentRegistry(), sandbox=InProcessSandbox(), gate=off)):
        with pytest.raises(ConnectorError, match="turned off"):
            await connector.get_file_text("f1")
    assert len(seen) == 1  # metadata only; nothing downloaded


# -- Canvas -------------------------------------------------------------------------------

BASE = "https://school.instructure.com"


class FakeCanvas:
    def __init__(self, *, files_status=200, meta=None, storage_host="school.inscloudgate.net", content=PDF):
        self.files_status = files_status
        self.meta = meta or {}
        self.storage_host = storage_host
        self.content = content
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/v1/courses/11/files":
            if self.files_status != 200:
                return httpx.Response(self.files_status, json={"errors": "unauthorized"})
            return httpx.Response(200, json=[
                {"id": 5, "display_name": "Lecture 7.pdf", "content-type": "application/pdf", "size": 900, "updated_at": "2026-09-20", "folder_id": 2},
                {"id": 6, "display_name": "Locked.pdf", "content-type": "application/pdf", "size": 1, "locked_for_user": True},
            ])
        if path == "/api/v1/courses/11/modules":
            return httpx.Response(200, json=[
                {"name": "Week 7", "items": [
                    {"type": "File", "content_id": 5, "title": "Lecture 7.pdf"},
                    {"type": "Page", "title": "Read me"},
                ]},
            ])
        if path == "/api/v1/files/5":
            return httpx.Response(200, json={
                "id": 5, "display_name": "Lecture 7.pdf", "content-type": "application/pdf", "size": len(self.content),
                "url": f"{BASE}/files/5/download?download_frd=1&verifier=v", **self.meta,
            })
        if path == "/files/5/download":
            return httpx.Response(302, headers={"Location": f"https://{self.storage_host}/files/abc?sig=x"})
        if request.url.host == self.storage_host:
            return httpx.Response(200, content=self.content)
        return httpx.Response(404, json={"errors": "not found"})


def canvas(fake: FakeCanvas) -> CanvasConnector:
    from core.network_security import normalize_policy_host

    connector = CanvasConnector(base_url=BASE, client_id="cid", client_secret="cs")
    connector._access_token = "canvas-token"
    connector._authenticated = True
    connector.set_network_policy("canvas", extra_hosts=(normalize_policy_host(BASE),))
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(fake),
        event_hooks={"request": [connector._enforce_network_policy]},
        max_redirects=connector.MAX_REDIRECTS,
    )
    return connector


@pytest.mark.asyncio
async def test_canvas_list_files(no_dns):
    fake = FakeCanvas()
    result = await canvas(fake).list_files("11", search="lecture", limit=5)
    assert result["source"] == "files"
    assert result["files"][0] == {
        "id": 5, "name": "Lecture 7.pdf", "content_type": "application/pdf", "size": 900,
        "updated_at": "2026-09-20", "folder_id": 2,
    }
    assert result["files"][1]["locked"] is True
    params = fake.requests[0].url.params
    assert params["search_term"] == "lecture" and params["sort"] == "updated_at" and params["order"] == "desc"


@pytest.mark.asyncio
async def test_canvas_list_files_falls_back_to_modules(no_dns):
    fake = FakeCanvas(files_status=403)
    result = await canvas(fake).list_files("11")
    assert result["source"] == "modules"
    assert result["files"] == [{"id": 5, "name": "Lecture 7.pdf", "module": "Week 7"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("storage", ["school.inscloudgate.net", "instructure-uploads-2.s3.amazonaws.com"])
async def test_canvas_get_file_text_hops_to_storage_without_the_bearer(no_dns, documents, storage):
    fake = FakeCanvas(storage_host=storage)
    result = await canvas(fake).get_file_text("5")
    assert result["kind"] == "pdf" and result["doc_id"].startswith("tmp_")
    download, stored = fake.requests[1], fake.requests[2]
    assert download.url.path == "/files/5/download"
    assert download.headers["Authorization"] == "Bearer canvas-token"
    assert stored.url.host == storage and "authorization" not in stored.headers


@pytest.mark.asyncio
async def test_canvas_refuses_an_off_list_redirect_host(no_dns, documents):
    fake = FakeCanvas(storage_host="attacker.example.com")
    with pytest.raises(ConnectorError, match="network policy"):
        await canvas(fake).get_file_text("5")
    assert all(r.url.host != "attacker.example.com" for r in fake.requests)


@pytest.mark.asyncio
async def test_canvas_refuses_a_download_address_on_another_host_before_any_request(no_dns, documents):
    fake = FakeCanvas(meta={"url": "https://evil.example.com/files/5/download"})
    with pytest.raises(ConnectorError, match="download address"):
        await canvas(fake).get_file_text("5")
    assert [r.url.path for r in fake.requests] == ["/api/v1/files/5"]


@pytest.mark.asyncio
async def test_canvas_refuses_a_locked_or_huge_file(no_dns, documents):
    with pytest.raises(ConnectorError, match="locked"):
        await canvas(FakeCanvas(meta={"locked_for_user": True})).get_file_text("5")
    with pytest.raises(ConnectorError, match="20 MB"):
        await canvas(FakeCanvas(meta={"size": 30 * 1024 * 1024})).get_file_text("5")


@pytest.mark.asyncio
async def test_canvas_ids_must_be_numeric(no_dns):
    with pytest.raises(ConnectorError, match="numeric"):
        await canvas(FakeCanvas()).get_file_text("../users/self")


def test_canvas_file_actions_are_reads_on_courses_read():
    from services.connectors.canvas import ACTIONS

    specs = {s.action: s for s in ACTIONS}
    for action in ("list_files", "get_file_text"):
        assert specs[action].category.value == "read"
        assert specs[action].required_scope == "courses.read"
    assert json.dumps(specs["get_file_text"].parameters)
