"""Tests for the mail connectors' get_attachment_hash bodies
(services/connectors/google_api/attachment_hash.py and microsoft_api/attachment_hash.py),
through the assembled GoogleWorkspaceConnector and MicrosoftConnector: they prove Gmail selects
the part by its part_id and downloads it by the fresh attachment id, Outlook reads the metadata
then the raw $value, both refuse what is over 25 MB without downloading it (and stop a download
that runs past the cap), Outlook refuses attached items, the byte sink receives the bytes only
when a caller bound it for that very fingerprint, and no byte of an attachment ever appears in
a result.

Why it exists: these READs hand the model and S2 a fingerprint for a malware lookup. Returning
content would put an attacker's file into the model's context; downloading past the cap would
let one email exhaust memory; and offering bytes to the wrong sink could upload a file nobody
approved (S10 4.3 C and G). All HTTP goes to ``httpx.MockTransport``; no real network.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import httpx
import pytest

from services.connectors.base import ConnectorError
from services.connectors.google_api import attachment_hash as gmail_hash
from services.connectors.microsoft_api import attachment_hash as outlook_hash
from services.file_reputation import byte_sink
from tests.connectors.test_google_workspace_support import (
    make,
    no_dns,  # noqa: F401 - fixture
)
from tests.connectors.test_microsoft import make_connector

pytestmark = pytest.mark.usefixtures("no_dns")

MARKER = b"SECRET-ATTACHMENT-CONTENT \x00 MZ"
EXE = b"MZ\x90\x00" + MARKER
FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _message(parts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": "m1",
        "threadId": "t1",
        "payload": {"mimeType": "multipart/mixed", "headers": [{"name": "Subject", "value": "Invoice"}], "parts": parts},
    }


def _gmail(parts: list[dict[str, Any]], attachment: bytes = EXE):
    def handler(request: httpx.Request) -> httpx.Response:
        if "/attachments/" in request.url.path:
            return httpx.Response(200, json={"data": _b64(attachment), "size": len(attachment)})
        return httpx.Response(200, json=_message(parts))

    return make(handler)


def _outlook(meta: dict[str, Any], raw: bytes = EXE):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=raw)
        return httpx.Response(200, json=meta)

    return make_connector(handler)


EXE_PART = {
    "partId": "2",
    "mimeType": "application/x-msdownload",
    "filename": "invoice.exe",
    "body": {"attachmentId": "fresh/id", "size": len(EXE)},
}


@pytest.mark.asyncio
async def test_gmail_attachment_hash_selects_by_part_id_and_returns_only_the_hash_and_size():
    parts = [
        {"partId": "0", "mimeType": "text/plain", "body": {"data": _b64(b"hello")}},
        {"partId": "1", "mimeType": "application/pdf", "filename": "a.pdf", "body": {"data": _b64(b"%PDF-1.7")}},
        EXE_PART,
    ]
    connector, seen = _gmail(parts)

    result = await connector.get_attachment_hash("m1", "2")

    assert result == {
        "message_id": "m1",
        "part_id": "2",
        "filename": "invoice.exe",
        "mime_type": "application/x-msdownload",
        "size": len(EXE),
        "sha256": _sha(EXE),
    }
    assert seen[0].url.params["format"] == "full"
    assert seen[1].url.raw_path == b"/gmail/v1/users/me/messages/m1/attachments/fresh%2Fid"
    # An inline part needs no second request.
    connector, seen = _gmail(parts)
    inline = await connector.get_attachment_hash("m1", "1")
    assert inline["sha256"] == _sha(b"%PDF-1.7") and len(seen) == 1
    with pytest.raises(ConnectorError, match="has no part '9'"):
        await connector.get_attachment_hash("m1", "9")


@pytest.mark.asyncio
async def test_gmail_attachment_hash_over_25_mb_says_too_large_without_downloading(monkeypatch):
    big = {**EXE_PART, "body": {"attachmentId": "big", "size": 26 * 1024 * 1024}}
    connector, seen = _gmail([big])

    result = await connector.get_attachment_hash("m1", "2")

    assert result == {
        "message_id": "m1",
        "part_id": "2",
        "filename": "invoice.exe",
        "mime_type": "application/x-msdownload",
        "size": 26 * 1024 * 1024,
        "sha256": None,
        "too_large": True,
    }
    assert len(seen) == 1  # the message only; the attachment was never fetched

    # A part that does not declare its size is stopped by the cap while downloading.
    monkeypatch.setattr(gmail_hash, "MAX_HASH_BYTES", 1024)
    undeclared = {**EXE_PART, "body": {"attachmentId": "undeclared"}}
    connector, seen = _gmail([undeclared], attachment=b"x" * 4096)
    stopped = await connector.get_attachment_hash("m1", "2")
    assert stopped["sha256"] is None and stopped["too_large"] is True and len(seen) == 2


@pytest.mark.asyncio
async def test_outlook_attachment_hash_downloads_value_and_returns_only_the_hash():
    meta = {"@odata.type": FILE_ATTACHMENT, "id": "a1", "name": "invoice.exe", "contentType": "application/octet-stream", "size": len(EXE)}
    connector, seen = _outlook(meta)

    result = await connector.get_attachment_hash("m1", "a1")

    assert result == {
        "message_id": "m1",
        "attachment_id": "a1",
        "filename": "invoice.exe",
        "mime_type": "application/octet-stream",
        "size": len(EXE),
        "sha256": _sha(EXE),
    }
    assert [r.url.path for r in seen] == [
        "/v1.0/me/messages/m1/attachments/a1",
        "/v1.0/me/messages/m1/attachments/a1/$value",
    ]
    assert "contentBytes" not in seen[0].url.params["$select"]


@pytest.mark.asyncio
async def test_outlook_item_attachments_are_refused(monkeypatch):
    item = {"@odata.type": "#microsoft.graph.itemAttachment", "id": "a1", "name": "Fwd: invoice"}
    connector, seen = _outlook(item)
    with pytest.raises(ConnectorError, match="attached item or link"):
        await connector.get_attachment_hash("m1", "a1")
    assert len(seen) == 1

    big = {"@odata.type": FILE_ATTACHMENT, "id": "a2", "name": "disk.iso", "contentType": "application/x-iso9660-image", "size": 30 * 1024 * 1024}
    connector, seen = _outlook(big)
    too_large = await connector.get_attachment_hash("m1", "a2")
    assert too_large["sha256"] is None and too_large["too_large"] is True and len(seen) == 1

    monkeypatch.setattr(outlook_hash, "MAX_HASH_BYTES", 1024)
    undeclared = {"@odata.type": FILE_ATTACHMENT, "id": "a3", "name": "x.bin"}
    connector, seen = _outlook(undeclared, raw=b"y" * 4096)
    stopped = await connector.get_attachment_hash("m1", "a3")
    assert stopped["sha256"] is None and stopped["too_large"] is True


@pytest.mark.asyncio
async def test_the_byte_sink_receives_the_bytes_only_when_bound_for_that_hash():
    connector, _ = _gmail([EXE_PART])
    meta = {"@odata.type": FILE_ATTACHMENT, "id": "a1", "name": "invoice.exe", "size": len(EXE)}
    outlook, _ = _outlook(meta)

    with byte_sink.expect(_sha(EXE)) as bound, byte_sink.expect(_sha(b"another file")) as other:
        await connector.get_attachment_hash("m1", "2")
    assert bound.data == EXE and other.data is None

    with byte_sink.expect(_sha(EXE)) as through_outlook:
        await outlook.get_attachment_hash("m1", "a1")
    assert through_outlook.data == EXE

    # Without a bound sink the bytes go nowhere (and nothing fails).
    unbound = await connector.get_attachment_hash("m1", "2")
    assert unbound["sha256"] == _sha(EXE)


@pytest.mark.asyncio
async def test_no_attachment_bytes_ever_appear_in_the_result():
    connector, _ = _gmail([EXE_PART])
    meta = {"@odata.type": FILE_ATTACHMENT, "id": "a1", "name": "invoice.exe", "size": len(EXE)}
    outlook, _ = _outlook(meta)

    answers: list[Any] = [
        await connector.get_attachment_hash("m1", "2"),
        (await connector.execute("get_attachment_hash", {"message_id": "m1", "part_id": "2"})).data,
        await outlook.get_attachment_hash("m1", "a1"),
        (await outlook.execute("get_attachment_hash", {"message_id": "m1", "attachment_id": "a1"})).data,
    ]

    for answer in answers:
        text = json.dumps(answer, default=str)
        assert "SECRET-ATTACHMENT-CONTENT" not in text
        assert _b64(EXE)[:16] not in text and base64.b64encode(EXE).decode()[:16] not in text
        assert answer["sha256"] == _sha(EXE)
