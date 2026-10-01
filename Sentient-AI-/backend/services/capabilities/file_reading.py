"""Declares the "file_reading" capability that gates files.list, files.read
and files.forget, and, at call time, every other way a document is read.

Why it exists: the registry lists it so the owner can switch document reading
off in one place. Besides the three files.* tools it claims, the switch is
read when a document turns up elsewhere: the document path of web.fetch_page
and web.research and of the connector file readers (through the executor's
DocumentContext), POST /api/files (403 with this when_denied), and Telegram
and Slack file intake (which reply with it). Parsing happens on this
computer, in a sandboxed worker process, so it is low risk and on by
default; a document's text reaches the model only as an untrusted tool
result.

Read files and documents: PDFs and Office files you send or your apps hold.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="file_reading",
    label="Read files and documents",
    description=(
        "Read PDFs and Word, PowerPoint, Excel, CSV, text and HTML files that you send "
        "or that your connected apps hold. Files are read on this computer."
    ),
    # Exact names, not the "files." family: a later files.view_page belongs
    # to its own switch.
    tools=("files.list", "files.read", "files.forget"),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Reading files is turned off. The owner can turn on 'Read files and documents' "
        "in Settings → Permissions."
    ),
)
