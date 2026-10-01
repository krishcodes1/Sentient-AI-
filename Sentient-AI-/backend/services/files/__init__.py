"""Reads documents (PDF, Word, PowerPoint, Excel, CSV, text, Markdown, HTML,
JSON) as labelled sections, for uploads, chat channels, connectors and the
web.

Why it exists: every source that hands Crawler a file goes through one
sandboxed reader, so the type check, the parser limits, the isolation of the
parser process and the shape the model reads (a list of sections it can page
through with files.read) are the same everywhere.

This package init stays import-free on purpose: the parser worker
(services/files/worker) runs in a separate, isolated process and must never
load the app (core, sqlalchemy, structlog, services.agent) by importing this
package.

Modules:
- limits: every cap, deadline and preset (UPLOAD, CONNECTOR, WEB_PAGE,
  WEB_RESEARCH).
- detect: the file type from its magic bytes, never its name.
- sections: the Section / Extraction types, normalisation and splitting.
- sandbox: runs the worker (services/workers.py) and collects its output.
- documents: extract() and read_document(), the one entry point for callers.
- registry: documents opened from the web or a connector, kept 30 minutes.
- store: uploaded files' extracted text, encrypted at rest (user_files).
- window: the part of a document one files.read call returns.
- intake: uploads from the web chat, Telegram and Slack.
- prompting, messages, facts, context: names, user texts, audit facts and
  the per-call document context the executor binds.
"""
