"""Every cap, deadline and preset the document reader works under.

Why it exists: an upload, a connector file, a web page and a research source
are read under different budgets (a research source gets 6 seconds and no
OCR; an upload gets two minutes). Keeping the numbers in one module means
the sandbox, the store, the routes and the channels can never disagree, and
a reviewer finds every limit in one place.

Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass

MB = 1024 * 1024


@dataclass(frozen=True)
class Preset:
    """How one kind of source is read.

    ``max_bytes``: the largest file accepted (refused as too_large above it).
    ``deadline_s``: the wall-clock budget of the parser process; sections
    already read when it runs out are kept and marked partial.
    ``ocr_pages``: how many scanned pages local OCR may read (phase 4; 0
    means scans are reported as unread).
    """

    name: str
    max_bytes: int
    deadline_s: float
    ocr_pages: int


UPLOAD = Preset("upload", 20 * MB, 120.0, 30)
CONNECTOR = Preset("connector", 20 * MB, 60.0, 10)
WEB_PAGE = Preset("web_page", 15 * MB, 30.0, 5)
WEB_RESEARCH = Preset("web_research", 8 * MB, 6.0, 0)

PRESETS: dict[str, Preset] = {p.name: p for p in (UPLOAD, CONNECTOR, WEB_PAGE, WEB_RESEARCH)}

# Per user, for uploaded files (user_files).
MAX_FILES_PER_USER = 100
MAX_STORED_BYTES_PER_USER = 200 * MB
MAX_UPLOADS_PER_HOUR = 30
# An upload's text is kept this long after it was last read.
RETENTION_DAYS = 30

# Parser output caps (the sandbox enforces them on what the worker sends).
MAX_LINE_BYTES = 1024 * 1024
MAX_DOCUMENT_CHARS = 1_000_000
MAX_PAGE_IMAGES = 20
MAX_IMAGE_BYTES_TOTAL = 8 * MB
# Everything the worker may write to stdout, escapes included.
MAX_WORKER_STDOUT_BYTES = 24 * MB

# The parser processes one server process runs at once, and how long a
# caller waits for one before the answer is "busy".
WORKER_SLOTS = 2
WORKER_QUEUE_WAIT_S = 30.0

# Parsers (enforced inside the worker).
MAX_PDF_PAGES = 300
MAX_ZIP_MEMBERS = 2000
MAX_ZIP_TOTAL_BYTES = 200 * MB
MAX_ZIP_MEMBER_BYTES = 50 * MB
MAX_ZIP_RATIO = 100
MAX_XLSX_SHEETS = 20
MAX_XLSX_ROWS = 5000
MAX_XLSX_COLUMNS = 60
MAX_CELL_CHARS = 1000
MAX_IMAGE_PIXELS = 40_000_000
WORKER_MEMORY_BYTES = 768 * MB

# Sections: a split aims for this many characters and never exceeds the
# maximum.
SECTION_TARGET_CHARS = 3000
SECTION_MAX_CHARS = 4000

# files.read windows, measured as the model sees them.
WINDOW_DEFAULT_CHARS = 12000
WINDOW_MIN_CHARS = 1000
WINDOW_MAX_CHARS = 12000

# The in-memory registry of documents opened from the web or a connector.
REGISTRY_MAX_PER_USER = 20
REGISTRY_MAX_CHARS = 64 * MB
REGISTRY_TTL_S = 30 * 60.0

# At most this many files ride along with one chat message.
MAX_FILES_PER_MESSAGE = 5
