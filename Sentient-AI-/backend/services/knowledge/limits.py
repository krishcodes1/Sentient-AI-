"""Every cap the knowledge base works under, and the owner-editable settings.

Why it exists: the toolkit, the store, the sweeper, the Telegram caption and
the capability declaration must agree on the same numbers; keeping them in
one module means a reviewer finds every limit in one place.

Stdlib only, so the capability module can import it without the app.
"""

from __future__ import annotations

# Owner-editable (PUT /api/capabilities/knowledge_base/settings): whole
# numbers from 1 to 10000, like every capability setting.
KNOWLEDGE_SETTINGS_DEFAULTS: dict[str, int] = {
    "documents_per_user": 400,
    "text_mb_per_user": 25,
    "file_mb": 25,
    "embed_ktokens_per_day": 1000,
}

MB = 1024 * 1024

# Collections.
MAX_COLLECTIONS_PER_USER = 50
COLLECTION_NAME_MAX = 80
COLLECTION_DESCRIPTION_MAX = 300

# Documents.
TITLE_MAX = 200
SOURCE_REF_MAX = 500
ORIGINAL_NAME_MAX = 255
MEDIA_TYPE_MAX = 100
# A document's text is cut here (and flagged truncated).
MAX_DOCUMENT_CHARS = 2_000_000

# Passages (chunking.py).
CHUNK_TARGET_CHARS = 1200
CHUNK_MAX_CHARS = 1600
CHUNK_OVERLAP_CHARS = 200
LOCATOR_MAX = 40
HEADING_MAX = 200

# The index (text.py, ranking.py).
TERM_MAX_CHARS = 40
BM25_K1 = 1.2
BM25_B = 0.75
RRF_K = 60
# A query term found in more than this share of the passages in scope is
# skipped (it cannot tell passages apart), when the scope has at least
# COMMON_TERM_MIN_PASSAGES passages and the query has another term.
COMMON_TERM_RATIO = 0.5
COMMON_TERM_MIN_PASSAGES = 10
PER_DOCUMENT_CAP = 3
# Candidates each ranking contributes before fusion and the cap.
CANDIDATES = 60
# Rows per bulk insert (5 columns x 1000 rows fits both dialects' limits).
INSERT_BATCH = 1000

# knowledge.add.
MAX_SOURCE_IDS = 10
MAX_TEXT_CHARS = 12_000
URL_MAX = 500
ADD_DEADLINE_S = 180.0
URL_DEADLINE_S = 30.0
URL_MAX_BYTES = 25 * MB
# Telegram "/kb <collection>": Telegram's own getFile limit.
TELEGRAM_MAX_BYTES = 20 * MB

# knowledge.search / read / list.
QUERY_MAX = 300
SEARCH_DEFAULT_LIMIT = 6
SEARCH_MAX_LIMIT = 12
PASSAGE_SHOWN_MAX = 1200
# The passages of one search share this many characters as shown, so a full
# result stays inside RESULT_CHAR_BUDGETS["knowledge.search"] (10000).
SEARCH_TEXT_BUDGET = 7200
READ_DEFAULT_COUNT = 3
READ_MAX_COUNT = 8
READ_TEXT_BUDGET = 10_000
LIST_DEFAULT_LIMIT = 20
LIST_MAX_LIMIT = 50
# knowledge.list keeps its rows within this many characters as shown
# (RESULT_CHAR_BUDGETS["knowledge.list"] is 8000; raise both together).
LIST_ROWS_CHARS = 7000

# Embeddings (embeddings.py, embedder.py).
EMBED_DIMS = 256
EMBED_INTERVAL_S = 30.0
EMBED_CLAIM_DOCUMENTS = 4
EMBED_LEASE_MINUTES = 5
EMBED_PASSAGES_PER_SWEEP = 256
EMBED_PASSAGES_PER_CALL = 64
EMBED_SWEEP_DEADLINE_S = 60.0
EMBED_MAX_ATTEMPTS = 5
EMBED_BACKOFF_MIN_MINUTES = 1
EMBED_BACKOFF_MAX_MINUTES = 60
EMBED_REQUEUE_PER_SWEEP = 20
QUERY_EMBED_TIMEOUT_S = 5.0
VECTOR_CACHE_BYTES = 64 * MB
