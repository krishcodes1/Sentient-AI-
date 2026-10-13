"""The knowledge base: per-user collections of saved documents, searched with a
pure-Python BM25 index held in plain tables, with citations by page, slide or
section, and an optional meaning (vector) index behind its own switch.

Why it exists: a student asks "when is the CS101 midterm?" and the answer is
on page 3 of a syllabus they saved weeks ago. The index lives in ordinary
tables (kb_collections, kb_documents, kb_chunks, kb_postings, kb_embeddings),
so ranking is identical on SQLite and Postgres and needs no extension.

This package init stays import-free; the modules are:
- limits: the owner-editable settings and every fixed cap.
- text: the tokenizer (NFKC, casefold, course codes, CJK bigrams, stopwords,
  a light English stemmer).
- chunking: page-aware passages with 'p. 3' / 'slides 4–6' / '§ Grading'
  locators.
- ranking: BM25, Reciprocal Rank Fusion and the per-document cap.
- vectors: float32 packing, normalisation, scoring and the vector cache.
- screen: PromptGuard withholding and secret redaction of each passage.
- sources: what a saved document is made from (a URL, text, an extraction).
- store: KnowledgeService, every read and write, always scoped to one user.
- embeddings / embedder: the embedding backend rule and the sweeper that
  builds the meaning index while knowledge_semantic is on.
- facts, export, channels: audit summaries, the account export and the
  Telegram "/kb <collection>" caption.
"""
