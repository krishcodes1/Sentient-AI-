"""Shared Pydantic validators for user-supplied text.

Postgres ``text``/``varchar`` columns cannot store the U+0000 NUL byte, and
the asyncpg driver raises deep inside the request when one slips through —
surfacing as an opaque HTTP 500. Rejecting NUL bytes at the API boundary
turns that into a clean 422 with an actionable message.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator


def reject_null_bytes(value: str) -> str:
    if value is not None and "\x00" in value:
        raise ValueError("must not contain null bytes")
    return value


# A ``str`` that is guaranteed free of NUL bytes. Combine with
# ``Field(max_length=...)`` on the field as usual; the length constraint and
# this validator both apply.
SafeStr = Annotated[str, AfterValidator(reject_null_bytes)]
