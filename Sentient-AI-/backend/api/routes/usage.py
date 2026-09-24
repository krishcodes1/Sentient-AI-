"""Token usage for the signed-in account.

Owner-scoped like every other resource: the user comes from the JWT, and
the aggregation joins through conversations.user_id, so there is no
parameter through which one account could read another's usage.
"""

from __future__ import annotations

from typing import Literal, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.user import User
from services.auth import get_current_user
from services.usage import usage_summary

router = APIRouter(prefix="/usage", tags=["usage"])


class UsageWindow(BaseModel):
    # The whole prompt, cached share included.
    input_tokens: int
    output_tokens: int
    # Parts of input_tokens read from / written to the prompt cache.
    cache_read_tokens: int
    cache_write_tokens: int
    total_tokens: int
    turns: int
    # None when every turn in the window is on a model with no known price.
    estimated_cost_usd: Optional[float]
    # Turns counted in the token totals but left out of the cost.
    unpriced_turns: int


class UsageWindows(BaseModel):
    today: UsageWindow
    last_7_days: UsageWindow
    last_30_days: UsageWindow
    all_time: UsageWindow


class ModelUsage(BaseModel):
    provider: Optional[str]
    model: Optional[str]
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    total_tokens: int
    turns: int
    estimated_cost_usd: Optional[float]


class UsageSummaryResponse(BaseModel):
    windows: UsageWindows
    by_model: list[ModelUsage]
    currency: Literal["USD"]
    pricing_note: str


def _parse_tz(tz: str) -> ZoneInfo:
    """Resolve an IANA zone name, or fail the request.

    An unknown name is refused rather than quietly replaced with UTC: the
    caller would then show a "today" that starts at the wrong hour with
    nothing to say so.
    """
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        # ValueError: a malformed key (an absolute or "../" path) or a
        # non-zone data file such as "zone.tab"; OSError: a directory name
        # such as "America".
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown timezone {tz!r}; expected an IANA name such as 'Europe/Paris'.",
        ) from None


@router.get("/summary", response_model=UsageSummaryResponse)
async def get_usage_summary(
    tz: str = Query(
        "UTC",
        min_length=1,
        max_length=64,
        description="IANA timezone whose midnight starts the 'today' window.",
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Tokens used today, over the last 7 and 30 days, and all time, with a
    per-model breakdown and an estimated cost at list prices."""
    return await usage_summary(db, current_user.id, tz=_parse_tz(tz))
