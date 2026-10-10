"""The study store's operations, shared by the study.* tools and the model-free
Telegram and Slack reviews: decks and items, the due queue, grading, quizzes,
progress and the user's review settings.

Why it exists: a card graded in chat, on Telegram or in Slack must be
scheduled the same way and guarded the same way, so the rules live here once:
- every query is scoped to the caller's user id (the executor's, or the linked
  chat's owner); another user's deck, item or attempt reads as not found;
- grading is a conditional UPDATE: it matches only while the card is still due
  and still in the state it was read in, so a second press, a replay or a
  race changes nothing ("already answered");
- a quiz keeps its answer key server-side and grades choice items in code; a
  wrong answer makes the item due now, a right one leaves its schedule alone;
- day boundaries (the new-card cap, "due today", streaks) are the user's local
  days: users.timezone, then CRAWLER_TIMEZONE, then UTC.
Nothing here calls a model or a network, and nothing is logged but ids and
counts.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Sequence
from zoneinfo import ZoneInfo

from sqlalchemy import and_, case, delete, func, or_, select, update

from models.study import (
    DEFAULT_NEW_PER_DAY,
    DEFAULT_SESSION_SIZE,
    StudyDeck,
    StudyItem,
    StudyQuizAttempt,
    StudyReview,
    StudySettings,
)
from services.study import srs
from services.study.items import ItemDraft

QUIZ_MAX_ITEMS = 30
SKIP_MINUTES = 60
ABANDON_AFTER = timedelta(hours=24)
ACCURACY_DAYS = 30
FORECAST_DAYS = 7
# A rating of good or easy (3-4) is a correct answer.
CORRECT_RATING = 3
# How a quiz answer is recorded among the reviews (for accuracy only).
QUIZ_RIGHT_RATING = 3
QUIZ_WRONG_RATING = 1

NOT_FOUND = "not_found"

# An item's scheduling as a new card (reset_progress). Its review history is
# kept for the statistics.
_NEW_STATE: dict[str, Any] = {
    "ease": srs.START_EASE,
    "interval_days": 0.0,
    "repetitions": 0,
    "lapses": 0,
    "due_at": None,
    "last_reviewed_at": None,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    # SQLite hands back naive datetimes; every value written here is UTC.
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def default_timezone() -> Optional[str]:
    """The install's zone (CRAWLER_TIMEZONE), or None."""
    from core.config import settings

    return getattr(settings, "DEFAULT_TIMEZONE", None)


def as_uuid(value: Any) -> Optional[uuid.UUID]:
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str):
        return None
    try:
        return uuid.UUID(value.strip())
    except ValueError:
        return None


def zone_for(user_tz: Optional[str], default: Optional[str]) -> ZoneInfo:
    """The user's zone for day boundaries: theirs, the install's, or UTC."""
    from services.scheduler.timezones import resolve_zone

    return resolve_zone(None, user_tz, default) or ZoneInfo("UTC")


def day_start(now: datetime, tz: ZoneInfo) -> datetime:
    """The start of *now*'s local day, in UTC."""
    local = now.astimezone(tz)
    return datetime(local.year, local.month, local.day, tzinfo=tz).astimezone(timezone.utc)


def day_end(now: datetime, tz: ZoneInfo) -> datetime:
    local = now.astimezone(tz)
    nxt = datetime(local.year, local.month, local.day, tzinfo=tz) + timedelta(days=1)
    return datetime(nxt.year, nxt.month, nxt.day, tzinfo=tz).astimezone(timezone.utc)


def card_state(item: StudyItem) -> srs.CardState:
    return srs.CardState(
        ease=float(item.ease or srs.START_EASE),
        interval_days=float(item.interval_days or 0.0),
        repetitions=int(item.repetitions or 0),
        lapses=int(item.lapses or 0),
    )


def shuffled_order(attempt_id: Any, item_id: Any, count: int) -> list[int]:
    """The order a quiz shows an item's choices in: ``order[shown] =
    stored index``, seeded by attempt and item so every look is the same."""
    order = list(range(count))
    random.Random(f"{attempt_id}:{item_id}").shuffle(order)
    return order


def quiz_summary(attempt: Any, items: Sequence[Any], deck_title: str) -> dict[str, Any]:
    """A quiz's score, its weakest tags (from the missed items) and how many
    missed items are now due. Titles, tags and counts only."""
    wrong = [str(a.get("item_id")) for a in attempt.answers or [] if not a.get("correct")]
    by_id = {str(i.id): i for i in items}
    tag_misses: dict[str, int] = {}
    for item_id in wrong:
        for tag in (by_id[item_id].tags or []) if item_id in by_id else []:
            tag_misses[tag] = tag_misses.get(tag, 0) + 1
    weakest = sorted(tag_misses.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    total = int(attempt.total or 0)
    correct = int(attempt.correct or 0)
    return {
        "attempt_id": str(attempt.id),
        "deck": deck_title,
        "status": attempt.status,
        "score": f"{correct}/{total}",
        "percent": round(100 * correct / total) if total else 0,
        "answered": int(attempt.answered or 0),
        "weakest_tags": [t for t, _n in weakest],
        "now_due_for_review": len(wrong),
    }


@dataclass
class ReviewSettings:
    new_per_day: int = DEFAULT_NEW_PER_DAY
    session_size: int = DEFAULT_SESSION_SIZE
    nudge_task_id: Optional[uuid.UUID] = None


@dataclass
class GradeResult:
    ok: bool
    item: Optional[StudyItem] = None
    rating: str = ""
    interval: timedelta = timedelta(0)
    due_at: Optional[datetime] = None
    reason: str = ""  # not_found | not_due


# -- queries that take the caller's session (the nudge renderer's) ---------------


async def load_settings(session: Any, owner: uuid.UUID) -> ReviewSettings:
    row = await session.get(StudySettings, owner)
    if row is None:
        return ReviewSettings()
    return ReviewSettings(int(row.new_per_day), int(row.session_size), row.nudge_task_id)


async def user_zone(session: Any, owner: uuid.UUID, default: Optional[str]) -> ZoneInfo:
    from models.user import User

    tz = (await session.execute(select(User.timezone).where(User.id == owner))).scalar_one_or_none()
    return zone_for(tz, default)


async def new_introduced_since(session: Any, owner: uuid.UUID, since: datetime) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(StudyReview)
                .where(
                    StudyReview.user_id == owner,
                    StudyReview.was_new.is_(True),
                    StudyReview.reviewed_at >= since,
                )
            )
        ).scalar_one()
    )


async def new_left_today(
    session: Any, owner: uuid.UUID, now: datetime, tz: ZoneInfo, per_day: int
) -> int:
    return max(0, per_day - await new_introduced_since(session, owner, day_start(now, tz)))


def _reviewable(owner: uuid.UUID, deck_id: Optional[uuid.UUID]) -> list[Any]:
    """Unsuspended items of the user's decks that are in reviews, or of one
    deck they named (a deck taken out of reviews can still be studied on
    purpose)."""
    conditions: list[Any] = [StudyItem.user_id == owner, StudyItem.suspended.is_(False)]
    if deck_id is not None:
        conditions.append(StudyItem.deck_id == deck_id)
    else:
        conditions.append(StudyDeck.in_reviews.is_(True))
    return conditions


async def due_counts_by_deck(
    session: Any, owner: uuid.UUID, *, until: datetime, new_left: int
) -> list[tuple[uuid.UUID, str, int]]:
    """``(deck id, title, count)`` of what is due by *until* in the decks in
    reviews, new cards counted up to *new_left* in all (oldest decks'
    first), busiest deck first. Ids, titles and numbers only."""
    base = (
        select(StudyItem.deck_id, StudyDeck.title, StudyDeck.created_at, func.count())
        .join(StudyDeck, StudyDeck.id == StudyItem.deck_id)
        .group_by(StudyItem.deck_id, StudyDeck.title, StudyDeck.created_at)
    )
    due_rows = (
        await session.execute(
            base.where(
                *_reviewable(owner, None), StudyItem.due_at.is_not(None), StudyItem.due_at <= until
            )
        )
    ).all()
    counts: dict[uuid.UUID, list[Any]] = {r[0]: [r[1], r[2], int(r[3])] for r in due_rows}
    if new_left > 0:
        new_rows = (
            await session.execute(
                base.where(*_reviewable(owner, None), StudyItem.due_at.is_(None)).order_by(
                    StudyDeck.created_at, StudyItem.deck_id
                )
            )
        ).all()
        left = new_left
        for deck_id, title, created, count in new_rows:
            if left <= 0:
                break
            take = min(left, int(count))
            left -= take
            entry = counts.setdefault(deck_id, [title, created, 0])
            entry[2] += take
    oldest = datetime.min.replace(tzinfo=timezone.utc)
    ordered = sorted(
        counts.items(),
        key=lambda kv: (-kv[1][2], _utc(kv[1][1]) or oldest, str(kv[1][0]), str(kv[0])),
    )
    return [(deck_id, str(v[0]), int(v[2])) for deck_id, v in ordered if v[2] > 0]


class StudyEngine:
    """The study store for one process. ``clock`` and ``default_timezone``
    are test seams; without a session factory every call refuses."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]],
        *,
        clock: Callable[[], datetime] = _utcnow,
        default_timezone: Callable[[], Optional[str]] = default_timezone,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._default_timezone = default_timezone

    @property
    def configured(self) -> bool:
        return self._session_factory is not None

    def now(self) -> datetime:
        return self._clock()

    def session(self) -> Any:
        if self._session_factory is None:
            raise RuntimeError("study store is not configured")
        return self._session_factory()

    async def zone(self, session: Any, owner: uuid.UUID) -> ZoneInfo:
        return await user_zone(session, owner, self._default_timezone())

    # -- decks -----------------------------------------------------------------

    async def deck(self, session: Any, owner: uuid.UUID, deck_id: Any) -> Optional[StudyDeck]:
        key = as_uuid(deck_id)
        if key is None:
            return None
        return (
            await session.execute(select(StudyDeck).where(StudyDeck.id == key, StudyDeck.user_id == owner))
        ).scalar_one_or_none()

    async def item(self, session: Any, owner: uuid.UUID, item_id: Any) -> Optional[StudyItem]:
        key = as_uuid(item_id)
        if key is None:
            return None
        return (
            await session.execute(select(StudyItem).where(StudyItem.id == key, StudyItem.user_id == owner))
        ).scalar_one_or_none()

    async def numbered_decks(self, owner: uuid.UUID) -> list[StudyDeck]:
        """The user's decks as /decks numbers them: oldest first."""
        async with self.session() as session:
            return list(
                (
                    await session.execute(
                        select(StudyDeck)
                        .where(StudyDeck.user_id == owner)
                        .order_by(StudyDeck.created_at, StudyDeck.id)
                    )
                )
                .scalars()
                .all()
            )

    async def deck_count(self, session: Any, owner: uuid.UUID) -> int:
        return int(
            (
                await session.execute(
                    select(func.count()).select_from(StudyDeck).where(StudyDeck.user_id == owner)
                )
            ).scalar_one()
        )

    async def item_count(self, session: Any, owner: uuid.UUID, deck_id: Optional[uuid.UUID] = None) -> int:
        query = select(func.count()).select_from(StudyItem).where(StudyItem.user_id == owner)
        if deck_id is not None:
            query = query.where(StudyItem.deck_id == deck_id)
        return int((await session.execute(query)).scalar_one())

    async def deck_stats(self, session: Any, owner: uuid.UUID, now: datetime) -> dict[uuid.UUID, dict[str, Any]]:
        """Per deck: items, due now, new, and 30-day review accuracy."""
        stats: dict[uuid.UUID, dict[str, Any]] = {}

        def entry(deck_id: uuid.UUID) -> dict[str, Any]:
            return stats.setdefault(
                deck_id, {"items": 0, "due_now": 0, "new": 0, "reviews_30d": 0, "correct_30d": 0}
            )

        rows = (
            await session.execute(
                select(
                    StudyItem.deck_id,
                    func.count(),
                    func.sum(
                        case(
                            (
                                and_(
                                    StudyItem.suspended.is_(False),
                                    StudyItem.due_at.is_not(None),
                                    StudyItem.due_at <= now,
                                ),
                                1,
                            ),
                            else_=0,
                        )
                    ),
                    func.sum(
                        case((and_(StudyItem.suspended.is_(False), StudyItem.due_at.is_(None)), 1), else_=0)
                    ),
                )
                .where(StudyItem.user_id == owner)
                .group_by(StudyItem.deck_id)
            )
        ).all()
        for deck_id, total, due, new in rows:
            e = entry(deck_id)
            e["items"], e["due_now"], e["new"] = int(total), int(due or 0), int(new or 0)
        since = now - timedelta(days=ACCURACY_DAYS)
        reviews = (
            await session.execute(
                select(
                    StudyReview.deck_id,
                    func.count(),
                    func.sum(case((StudyReview.rating >= CORRECT_RATING, 1), else_=0)),
                )
                .where(StudyReview.user_id == owner, StudyReview.reviewed_at >= since)
                .group_by(StudyReview.deck_id)
            )
        ).all()
        for deck_id, total, correct in reviews:
            e = entry(deck_id)
            e["reviews_30d"], e["correct_30d"] = int(total), int(correct or 0)
        return stats

    async def list_decks(self, owner: uuid.UUID) -> tuple[list[StudyDeck], dict[uuid.UUID, dict[str, Any]]]:
        now = self._clock()
        async with self.session() as session:
            decks = list(
                (
                    await session.execute(
                        select(StudyDeck)
                        .where(StudyDeck.user_id == owner)
                        .order_by(StudyDeck.created_at, StudyDeck.id)
                    )
                )
                .scalars()
                .all()
            )
            stats = await self.deck_stats(session, owner, now) if decks else {}
        return decks, stats

    async def deck_items(
        self, owner: uuid.UUID, deck_id: Any, *, tag: Optional[str] = None
    ) -> Optional[tuple[StudyDeck, list[StudyItem]]]:
        async with self.session() as session:
            deck = await self.deck(session, owner, deck_id)
            if deck is None:
                return None
            items = list(
                (
                    await session.execute(
                        select(StudyItem)
                        .where(StudyItem.deck_id == deck.id, StudyItem.user_id == owner)
                        .order_by(StudyItem.position, StudyItem.id)
                    )
                )
                .scalars()
                .all()
            )
        if tag:
            items = [i for i in items if tag in (i.tags or [])]
        return deck, items

    async def save_items(
        self,
        owner: uuid.UUID,
        *,
        deck_id: Optional[uuid.UUID],
        new_deck: Optional[dict[str, Any]],
        drafts: Sequence[tuple[int, ItemDraft]],
        max_decks: int,
        max_items_per_user: int,
        max_items_per_deck: int,
    ) -> dict[str, Any]:
        """Add *drafts* (``(index, draft)``) to the user's deck *deck_id*, or
        to a new deck made from *new_deck*. Items whose fingerprint the deck
        already has are skipped. Refuses past the per-user and per-deck
        limits before writing anything."""
        now = self._clock()
        async with self.session() as session:
            if deck_id is not None:
                deck = await self.deck(session, owner, deck_id)
                if deck is None:
                    return {"ok": False, "reason": NOT_FOUND}
                created = False
            else:
                if await self.deck_count(session, owner) >= max_decks:
                    return {"ok": False, "reason": "deck_limit"}
                deck = StudyDeck(
                    id=uuid.uuid4(),
                    user_id=owner,
                    created_at=now,
                    updated_at=now,
                    in_reviews=True,
                    **(new_deck or {}),
                )
                created = True
            existing_hashes: set[str] = set()
            in_deck = 0
            next_position = 0
            if not created:
                rows = (
                    await session.execute(
                        select(StudyItem.content_hash, StudyItem.position).where(StudyItem.deck_id == deck.id)
                    )
                ).all()
                existing_hashes = {r[0] for r in rows}
                in_deck = len(rows)
                next_position = max((int(r[1]) for r in rows), default=-1) + 1
            fresh: list[tuple[int, ItemDraft]] = []
            skipped = 0
            seen = set(existing_hashes)
            for index, draft in drafts:
                digest = draft.content_hash
                if digest in seen:
                    skipped += 1
                    continue
                seen.add(digest)
                fresh.append((index, draft))
            if in_deck + len(fresh) > max_items_per_deck:
                return {"ok": False, "reason": "deck_item_limit", "in_deck": in_deck}
            if fresh and await self.item_count(session, owner) + len(fresh) > max_items_per_user:
                return {"ok": False, "reason": "user_item_limit"}
            if created and not fresh:
                return {"ok": False, "reason": "nothing_to_add", "skipped": skipped}
            if created:
                session.add(deck)
                await session.flush()
            added_ids: list[str] = []
            for offset, (_index, draft) in enumerate(fresh):
                item = StudyItem(
                    id=uuid.uuid4(),
                    deck_id=deck.id,
                    user_id=owner,
                    kind=draft.kind,
                    front=draft.front,
                    back=draft.back,
                    choices=list(draft.choices) if draft.choices is not None else None,
                    answer_index=draft.answer_index,
                    explanation=draft.explanation,
                    choice_notes=list(draft.choice_notes) if draft.choice_notes is not None else None,
                    tags=list(draft.tags),
                    difficulty=draft.difficulty,
                    source_note=draft.source_note,
                    content_hash=draft.content_hash,
                    position=next_position + offset,
                    suspended=False,
                    ease=srs.START_EASE,
                    interval_days=0.0,
                    repetitions=0,
                    lapses=0,
                    due_at=None,
                    created_at=now,
                    updated_at=now,
                )
                session.add(item)
                added_ids.append(str(item.id))
            deck.updated_at = now
            await session.commit()
            return {
                "ok": True,
                "deck_id": str(deck.id),
                "title": deck.title,
                "created": created,
                "added": len(fresh),
                "added_ids": added_ids,
                "skipped_duplicates": skipped,
                "deck_items": in_deck + len(fresh),
            }

    async def edit_deck(
        self, owner: uuid.UUID, deck_id: Any, values: dict[str, Any], *, reset_progress: bool
    ) -> dict[str, Any]:
        """Change the user's deck (title, course, in_reviews) and, with
        *reset_progress*, make every item in it new again."""
        now = self._clock()
        async with self.session() as session:
            deck = await self.deck(session, owner, deck_id)
            if deck is None:
                return {"ok": False, "reason": NOT_FOUND}
            for name, value in values.items():
                setattr(deck, name, value)
            deck.updated_at = now
            reset = 0
            if reset_progress:
                changed = await session.execute(
                    update(StudyItem)
                    .where(StudyItem.deck_id == deck.id, StudyItem.user_id == owner)
                    .values(**_NEW_STATE, updated_at=now)
                    .execution_options(synchronize_session=False)
                )
                reset = int(changed.rowcount or 0)
            await session.commit()
            return {"ok": True, "deck_id": str(deck.id), "title": deck.title, "reset_items": reset}

    async def edit_item(
        self,
        owner: uuid.UUID,
        item_id: Any,
        draft: Optional[ItemDraft],
        values: dict[str, Any],
        *,
        reset_progress: bool,
    ) -> dict[str, Any]:
        """Replace the user's item's content with *draft* (already
        validated), set *values* (suspended), and with *reset_progress* make
        it new again. A front another item of the deck already has is
        refused."""
        now = self._clock()
        async with self.session() as session:
            item = await self.item(session, owner, item_id)
            if item is None:
                return {"ok": False, "reason": NOT_FOUND}
            if draft is not None:
                digest = draft.content_hash
                clash = (
                    await session.execute(
                        select(StudyItem.id).where(
                            StudyItem.deck_id == item.deck_id,
                            StudyItem.content_hash == digest,
                            StudyItem.id != item.id,
                        )
                    )
                ).first()
                if clash is not None:
                    return {"ok": False, "reason": "duplicate"}
                item.front, item.back = draft.front, draft.back
                item.choices = list(draft.choices) if draft.choices is not None else None
                item.answer_index = draft.answer_index
                item.explanation = draft.explanation
                item.choice_notes = list(draft.choice_notes) if draft.choice_notes is not None else None
                item.tags = list(draft.tags)
                item.difficulty = draft.difficulty
                item.source_note = draft.source_note
                item.content_hash = digest
            for name, value in values.items():
                setattr(item, name, value)
            if reset_progress:
                for name, value in _NEW_STATE.items():
                    setattr(item, name, value)
            item.updated_at = now
            await session.commit()
            return {"ok": True, "item_id": str(item.id), "deck_id": str(item.deck_id)}

    async def delete(
        self, owner: uuid.UUID, deck_id: Any, item_ids: Optional[Sequence[uuid.UUID]]
    ) -> dict[str, Any]:
        """Delete the user's deck (with its items, reviews and quizzes), or
        some of its items (with their reviews). Ownership is checked in the
        same statements."""
        async with self.session() as session:
            deck = await self.deck(session, owner, deck_id)
            if deck is None:
                return {"ok": False, "reason": NOT_FOUND}
            if item_ids:
                ids = list(item_ids)
                found = (
                    await session.execute(
                        select(func.count())
                        .select_from(StudyItem)
                        .where(StudyItem.deck_id == deck.id, StudyItem.user_id == owner, StudyItem.id.in_(ids))
                    )
                ).scalar_one()
                await session.execute(
                    delete(StudyReview).where(StudyReview.user_id == owner, StudyReview.item_id.in_(ids))
                )
                await session.execute(
                    delete(StudyItem).where(
                        StudyItem.deck_id == deck.id, StudyItem.user_id == owner, StudyItem.id.in_(ids)
                    )
                )
                await session.commit()
                return {"ok": True, "deck_id": str(deck.id), "deleted_items": int(found)}
            items = await self.item_count(session, owner, deck.id)
            # Children first: the ORM does not rely on the database's
            # cascade (SQLite runs without it unless asked).
            await session.execute(delete(StudyReview).where(StudyReview.deck_id == deck.id, StudyReview.user_id == owner))
            await session.execute(
                delete(StudyQuizAttempt).where(StudyQuizAttempt.deck_id == deck.id, StudyQuizAttempt.user_id == owner)
            )
            await session.execute(delete(StudyItem).where(StudyItem.deck_id == deck.id, StudyItem.user_id == owner))
            await session.execute(delete(StudyDeck).where(StudyDeck.id == deck.id, StudyDeck.user_id == owner))
            await session.commit()
            return {"ok": True, "deck_id": str(deck_id), "deleted_deck": True, "deleted_items": items}

    async def deck_facts(self, owner: uuid.UUID, deck_id: Any) -> Optional[dict[str, Any]]:
        """What a delete card states, from the database: the deck's title and
        how many items and reviews it has. None for a deck that is not the
        user's."""
        async with self.session() as session:
            deck = await self.deck(session, owner, deck_id)
            if deck is None:
                return None
            items = await self.item_count(session, owner, deck.id)
            reviews = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(StudyReview)
                        .where(StudyReview.deck_id == deck.id, StudyReview.user_id == owner)
                    )
                ).scalar_one()
            )
            return {"title": deck.title, "items": items, "reviews": reviews}

    async def items_in_deck(
        self, owner: uuid.UUID, deck_id: Any, item_ids: Sequence[uuid.UUID]
    ) -> Optional[int]:
        """How many of *item_ids* are in the user's deck; None when the deck
        is not theirs."""
        async with self.session() as session:
            deck = await self.deck(session, owner, deck_id)
            if deck is None:
                return None
            return int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(StudyItem)
                        .where(
                            StudyItem.deck_id == deck.id,
                            StudyItem.user_id == owner,
                            StudyItem.id.in_(list(item_ids)),
                        )
                    )
                ).scalar_one()
            )

    # -- the review queue ----------------------------------------------------------

    async def settings(self, owner: uuid.UUID) -> ReviewSettings:
        async with self.session() as session:
            return await load_settings(session, owner)

    async def queue(
        self, owner: uuid.UUID, *, limit: int, deck_id: Optional[uuid.UUID] = None, exclude: Sequence[str] = ()
    ) -> dict[str, Any]:
        """What to review now, oldest-due first: due cards, then new cards
        up to what is left of today's new-card allowance. Also the counts."""
        now = self._clock()
        skip = [k for k in (as_uuid(i) for i in exclude) if k is not None]
        async with self.session() as session:
            settings = await load_settings(session, owner)
            tz = await self.zone(session, owner)
            new_left = await new_left_today(session, owner, now, tz, settings.new_per_day)
            base = (
                select(StudyItem)
                .join(StudyDeck, StudyDeck.id == StudyItem.deck_id)
                .where(*_reviewable(owner, deck_id))
            )
            if skip:
                base = base.where(StudyItem.id.not_in(skip))
            due = list(
                (
                    await session.execute(
                        base.where(StudyItem.due_at.is_not(None), StudyItem.due_at <= now)
                        .order_by(StudyItem.due_at, StudyItem.position, StudyItem.id)
                        .limit(max(0, limit))
                    )
                )
                .scalars()
                .all()
            )
            new: list[StudyItem] = []
            room = min(max(0, limit - len(due)), new_left)
            if room > 0:
                new = list(
                    (
                        await session.execute(
                            base.where(StudyItem.due_at.is_(None))
                            .order_by(StudyDeck.created_at, StudyItem.deck_id, StudyItem.position, StudyItem.id)
                            .limit(room)
                        )
                    )
                    .scalars()
                    .all()
                )
            due_total = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(StudyItem)
                        .join(StudyDeck, StudyDeck.id == StudyItem.deck_id)
                        .where(*_reviewable(owner, deck_id), StudyItem.due_at.is_not(None), StudyItem.due_at <= now)
                    )
                ).scalar_one()
            )
            new_total = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(StudyItem)
                        .join(StudyDeck, StudyDeck.id == StudyItem.deck_id)
                        .where(*_reviewable(owner, deck_id), StudyItem.due_at.is_(None))
                    )
                ).scalar_one()
            )
            titles: dict[uuid.UUID, str] = {}
            deck_ids = {i.deck_id for i in (*due, *new)}
            if deck_ids:
                titles = {
                    r[0]: r[1]
                    for r in (
                        await session.execute(
                            select(StudyDeck.id, StudyDeck.title).where(
                                StudyDeck.user_id == owner, StudyDeck.id.in_(list(deck_ids))
                            )
                        )
                    ).all()
                }
        return {
            "items": [*due, *new],
            "titles": titles,
            "due": due_total,
            "new_available": min(new_total, new_left),
            "new_total": new_total,
            "new_left_today": new_left,
            "session_size": settings.session_size,
        }

    async def grade(
        self, owner: uuid.UUID, item_id: Any, rating: Any, *, mode: str = "review", channel: str = "chat"
    ) -> GradeResult:
        """Apply SM-2 for *rating* to the user's item, only while it is still
        due and unchanged since it was read; record the review."""
        name = srs.rating_name(rating)
        if name is None:
            raise ValueError("rating must be again, hard, good or easy")
        now = self._clock()
        async with self.session() as session:
            item = await self.item(session, owner, item_id)
            if item is None:
                return GradeResult(False, reason=NOT_FOUND)
            due_at = _utc(item.due_at)
            if item.suspended or (due_at is not None and due_at > now):
                return GradeResult(False, item=item, reason="not_due")
            state = card_state(item)
            result = srs.schedule(state, name, now)
            changed = await session.execute(
                update(StudyItem)
                .where(
                    StudyItem.id == item.id,
                    StudyItem.user_id == owner,
                    StudyItem.suspended.is_(False),
                    StudyItem.repetitions == state.repetitions,
                    StudyItem.lapses == state.lapses,
                    or_(StudyItem.due_at.is_(None), StudyItem.due_at <= now),
                )
                .values(
                    ease=result.state.ease,
                    interval_days=result.state.interval_days,
                    repetitions=result.state.repetitions,
                    lapses=result.state.lapses,
                    due_at=result.due_at,
                    last_reviewed_at=now,
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if changed.rowcount != 1:
                await session.rollback()
                return GradeResult(False, item=item, reason="not_due")
            session.add(
                StudyReview(
                    id=uuid.uuid4(),
                    user_id=owner,
                    deck_id=item.deck_id,
                    item_id=item.id,
                    reviewed_at=now,
                    rating=srs.RATING_NUMBERS[name],
                    was_new=item.last_reviewed_at is None,
                    mode=mode,
                    channel=channel,
                    interval_after_days=result.state.interval_days,
                    ease_after=result.state.ease,
                )
            )
            await session.execute(
                update(StudyDeck)
                .where(StudyDeck.id == item.deck_id, StudyDeck.user_id == owner)
                .values(last_studied_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
            return GradeResult(True, item=item, rating=name, interval=result.due_at - now, due_at=result.due_at)

    async def skip(self, owner: uuid.UUID, item_id: Any) -> bool:
        """Put a due card away for an hour without touching its interval or
        ease. False when it is not the user's or not due."""
        now = self._clock()
        key = as_uuid(item_id)
        if key is None:
            return False
        async with self.session() as session:
            changed = await session.execute(
                update(StudyItem)
                .where(
                    StudyItem.id == key,
                    StudyItem.user_id == owner,
                    StudyItem.suspended.is_(False),
                    or_(StudyItem.due_at.is_(None), StudyItem.due_at <= now),
                )
                .values(due_at=now + timedelta(minutes=SKIP_MINUTES), updated_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
            return changed.rowcount == 1

    # -- quizzes -------------------------------------------------------------------

    async def _abandon_stale(self, session: Any, owner: uuid.UUID, now: datetime) -> None:
        await session.execute(
            update(StudyQuizAttempt)
            .where(
                StudyQuizAttempt.user_id == owner,
                StudyQuizAttempt.status == "active",
                StudyQuizAttempt.started_at < now - ABANDON_AFTER,
            )
            .values(status="abandoned")
            .execution_options(synchronize_session=False)
        )

    async def quiz_start(
        self,
        owner: uuid.UUID,
        deck_id: Any,
        *,
        count: int,
        channel: str,
        tag: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> dict[str, Any]:
        """Pick up to *count* items (choice items first; within each kind
        overdue, most-lapsed and least-accurate first, then an order seeded
        by the attempt id) and store the attempt."""
        now = self._clock()
        async with self.session() as session:
            deck = await self.deck(session, owner, deck_id)
            if deck is None:
                return {"ok": False, "reason": NOT_FOUND}
            await self._abandon_stale(session, owner, now)
            items = list(
                (
                    await session.execute(
                        select(StudyItem).where(
                            StudyItem.deck_id == deck.id,
                            StudyItem.user_id == owner,
                            StudyItem.suspended.is_(False),
                        )
                    )
                )
                .scalars()
                .all()
            )
            if tag:
                items = [i for i in items if tag in (i.tags or [])]
            if difficulty:
                items = [i for i in items if i.difficulty == difficulty]
            if not items:
                await session.commit()
                return {"ok": False, "reason": "empty"}
            accuracy = await self._item_accuracy(session, owner, [i.id for i in items])
            attempt_id = uuid.uuid4()
            rng = random.Random(str(attempt_id))
            keyed = []
            for item in items:
                due = _utc(item.due_at)
                overdue = due is not None and due <= now
                seen, right = accuracy.get(item.id, (0, 0))
                acc = right / seen if seen else 1.0
                keyed.append(((0 if item.kind == "choice" else 1, 0 if overdue else 1, -int(item.lapses or 0), acc, rng.random()), item))
            keyed.sort(key=lambda kv: kv[0])
            picked = [item for _key, item in keyed[: max(1, min(count, QUIZ_MAX_ITEMS))]]
            attempt = StudyQuizAttempt(
                id=attempt_id,
                user_id=owner,
                deck_id=deck.id,
                channel=channel,
                item_ids=[str(i.id) for i in picked],
                position=0,
                answers=[],
                total=len(picked),
                answered=0,
                correct=0,
                status="active",
                started_at=now,
            )
            session.add(attempt)
            await session.commit()
            return {"ok": True, "attempt": attempt, "items": picked, "deck": deck}

    async def _item_accuracy(
        self, session: Any, owner: uuid.UUID, item_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, tuple[int, int]]:
        if not item_ids:
            return {}
        rows = (
            await session.execute(
                select(
                    StudyReview.item_id,
                    func.count(),
                    func.sum(case((StudyReview.rating >= CORRECT_RATING, 1), else_=0)),
                )
                .where(StudyReview.user_id == owner, StudyReview.item_id.in_(list(item_ids)))
                .group_by(StudyReview.item_id)
            )
        ).all()
        return {r[0]: (int(r[1]), int(r[2] or 0)) for r in rows}

    async def attempt(
        self, owner: uuid.UUID, attempt_id: Any
    ) -> Optional[tuple[StudyQuizAttempt, list[StudyItem], StudyDeck]]:
        """The user's attempt with its items in quiz order (items deleted
        since are left out) and its deck; None when it is not theirs."""
        key = as_uuid(attempt_id)
        if key is None:
            return None
        async with self.session() as session:
            attempt = (
                await session.execute(
                    select(StudyQuizAttempt).where(StudyQuizAttempt.id == key, StudyQuizAttempt.user_id == owner)
                )
            ).scalar_one_or_none()
            if attempt is None:
                return None
            if attempt.status == "active" and (_utc(attempt.started_at) or self._clock()) < self._clock() - ABANDON_AFTER:
                attempt.status = "abandoned"
                await session.commit()
            ids = [k for k in (as_uuid(i) for i in attempt.item_ids or []) if k is not None]
            rows = (
                (
                    await session.execute(
                        select(StudyItem).where(StudyItem.user_id == owner, StudyItem.id.in_(ids))
                    )
                )
                .scalars()
                .all()
                if ids
                else []
            )
            by_id = {r.id: r for r in rows}
            deck = await session.get(StudyDeck, attempt.deck_id)
            if deck is None:
                return None
            return attempt, [by_id[i] for i in ids if i in by_id], deck

    async def record_answers(
        self,
        owner: uuid.UUID,
        attempt: StudyQuizAttempt,
        results: Sequence[dict[str, Any]],
        *,
        position: Optional[int] = None,
    ) -> bool:
        """Store graded answers on the attempt, only while it is still
        active and at the position (or answered count) it was read at; make
        each wrong item due now and record each answer for accuracy. False
        when someone got there first."""
        now = self._clock()
        guard_answered = int(attempt.answered or 0)
        answers = [*list(attempt.answers or []), *[
            {"item_id": r["item_id"], "choice": r.get("choice"), "correct": bool(r["correct"])} for r in results
        ]]
        correct = int(attempt.correct or 0) + sum(1 for r in results if r["correct"])
        answered = guard_answered + len(results)
        new_position = int(attempt.position or 0) + len(results) if position is None else position + 1
        async with self.session() as session:
            changed = await session.execute(
                update(StudyQuizAttempt)
                .where(
                    StudyQuizAttempt.id == attempt.id,
                    StudyQuizAttempt.user_id == owner,
                    StudyQuizAttempt.status == "active",
                    StudyQuizAttempt.answered == guard_answered,
                    StudyQuizAttempt.position == (attempt.position if position is None else position),
                )
                .values(answers=answers, answered=answered, correct=correct, position=new_position)
                .execution_options(synchronize_session=False)
            )
            if changed.rowcount != 1:
                await session.rollback()
                return False
            for r in results:
                item_key = as_uuid(r["item_id"])
                if item_key is None:
                    continue
                item = await self.item(session, owner, item_key)
                if item is None:
                    continue
                if not r["correct"]:
                    await session.execute(
                        update(StudyItem)
                        .where(StudyItem.id == item.id, StudyItem.user_id == owner)
                        .values(due_at=now, updated_at=now)
                        .execution_options(synchronize_session=False)
                    )
                session.add(
                    StudyReview(
                        id=uuid.uuid4(),
                        user_id=owner,
                        deck_id=item.deck_id,
                        item_id=item.id,
                        reviewed_at=now,
                        rating=QUIZ_RIGHT_RATING if r["correct"] else QUIZ_WRONG_RATING,
                        was_new=False,
                        mode="quiz",
                        channel=attempt.channel,
                        interval_after_days=float(item.interval_days or 0.0),
                        ease_after=float(item.ease or srs.START_EASE),
                    )
                )
            await session.execute(
                update(StudyDeck)
                .where(StudyDeck.id == attempt.deck_id, StudyDeck.user_id == owner)
                .values(last_studied_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        attempt.answers, attempt.answered, attempt.correct, attempt.position = answers, answered, correct, new_position
        return True

    async def quiz_pass(self, owner: uuid.UUID, attempt: StudyQuizAttempt, position: int) -> bool:
        """Move an active attempt past *position*, a question deleted since
        the quiz started, without recording an answer (the chat channels'
        positions count over ``attempt.item_ids``). False when the attempt
        moved on or ended meanwhile."""
        async with self.session() as session:
            changed = await session.execute(
                update(StudyQuizAttempt)
                .where(
                    StudyQuizAttempt.id == attempt.id,
                    StudyQuizAttempt.user_id == owner,
                    StudyQuizAttempt.status == "active",
                    StudyQuizAttempt.position == position,
                )
                .values(position=position + 1)
                .execution_options(synchronize_session=False)
            )
            if changed.rowcount != 1:
                await session.rollback()
                return False
            await session.commit()
        attempt.position = position + 1
        return True

    async def quiz_finish(self, owner: uuid.UUID, attempt_id: Any) -> Optional[StudyQuizAttempt]:
        key = as_uuid(attempt_id)
        if key is None:
            return None
        now = self._clock()
        async with self.session() as session:
            attempt = (
                await session.execute(
                    select(StudyQuizAttempt).where(StudyQuizAttempt.id == key, StudyQuizAttempt.user_id == owner)
                )
            ).scalar_one_or_none()
            if attempt is None:
                return None
            if attempt.status == "active":
                attempt.status = "finished"
                attempt.finished_at = now
            await session.commit()
            return attempt

    async def recent_quizzes(self, owner: uuid.UUID, limit: int = 5) -> list[StudyQuizAttempt]:
        async with self.session() as session:
            return list(
                (
                    await session.execute(
                        select(StudyQuizAttempt)
                        .where(StudyQuizAttempt.user_id == owner, StudyQuizAttempt.status == "finished")
                        .order_by(StudyQuizAttempt.started_at.desc())
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )

    # -- progress ------------------------------------------------------------------

    async def progress(
        self, owner: uuid.UUID, *, deck_ids: Optional[Sequence[uuid.UUID]] = None
    ) -> dict[str, Any]:
        """Due today, a 7-day forecast, 30-day reviews and accuracy, the
        streak, the weakest decks and tags, and the last quiz scores. Counts,
        titles and tags only."""
        now = self._clock()
        async with self.session() as session:
            settings = await load_settings(session, owner)
            tz = await self.zone(session, owner)
            scope: list[Any] = [StudyItem.user_id == owner, StudyItem.suspended.is_(False)]
            review_scope: list[Any] = [StudyReview.user_id == owner]
            if deck_ids is not None:
                scope.append(StudyItem.deck_id.in_(list(deck_ids)))
                review_scope.append(StudyReview.deck_id.in_(list(deck_ids)))
            in_reviews = [*scope, StudyDeck.in_reviews.is_(True)]
            end_today = day_end(now, tz)
            upcoming = (
                await session.execute(
                    select(StudyItem.due_at)
                    .join(StudyDeck, StudyDeck.id == StudyItem.deck_id)
                    .where(
                        *in_reviews,
                        StudyItem.due_at.is_not(None),
                        StudyItem.due_at < end_today + timedelta(days=FORECAST_DAYS - 1),
                    )
                )
            ).scalars().all()
            new_total = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(StudyItem)
                        .join(StudyDeck, StudyDeck.id == StudyItem.deck_id)
                        .where(*in_reviews, StudyItem.due_at.is_(None))
                    )
                ).scalar_one()
            )
            new_left = await new_left_today(session, owner, now, tz, settings.new_per_day)
            forecast = [0] * FORECAST_DAYS
            today = now.astimezone(tz).date()
            for due in upcoming:
                when = _utc(due)
                if when is None:
                    continue
                offset = max(0, (when.astimezone(tz).date() - today).days)
                if offset < FORECAST_DAYS:
                    forecast[offset] += 1
            since = now - timedelta(days=ACCURACY_DAYS)
            reviews = (
                await session.execute(
                    select(StudyReview.reviewed_at, StudyReview.rating, StudyReview.deck_id, StudyReview.item_id)
                    .where(*review_scope, StudyReview.reviewed_at >= since)
                )
            ).all()
            total = len(reviews)
            right = sum(1 for r in reviews if int(r[1]) >= CORRECT_RATING)
            days_with_reviews = {(_utc(r[0]) or now).astimezone(tz).date() for r in reviews}
            streak = 0
            cursor = today if today in days_with_reviews else today - timedelta(days=1)
            while cursor in days_with_reviews:
                streak += 1
                cursor -= timedelta(days=1)
            by_deck: dict[uuid.UUID, list[int]] = {}
            by_item: dict[uuid.UUID, list[int]] = {}
            for _when, rating, deck_id, item_id in reviews:
                d = by_deck.setdefault(deck_id, [0, 0])
                d[0] += 1
                d[1] += 1 if int(rating) >= CORRECT_RATING else 0
                it = by_item.setdefault(item_id, [0, 0])
                it[0] += 1
                it[1] += 1 if int(rating) >= CORRECT_RATING else 0
            titles = {
                r[0]: r[1]
                for r in (
                    await session.execute(select(StudyDeck.id, StudyDeck.title).where(StudyDeck.user_id == owner))
                ).all()
            }
            tag_rows = (
                (
                    await session.execute(
                        select(StudyItem.id, StudyItem.tags).where(
                            StudyItem.user_id == owner, StudyItem.id.in_(list(by_item))
                        )
                    )
                ).all()
                if by_item
                else []
            )
            by_tag: dict[str, list[int]] = {}
            for item_id, tags in tag_rows:
                seen, ok = by_item.get(item_id, [0, 0])
                for tag in tags or []:
                    t = by_tag.setdefault(str(tag), [0, 0])
                    t[0] += seen
                    t[1] += ok
            quizzes = list(
                (
                    await session.execute(
                        select(StudyQuizAttempt)
                        .where(StudyQuizAttempt.user_id == owner, StudyQuizAttempt.status == "finished")
                        .order_by(StudyQuizAttempt.started_at.desc())
                        .limit(5)
                    )
                )
                .scalars()
                .all()
            )
            nudge = None
            if settings.nudge_task_id is not None:
                from models.scheduled_task import ScheduledTask

                task = await session.get(ScheduledTask, settings.nudge_task_id)
                if task is not None and task.user_id == owner:
                    nudge = {
                        "on": task.status == "active",
                        "recurrence": task.recurrence,
                        "timezone": task.timezone,
                        "channels": list(task.channels or []),
                    }
        due_today = forecast[0] + min(new_total, new_left)

        def weakest(table: dict[Any, list[int]], name: Callable[[Any], str]) -> list[dict[str, Any]]:
            ranked = sorted(
                ((round(v[1] / v[0], 2), -v[0], name(key)) for key, v in table.items() if v[0] >= 3),
            )
            return [
                {"name": label, "reviews": -negative, "accuracy": accuracy}
                for accuracy, negative, label in ranked[:3]
            ]

        return {
            "timezone": str(tz.key),
            "due_today": due_today,
            "due_now": sum(
                1 for d in upcoming if (_utc(d) or now) <= now
            ),
            "new_available_today": min(new_total, new_left),
            "forecast_7d": forecast,
            "reviews_30d": total,
            "accuracy_30d": round(right / total, 2) if total else None,
            "streak_days": streak,
            "weakest_decks": weakest(by_deck, lambda k: str(titles.get(k, "a deleted deck"))),
            "weakest_tags": weakest(by_tag, str),
            "last_quizzes": [
                {
                    "deck": str(titles.get(q.deck_id, "a deleted deck")),
                    "score": f"{q.correct}/{q.total}",
                    "percent": round(100 * q.correct / q.total) if q.total else 0,
                }
                for q in quizzes
            ],
            "nudge": nudge,
            "settings": {"new_per_day": settings.new_per_day, "session_size": settings.session_size},
        }

    # -- settings ------------------------------------------------------------------

    async def save_settings(self, owner: uuid.UUID, **fields: Any) -> ReviewSettings:
        now = self._clock()
        async with self.session() as session:
            row = await session.get(StudySettings, owner)
            if row is None:
                row = StudySettings(
                    user_id=owner,
                    new_per_day=DEFAULT_NEW_PER_DAY,
                    session_size=DEFAULT_SESSION_SIZE,
                    updated_at=now,
                )
                session.add(row)
            for name, value in fields.items():
                setattr(row, name, value)
            row.updated_at = now
            await session.commit()
            return ReviewSettings(int(row.new_per_day), int(row.session_size), row.nudge_task_id)
