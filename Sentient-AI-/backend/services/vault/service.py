"""The only reader and writer of ``vault_items``: stores the owner's card
sealed, lists masked views, and opens the card for the checkout toolkit
(purchases spec §4).

Why it exists: Every path to a card value goes through this one class, so
the guarantees are checked here once: the number is Luhn-valid and the
expiry ahead before anything is sealed; views carry brand and last4 only;
``open_card`` is the single decrypting call, it stamps ``last_used_at`` and
logs kind, label and purpose, never the value; and ``CardSecret`` prints
masked so an accidental ``repr`` in a log or traceback shows ``····4242``.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Callable, Optional, Sequence

import structlog
from sqlalchemy import select

from models.vault_item import VaultItem
from services.vault import crypto
from services.vault.keys import KeyProvider, VaultUnavailable

logger = structlog.get_logger(__name__)

KIND_CARD = "card"
KIND_LOGIN = "login"
KINDS = (KIND_CARD, KIND_LOGIN)
MASK = "····"
MAX_LABEL = 120
MAX_NAME = 120
MAX_ORIGINS = 20
NO_CARD = "No payment card is stored."


def _aad(kind: str, item_id: uuid.UUID) -> bytes:
    """The associated data that pins a blob to its row (crypto.py)."""
    return f"vault_items:{kind}:{item_id}".encode("ascii")


def mask_card(brand: str, last4: str) -> str:
    return f"{brand} {MASK}{last4}"


def _split_mask(kind: str, masked: str) -> tuple[str, str]:
    """(brand, last4) back out of a card's masked label; empty for logins."""
    if kind == KIND_CARD:
        brand, sep, last4 = masked.rpartition(f" {MASK}")
        if sep:
            return brand, last4
    return "", ""


def _iso(moment: Optional[datetime]) -> Optional[str]:
    # SQLite hands naive datetimes back even for timezone=True columns;
    # every row is written in UTC, so say so.
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat()


def _uid(user_id: Any) -> uuid.UUID:
    return user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))


@dataclass(frozen=True)
class VaultItemView:
    """The only shape the API and the checkout card ever see."""

    id: str
    kind: str
    label: str
    origins: tuple[str, ...]
    masked: str
    brand: str
    last4: str
    created_at: str
    last_used_at: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "origins": list(self.origins),
            "masked": self.masked,
            "brand": self.brand,
            "last4": self.last4,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
        }


@dataclass
class CardSecret:
    """A decrypted card, alive only inside the checkout toolkit's fill.
    Prints masked so no log, traceback or f-string can show the number."""

    number: str
    exp_month: int
    exp_year: int
    cvc: str
    name: str
    brand: str
    last4: str

    def __repr__(self) -> str:
        return f"<CardSecret {MASK}{self.last4}>"

    __str__ = __repr__

    def wipe(self) -> None:
        """Hook for the toolkit's ``finally``. Python strings cannot be
        zeroed in place; this drops the references so nothing keeps the
        object readable by accident after the fill."""
        self.number = ""
        self.cvc = ""


# -- validation (ValueError messages are shown to the owner as-is) -----------


def normalize_card_number(number: str) -> str:
    """The digits of *number* with spaces and dashes dropped; ValueError
    when anything else is in it or the Luhn check fails."""
    digits = "".join(ch for ch in number if ch not in " -")
    if not digits.isdigit():
        raise ValueError("The card number may only contain digits.")
    if not crypto.luhn_ok(digits):
        raise ValueError("That does not look like a valid card number.")
    return digits


def check_expiry(exp_month: int, exp_year: int, *, today: Optional[date] = None) -> tuple[int, int]:
    """(month, four-digit year); ValueError for an impossible month or a
    card that already expired (valid through the end of its month)."""
    if not isinstance(exp_month, int) or not isinstance(exp_year, int):
        raise ValueError("The expiry must be a month and a year.")
    if not 1 <= exp_month <= 12:
        raise ValueError("The expiry month must be between 1 and 12.")
    if 0 <= exp_year < 100:
        exp_year += 2000
    if not 2000 <= exp_year <= 2099:
        raise ValueError("The expiry year is not valid.")
    now = today or datetime.now(timezone.utc).date()
    if (exp_year, exp_month) < (now.year, now.month):
        raise ValueError("That card has expired.")
    return exp_month, exp_year


def check_cvc(cvc: str) -> str:
    cvc = cvc.strip()
    if not cvc.isdigit() or not 3 <= len(cvc) <= 4:
        raise ValueError("The security code must be 3 or 4 digits.")
    return cvc


def check_name(name: str) -> str:
    name = " ".join(name.split())
    if not name or len(name) > MAX_NAME or not name.isprintable():
        raise ValueError("Enter the name as it appears on the card.")
    return name


def check_label(label: Optional[str], fallback: str) -> str:
    label = " ".join((label or "").split())
    if len(label) > MAX_LABEL or not label.isprintable():
        raise ValueError("The label is too long.")
    return label or fallback


def check_origins(origins: Sequence[str]) -> list[str]:
    seen: dict[str, None] = {}
    for origin in origins:
        origin = origin.strip().lower()
        if origin:
            seen[origin] = None
    return list(seen)[:MAX_ORIGINS]


class VaultService:
    def __init__(self, session_factory: Callable[[], Any], key_provider: KeyProvider) -> None:
        self._session_factory = session_factory
        self._keys = key_provider

    def available(self) -> tuple[bool, str]:
        """(True, "") when the key store can be reached; (False, reason) to
        show the owner instead of the card form. Asks the provider's
        ``check``, which never mints a key: Settings is opened long before
        the owner decides to store a card, and until then the Keychain
        must hold nothing of Crawler's. A provider without ``check`` (a
        test's fixed key) is asked for the key itself."""
        probe = getattr(self._keys, "check", None)
        try:
            if callable(probe):
                probe()
            else:
                self._keys.get()
        except VaultUnavailable as exc:
            return False, str(exc)
        return True, ""

    async def _key(self) -> bytes:
        # On a Mac the first read is a `security` subprocess; keep it off
        # the event loop (the provider caches after that).
        return await asyncio.to_thread(self._keys.get)

    @staticmethod
    def _view(row: VaultItem) -> VaultItemView:
        brand, last4 = _split_mask(row.kind, row.masked)
        return VaultItemView(
            id=str(row.id),
            kind=row.kind,
            label=row.label,
            origins=tuple(row.origins or ()),
            masked=row.masked,
            brand=brand,
            last4=last4,
            created_at=_iso(row.created_at) or "",
            last_used_at=_iso(row.last_used_at),
        )

    async def put_card(
        self,
        user_id: Any,
        *,
        label: str,
        number: str,
        exp_month: int,
        exp_year: int,
        cvc: str,
        name: str,
        origins: Sequence[str] = (),
    ) -> VaultItemView:
        """Store the owner's one card, replacing any stored before.

        Validation comes first and the key second, so a bad number never
        touches the key store and a container answers "unavailable" with
        nothing written. ValueError carries the owner-facing reason.
        """
        uid = _uid(user_id)
        digits = normalize_card_number(number)
        month, year = check_expiry(exp_month, exp_year)
        cvc = check_cvc(cvc)
        name = check_name(name)
        brand = crypto.card_brand(digits)
        last4 = digits[-4:]
        masked = mask_card(brand, last4)
        label = check_label(label, masked)
        origin_list = check_origins(origins)
        key = await self._key()

        item_id = uuid.uuid4()
        payload = json.dumps(
            {"number": digits, "exp_month": month, "exp_year": year, "cvc": cvc, "name": name},
            separators=(",", ":"),
        ).encode("utf-8")
        blob = crypto.seal(key, payload, _aad(KIND_CARD, item_id))
        now = datetime.now(timezone.utc)
        row = VaultItem(
            id=item_id,
            user_id=uid,
            kind=KIND_CARD,
            label=label,
            origins=origin_list,
            masked=masked,
            blob=blob,
            created_at=now,
            updated_at=now,
        )
        async with self._session_factory() as session:
            result = await session.execute(
                select(VaultItem).where(VaultItem.user_id == uid, VaultItem.kind == KIND_CARD)
            )
            for old in result.scalars():
                await session.delete(old)
            session.add(row)
            await session.commit()
        logger.info("vault_card_stored", kind=KIND_CARD, label=label, item_id=str(item_id))
        return self._view(row)

    async def list_items(self, user_id: Any, kind: Optional[str] = None) -> list[VaultItemView]:
        uid = _uid(user_id)
        query = select(VaultItem).where(VaultItem.user_id == uid)
        if kind is not None:
            query = query.where(VaultItem.kind == kind)
        query = query.order_by(VaultItem.created_at, VaultItem.id)
        async with self._session_factory() as session:
            rows = (await session.execute(query)).scalars().all()
        return [self._view(row) for row in rows]

    async def get_card_view(self, user_id: Any) -> Optional[VaultItemView]:
        cards = await self.list_items(user_id, KIND_CARD)
        return cards[0] if cards else None

    async def delete_item(self, user_id: Any, item_id: str) -> bool:
        """True when a row of this user's was removed; False for an id that
        is not theirs, not stored, or not an id at all."""
        uid = _uid(user_id)
        try:
            iid = uuid.UUID(str(item_id))
        except ValueError:
            return False
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(VaultItem).where(VaultItem.id == iid, VaultItem.user_id == uid)
                )
            ).scalar_one_or_none()
            if row is None:
                return False
            kind, label = row.kind, row.label
            await session.delete(row)
            await session.commit()
        logger.info("vault_item_deleted", kind=kind, label=label, item_id=str(iid))
        return True

    async def open_card(self, user_id: Any, *, purpose: str) -> CardSecret:
        """Decrypt the stored card for one use. Only the checkout toolkit
        calls this, after the owner approved the purchase; the log line
        says which item was opened and why, never what it holds."""
        uid = _uid(user_id)
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(VaultItem)
                    .where(VaultItem.user_id == uid, VaultItem.kind == KIND_CARD)
                    .order_by(VaultItem.created_at, VaultItem.id)
                )
            ).scalars().first()
            if row is None:
                raise VaultUnavailable(NO_CARD)
            key = await self._key()
            try:
                plaintext = crypto.open_(key, row.blob, _aad(row.kind, row.id))
            except VaultUnavailable:
                logger.warning("vault_item_unreadable", kind=row.kind, item_id=str(row.id))
                raise VaultUnavailable(
                    "The stored card cannot be read any more. Store it again in Settings."
                ) from None
            row.last_used_at = datetime.now(timezone.utc)
            await session.commit()
            kind, label, item_id, masked = row.kind, row.label, row.id, row.masked
        data = json.loads(plaintext.decode("utf-8"))
        brand, last4 = _split_mask(kind, masked)
        logger.info(
            "vault_item_opened", kind=kind, label=label, purpose=purpose, item_id=str(item_id)
        )
        return CardSecret(
            number=str(data["number"]),
            exp_month=int(data["exp_month"]),
            exp_year=int(data["exp_year"]),
            cvc=str(data["cvc"]),
            name=str(data["name"]),
            brand=brand,
            last4=last4,
        )
