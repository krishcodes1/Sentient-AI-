"""services/vault/service: the card goes in sealed and comes out only through
open_card; every view is masked; one card per owner; a blob moved to another
row will not open; and no log line ever carries the number. The key is a
dev file in tmp_path, the database the shared in-memory SQLite."""

from __future__ import annotations

import uuid
from datetime import date

import pytest
import structlog
from sqlalchemy import select, update

from models.vault_item import VaultItem
from services.vault import service as vault_module
from services.vault.keys import DevFileKeyProvider, DisabledKeyProvider, VaultUnavailable
from services.vault.service import (
    NO_CARD,
    CardSecret,
    VaultItemView,
    VaultService,
    check_expiry,
    normalize_card_number,
)
from tests.conftest import make_user

NUMBER = "4242 4242 4242 4242"
DIGITS = "4242424242424242"
CVC = "123"
CARD = {"label": "", "number": NUMBER, "exp_month": 12, "exp_year": 2099, "cvc": CVC, "name": "Krish Q"}


@pytest.fixture
def vault(session_factory, tmp_path):
    return VaultService(session_factory, DevFileKeyProvider(tmp_path / "dev.key"))


@pytest.fixture
def capture(monkeypatch):
    """structlog capture for the vault module: the app configures structlog
    at import, so the module logger is re-bound inside the capture."""
    with structlog.testing.capture_logs() as logs:
        monkeypatch.setattr(vault_module, "logger", structlog.get_logger(vault_module.__name__))
        yield logs


async def _owner(session_factory):
    user, _token = await make_user(session_factory, "owner@example.com")
    return str(user.id)


async def _rows(session_factory) -> list[VaultItem]:
    async with session_factory() as session:
        return list((await session.execute(select(VaultItem))).scalars())


# -- put / list / get ------------------------------------------------------


@pytest.mark.asyncio
async def test_put_card_returns_a_masked_view(session_factory, vault):
    user = await _owner(session_factory)
    view = await vault.put_card(user, **CARD)
    assert isinstance(view, VaultItemView)
    assert view.kind == "card" and view.brand == "Visa" and view.last4 == "4242"
    assert view.masked == "Visa ····4242"
    assert view.label == "Visa ····4242"  # no label given: the masked string
    assert uuid.UUID(view.id) and view.created_at and view.last_used_at is None
    body = view.to_dict()
    assert set(body) == {
        "id", "kind", "label", "origins", "masked", "brand", "last4", "created_at", "last_used_at"
    }
    assert DIGITS not in repr(view) and CVC not in str(body)


@pytest.mark.asyncio
async def test_the_row_holds_no_plaintext(session_factory, vault):
    user = await _owner(session_factory)
    await vault.put_card(user, **CARD)
    (row,) = await _rows(session_factory)
    assert DIGITS.encode() not in row.blob and b"Krish" not in row.blob and CVC.encode() not in row.blob
    assert DIGITS not in repr(row)
    assert row.masked == "Visa ····4242" and row.origins == []


@pytest.mark.asyncio
async def test_list_and_get_card_view(session_factory, vault):
    user = await _owner(session_factory)
    assert await vault.list_items(user) == []
    assert await vault.get_card_view(user) is None
    view = await vault.put_card(user, **{**CARD, "label": "My Visa", "origins": ("Shop.example.com ", "shop.example.com")})
    assert view.label == "My Visa" and view.origins == ("shop.example.com",)
    assert await vault.list_items(user) == [view]
    assert await vault.list_items(user, "card") == [view]
    assert await vault.list_items(user, "login") == []
    assert await vault.get_card_view(user) == view


@pytest.mark.asyncio
async def test_a_second_card_replaces_the_first(session_factory, vault):
    user = await _owner(session_factory)
    first = await vault.put_card(user, **CARD)
    second = await vault.put_card(user, **{**CARD, "number": "5555555555554444"})
    assert second.id != first.id and second.masked == "Mastercard ····4444"
    assert [v.id for v in await vault.list_items(user)] == [second.id]
    assert len(await _rows(session_factory)) == 1


@pytest.mark.asyncio
async def test_cards_are_per_user(session_factory, vault):
    a = await _owner(session_factory)
    b_user, _ = await make_user(session_factory, "other@example.com")
    b = str(b_user.id)
    await vault.put_card(a, **CARD)
    assert await vault.list_items(b) == []
    assert await vault.delete_item(b, (await vault.get_card_view(a)).id) is False
    assert len(await vault.list_items(a)) == 1


# -- validation --------------------------------------------------------------


@pytest.mark.parametrize(
    "patch, match",
    [
        ({"number": "4242424242424241"}, "valid card number"),
        ({"number": "4242-abcd-4242-4242"}, "only contain digits"),
        ({"number": "42424242"}, "valid card number"),
        ({"exp_month": 13}, "between 1 and 12"),
        ({"exp_month": 0}, "between 1 and 12"),
        ({"exp_year": 2020}, "expired"),
        ({"cvc": "12"}, "3 or 4 digits"),
        ({"cvc": "12a"}, "3 or 4 digits"),
        ({"name": "   "}, "name as it appears"),
        ({"label": "x" * 121}, "label is too long"),
    ],
)
@pytest.mark.asyncio
async def test_put_card_refuses_bad_input_before_touching_the_key(
    session_factory, tmp_path, patch, match
):
    user = await _owner(session_factory)
    vault = VaultService(session_factory, DevFileKeyProvider(tmp_path / "dev.key"))
    with pytest.raises(ValueError, match=match):
        await vault.put_card(user, **{**CARD, **patch})
    assert not (tmp_path / "dev.key").exists()  # validation comes first
    assert await _rows(session_factory) == []


def test_expiry_accepts_a_two_digit_year_and_the_current_month():
    today = date(2026, 9, 25)
    assert check_expiry(9, 26, today=today) == (9, 2026)
    assert check_expiry(9, 2026, today=today) == (9, 2026)
    with pytest.raises(ValueError, match="expired"):
        check_expiry(8, 2026, today=today)
    with pytest.raises(ValueError, match="not valid"):
        check_expiry(1, 1999, today=today)
    with pytest.raises(ValueError):
        check_expiry("12", 2030, today=today)  # type: ignore[arg-type]


def test_normalize_card_number_drops_separators_only():
    assert normalize_card_number("4242 4242-4242 4242") == DIGITS
    with pytest.raises(ValueError):
        normalize_card_number("4242.4242.4242.4242")


# -- availability ------------------------------------------------------------


@pytest.mark.asyncio
async def test_unavailable_key_store_fails_closed(session_factory):
    user = await _owner(session_factory)
    vault = VaultService(session_factory, DisabledKeyProvider("not here (container)"))
    assert vault.available() == (False, "not here (container)")
    with pytest.raises(VaultUnavailable, match="container"):
        await vault.put_card(user, **CARD)
    assert await _rows(session_factory) == []
    # Reads that need no key still work: the Settings page lists nothing.
    assert await vault.list_items(user) == []


@pytest.mark.asyncio
async def test_available_when_the_key_can_be_read(vault):
    assert vault.available() == (True, "")


def test_available_never_writes_a_keychain_item(tmp_path):
    """Opening Settings (GET /vault/items) asks available(); on a Mac with
    nothing stored yet that must not mint the key into the login Keychain.
    The runner is a recorder, so the owner's Keychain is never touched."""
    from services.platform.mac import MacPlatform
    from services.vault.keys import PlatformKeyProvider
    from tests.test_platform import Recorder

    runner = Recorder((44, "The specified item could not be found in the keychain."))
    platform = MacPlatform(runner=runner, home=tmp_path)
    vault = VaultService(lambda: None, PlatformKeyProvider(platform))
    assert vault.available() == (True, "")
    assert [line.split()[0] for line in runner.inputs if line] == ['"find-generic-password"']
    assert not any("add-generic-password" in (line or "") for line in runner.inputs)


def test_available_reports_a_locked_keychain_in_plain_words(tmp_path):
    from services.platform.mac import MacPlatform
    from services.vault.keys import PlatformKeyProvider
    from tests.test_platform import Recorder

    runner = Recorder((51, "SecKeychainSearchCopyNext: User interaction is not allowed."))
    vault = VaultService(lambda: None, PlatformKeyProvider(MacPlatform(runner=runner, home=tmp_path)))
    ok, reason = vault.available()
    assert not ok
    assert reason == "Crawler could not open this Mac's Keychain. Unlock the Mac and try again."


# -- open_card ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_card_decrypts_for_the_checkout_and_stamps_last_used(
    session_factory, vault, capture
):
    user = await _owner(session_factory)
    await vault.put_card(user, **{**CARD, "label": "Blue Visa"})
    secret = await vault.open_card(user, purpose="checkout shop.example.com")
    assert isinstance(secret, CardSecret)
    assert secret.number == DIGITS and secret.cvc == CVC and secret.name == "Krish Q"
    assert (secret.exp_month, secret.exp_year) == (12, 2099)
    assert secret.brand == "Visa" and secret.last4 == "4242"
    assert repr(secret) == "<CardSecret ····4242>" and str(secret) == repr(secret)
    assert f"{secret}" == "<CardSecret ····4242>"
    view = await vault.get_card_view(user)
    assert view.last_used_at is not None

    opened = [e for e in capture if e["event"] == "vault_item_opened"]
    assert len(opened) == 1
    assert opened[0]["kind"] == "card" and opened[0]["label"] == "Blue Visa"
    assert opened[0]["purpose"] == "checkout shop.example.com"
    for event in capture:
        assert DIGITS not in str(event) and CVC not in str(event) and "Krish" not in str(event)

    secret.wipe()
    assert secret.number == "" and secret.cvc == ""


@pytest.mark.asyncio
async def test_open_card_without_a_card_is_unavailable(session_factory, vault):
    user = await _owner(session_factory)
    with pytest.raises(VaultUnavailable, match=NO_CARD):
        await vault.open_card(user, purpose="checkout")


@pytest.mark.asyncio
async def test_a_blob_moved_to_another_row_will_not_open(session_factory, vault, capture):
    # The associated data is the row's own kind and id: re-keying the row
    # (as a tamperer with database access could) breaks the tag.
    user = await _owner(session_factory)
    await vault.put_card(user, **CARD)
    async with session_factory() as session:
        await session.execute(update(VaultItem).values(id=uuid.uuid4()))
        await session.commit()
    with pytest.raises(VaultUnavailable, match="cannot be read"):
        await vault.open_card(user, purpose="checkout")
    assert any(e["event"] == "vault_item_unreadable" for e in capture)
    assert all(DIGITS not in str(e) for e in capture)


@pytest.mark.asyncio
async def test_a_changed_key_makes_the_card_unreadable_not_wrong(session_factory, tmp_path):
    user = await _owner(session_factory)
    await VaultService(session_factory, DevFileKeyProvider(tmp_path / "a.key")).put_card(user, **CARD)
    rotated = VaultService(session_factory, DevFileKeyProvider(tmp_path / "b.key"))
    with pytest.raises(VaultUnavailable, match="Store it again"):
        await rotated.open_card(user, purpose="checkout")
    # The view is still listed (masked), so Settings can offer "store again".
    assert (await rotated.get_card_view(user)).masked == "Visa ····4242"


# -- delete --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_item(session_factory, vault, capture):
    user = await _owner(session_factory)
    view = await vault.put_card(user, **CARD)
    assert await vault.delete_item(user, "not-an-id") is False
    assert await vault.delete_item(user, str(uuid.uuid4())) is False
    assert await vault.delete_item(user, view.id) is True
    assert await vault.delete_item(user, view.id) is False
    assert await vault.list_items(user) == []
    deleted = [e for e in capture if e["event"] == "vault_item_deleted"]
    assert deleted and deleted[0]["kind"] == "card" and DIGITS not in str(deleted[0])


@pytest.mark.asyncio
async def test_deleting_the_user_cascades_to_the_vault(session_factory, vault):
    from models.user import User

    user = await _owner(session_factory)
    await vault.put_card(user, **CARD)
    async with session_factory() as session:
        row = await session.get(User, uuid.UUID(user))
        await session.delete(row)
        await session.commit()
    assert await _rows(session_factory) == []
