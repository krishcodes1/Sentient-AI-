"""Reads and updates the single installation row: capability switches, default LLM
provider and keys, Telegram token, registration and setup state.

Why it exists: Routes, the runtime and main.py need one cached, locked and
audited view of owner configuration with env-over-database precedence; its
change events are what restart the Telegram poller and drop cached providers.

Owner-level configuration of this Crawler install.

One row (models.installation) holds the capability switches, the default
AI provider/model, encrypted provider keys and the encrypted Telegram bot
token. Precedence is environment > database > default: a key in .env
(Docker, CI) always wins, so nothing there changes; the wizard fills the
row for native installs where there is no .env to edit.

Secrets are encrypted at rest with core.security.encrypt_credentials and
are never logged: log lines name what failed, never the value or an
exception message that could embed it (a Telegram API URL carries the
bot token in its path). A secret that no longer decrypts (ENCRYPTION_KEY
changed or lost) reads as absent but is never silently overwritten:
restoring the key brings it back, and clear_stored_secrets() is the
explicit, audited way to discard it.

Every write takes the row with SELECT ... FOR UPDATE, appends its audit
row in the same transaction and commits both together, so a change
without its audit row (or the reverse) cannot exist. Listeners hear about
a change only after that commit.

The capability report is cached next to the snapshot, for the same TTL
and dropped by the same invalidate(): every gated tool call reads it, and
building it gathers environment facts (filesystem stats, the browser
install record) that must not be re-read per call.

Single-process assumption: the asyncio locks, the 5 s caches and
the change listeners are per process. The production image and the
native install each run one process (one uvicorn worker), so they are
authoritative there. The row lock still serialises writers at the
database on Postgres (SQLite ignores FOR UPDATE and serialises writers
anyway), but a second process would serve a stale snapshot for up to the
cache TTL and never hear this process's change events.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from core.config import LLM_PROVIDERS, PROVIDER_KEY_FIELDS, settings
from core.security import decrypt_credentials, encrypt_credentials
from models.audit import AuditStatus
from models.installation import INSTALLATION_ROW_ID, Installation
from models.user import User
from services import capabilities as registry
from services.audit import append_audit_log
from services.capabilities.base import CapabilityStatus, ReportContext

logger = structlog.get_logger(__name__)

ChangeCallback = Callable[[str], Awaitable[None]]

UNREADABLE_KEYS_MESSAGE = (
    "Stored provider keys cannot be decrypted with the current ENCRYPTION_KEY; "
    "restore the key or clear the stored keys"
)

REGISTRATION_LOCKED_MESSAGE = (
    "Registration is locked closed by ALLOW_REGISTRATION=false in the server "
    "configuration; remove it from .env to manage it here."
)


class RegistrationLocked(Exception):
    """The environment locks registration closed (ALLOW_REGISTRATION=false),
    so the stored switch cannot be changed from the app."""


@dataclass(frozen=True)
class _Snapshot:
    capabilities: dict[str, bool]
    llm_provider: Optional[str]
    llm_model: Optional[str]
    llm_api_keys: dict[str, str] = field(repr=False)
    telegram_bot_token: Optional[str] = field(repr=False)
    allow_registration: bool
    setup_completed_at: Optional[datetime]
    # A stored blob exists but does not decrypt with the current key.
    keys_unreadable: bool = False
    token_unreadable: bool = False


@dataclass(frozen=True)
class _ReportView:
    """One capability report and the two indexes the gates read, built
    together so they can never disagree."""

    statuses: tuple[CapabilityStatus, ...]
    enabled: frozenset[str]
    # Read-only: every gate caller shares this one mapping.
    by_key: Mapping[str, CapabilityStatus]


class InstallationService:
    CACHE_TTL_S = 5.0

    def __init__(self, session_factory: Callable[[], Any], *, config: Any = settings) -> None:
        self._session_factory = session_factory
        self._config = config
        self._snapshot: Optional[tuple[float, _Snapshot]] = None
        self._report_view: Optional[tuple[float, _ReportView]] = None
        # Bumped by invalidate(); a load only caches what it read if no
        # invalidate() happened while it was reading.
        self._gen = 0
        self._callbacks: list[ChangeCallback] = []
        self._lock = asyncio.Lock()
        # Single-flight for the report: gate calls arriving together when
        # the cache runs out build it once, not once each.
        self._report_lock = asyncio.Lock()
        # Fingerprints of blobs already reported as undecryptable, so a
        # lost key logs once per blob rather than on every cache refresh.
        self._warned_blobs: set[str] = set()

    # ── loading ────────────────────────────────────────────────────────

    async def _get_or_create(self, session: Any, *, for_update: bool = False) -> Installation:
        """The row migration 0008 seeds. Created here too so a database
        built from metadata (tests, adoption) works without the migration.
        Must be the first thing a session does: losing a creation race
        rolls the session back, then reads the winner's row.

        Write paths pass for_update=True so concurrent writers serialise on
        the row (Postgres); SQLite ignores FOR UPDATE."""
        row = await session.get(Installation, INSTALLATION_ROW_ID, with_for_update=for_update)
        if row is not None:
            return row
        row = Installation(id=INSTALLATION_ROW_ID, capabilities={})
        session.add(row)
        try:
            await session.flush()
        except IntegrityError:
            await session.rollback()
            row = await session.get(Installation, INSTALLATION_ROW_ID, with_for_update=for_update)
            if row is None:
                raise
        return row

    def _warn_unreadable(self, event: str, blob: bytes) -> None:
        fingerprint = hashlib.sha256(bytes(blob)).hexdigest()
        if fingerprint in self._warned_blobs:
            return
        self._warned_blobs.add(fingerprint)
        # The ciphertext's hash identifies the blob without revealing it.
        logger.warning(event, blob_sha256=fingerprint[:16])

    def _decrypt_keys(self, blob: Optional[bytes]) -> tuple[dict[str, str], bool]:
        """(keys, unreadable). An undecryptable or corrupt blob reads as no
        keys, flagged so no write path overwrites it."""
        if not blob:
            return {}, False
        try:
            data = json.loads(decrypt_credentials(blob))
            if not isinstance(data, dict):
                raise ValueError("provider keys blob is not a mapping")
        except Exception:  # wrong ENCRYPTION_KEY or corrupt blob
            self._warn_unreadable("installation_keys_undecryptable", blob)
            return {}, True
        return {str(k): str(v) for k, v in data.items()}, False

    def _decrypt_token(self, blob: Optional[bytes]) -> tuple[Optional[str], bool]:
        """(token, unreadable), as _decrypt_keys."""
        if not blob:
            return None, False
        try:
            return decrypt_credentials(blob), False
        except Exception:  # wrong ENCRYPTION_KEY or corrupt blob
            self._warn_unreadable("installation_token_undecryptable", blob)
            return None, True

    async def _read_snapshot(self) -> _Snapshot:
        async with self._session_factory() as session:
            row = await self._get_or_create(session)
            # Read before commit so a factory that expires on commit never
            # triggers a lazy (and, under asyncio, illegal) refresh.
            keys, keys_unreadable = self._decrypt_keys(row.llm_api_keys)
            token, token_unreadable = self._decrypt_token(row.telegram_bot_token)
            snap = _Snapshot(
                capabilities={str(k): bool(v) for k, v in (row.capabilities or {}).items()},
                llm_provider=row.llm_provider,
                llm_model=row.llm_model,
                llm_api_keys=keys,
                telegram_bot_token=token,
                allow_registration=bool(row.allow_registration),
                setup_completed_at=row.setup_completed_at,
                keys_unreadable=keys_unreadable,
                token_unreadable=token_unreadable,
            )
            await session.commit()
        return snap

    async def _load(self) -> _Snapshot:
        now = time.monotonic()
        cached = self._snapshot
        if cached is not None and now - cached[0] < self.CACHE_TTL_S:
            return cached[1]
        gen = self._gen
        snap = await self._read_snapshot()
        # A write committed (and invalidated) while this read was in
        # flight: what was read may predate it, so return it but do not
        # cache it over the invalidation.
        if gen == self._gen:
            self._snapshot = (now, snap)
        return snap

    def invalidate(self) -> None:
        """Drop the cached snapshot and the report built from it, so the
        next read sees the database and the environment afresh (after a
        write, an install, or an OS permission grant)."""
        self._gen += 1
        self._snapshot = None
        self._report_view = None

    def on_change(self, callback: ChangeCallback) -> None:
        self._callbacks.append(callback)

    async def _changed(self, topic: str) -> None:
        self.invalidate()
        for cb in list(self._callbacks):
            try:
                await cb(topic)
            except Exception as exc:  # a listener must never break a save
                # Type only: a listener's message can embed a secret (e.g.
                # an httpx error quoting a bot-token URL).
                logger.warning(
                    "installation_listener_failed", topic=topic, error_type=type(exc).__name__
                )

    async def _write(
        self,
        mutate: Callable[[Installation], Mapping[str, Any]],
        *,
        actor_id: uuid.UUID,
        action: str,
        endpoint: str,
    ) -> None:
        """Apply ``mutate`` to the locked row and append its audit row in
        the same transaction. ``mutate`` returns the audit request_data;
        if it or the audit append raises, nothing is committed."""
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session, for_update=True)
                request_data = dict(mutate(row))
                row.updated_by_user_id = actor_id
                await append_audit_log(
                    session,
                    user_id=actor_id,
                    connector_name="installation",
                    action=action,
                    endpoint=endpoint,
                    scope_used="admin",
                    status=AuditStatus.approved,
                    request_data=request_data,
                )
                await session.commit()
            self.invalidate()

    # ── capabilities ───────────────────────────────────────────────────

    async def capabilities(self) -> dict[str, bool]:
        stored = (await self._load()).capabilities
        known = set(registry.keys())
        return {**registry.default_switches(), **{k: v for k, v in stored.items() if k in known}}

    async def set_capabilities(
        self, patch: Mapping[str, bool], *, actor_id: uuid.UUID
    ) -> list[CapabilityStatus]:
        known = set(registry.keys())
        unknown = sorted(str(k) for k in patch if k not in known)
        if unknown:
            raise ValueError(f"Unknown capabilities: {', '.join(unknown)}")
        not_bool = sorted(k for k, v in patch.items() if not isinstance(v, bool))
        if not_bool:
            raise ValueError(f"Capability switches must be true or false: {', '.join(not_bool)}")
        changes = dict(patch)

        def mutate(row: Installation) -> Mapping[str, Any]:
            row.capabilities = {**(row.capabilities or {}), **changes}
            return {"changes": changes}

        await self._write(
            mutate, actor_id=actor_id, action="capabilities_updated", endpoint="/api/capabilities"
        )
        await self._changed("capabilities")
        return await self.report()

    async def context(self) -> ReportContext:
        configured = bool(await self.telegram_token())
        # The Telegram switch is a fact for the capabilities that deliver
        # over Telegram (page_watch): with it off no message goes out.
        switches = await self.capabilities()
        return registry.default_context(
            telegram_configured=configured,
            telegram_enabled=configured and switches.get("telegram") is True,
        )

    def _cached_view(self) -> Optional[_ReportView]:
        cached = self._report_view
        if cached is not None and time.monotonic() - cached[0] < self.CACHE_TTL_S:
            return cached[1]
        return None

    async def _view(self) -> _ReportView:
        """The capability report, built at most once per cache period.
        default_context() (filesystem stats, the browser install record)
        runs only here."""
        view = self._cached_view()
        if view is not None:
            return view
        async with self._report_lock:
            view = self._cached_view()  # built while this call waited
            if view is not None:
                return view
            now = time.monotonic()
            gen = self._gen
            statuses = tuple(registry.report(await self.capabilities(), await self.context()))
            view = _ReportView(
                statuses=statuses,
                enabled=frozenset(s.key for s in statuses if s.effective == "on"),
                by_key=MappingProxyType(registry.statuses_by_key(statuses)),
            )
            # As in _load: a report built across an invalidate() may
            # predate the change, so it is returned but not cached.
            if gen == self._gen:
                self._report_view = (now, view)
            return view

    async def report(self) -> list[CapabilityStatus]:
        return list((await self._view()).statuses)

    async def enabled_keys(self) -> frozenset[str]:
        """Keys whose effective state is ``on``."""
        return (await self._view()).enabled

    async def capability_statuses(self) -> Mapping[str, CapabilityStatus]:
        """The report indexed by key (read-only): the capability gate the
        permission adapter and the executor read, so they can tell a
        capability the owner switched off from one that is on but blocked."""
        return (await self._view()).by_key

    # ── AI provider ────────────────────────────────────────────────────

    async def llm_defaults(self) -> tuple[str, str]:
        """Owner-first: a wizard choice must not be silently undone by a
        stale .env default, so the stored provider/model win here (keys,
        by contrast, are environment-first)."""
        snap = await self._load()
        provider = (snap.llm_provider or self._config.LLM_PROVIDER or "").strip().lower()
        model = (snap.llm_model or self._config.LLM_MODEL or "").strip()
        return provider, model

    def _env_api_key(self, provider: str) -> str:
        attr = PROVIDER_KEY_FIELDS.get(provider)
        return (getattr(self._config, attr, "") or "").strip() if attr else ""

    async def llm_api_key(self, provider: str) -> Optional[str]:
        name = (provider or "").strip().lower()
        if name == "ollama":
            return ""
        env_value = self._env_api_key(name)
        if env_value:
            return env_value
        stored = (await self._load()).llm_api_keys.get(name, "").strip()
        return stored or None

    async def stored_provider_keys(self) -> set[str]:
        """Names of the providers with a key stored by the wizard (never
        the keys). A blob that does not decrypt contributes none."""
        return {name for name, key in (await self._load()).llm_api_keys.items() if key.strip()}

    async def provider_configured(self) -> bool:
        provider, _model = await self.llm_defaults()
        return bool(provider) and (await self.llm_api_key(provider)) is not None

    async def set_llm(
        self, provider: str, model: str, api_key: Optional[str], *, actor_id: uuid.UUID
    ) -> None:
        name = (provider or "").strip().lower()
        if name not in LLM_PROVIDERS:
            # Never echo the input: a key pasted into the wrong field
            # would land in the HTTP response and the client's logs.
            raise ValueError("Unknown provider")
        model = (model or "").strip()
        if not model:
            raise ValueError("A model is required")
        api_key = (api_key or "").strip() or None

        def mutate(row: Installation) -> Mapping[str, Any]:
            keys, unreadable = self._decrypt_keys(row.llm_api_keys)
            if unreadable:
                # Re-encrypting would replace every stored provider key
                # with just this one; the owner must decide explicitly.
                raise RuntimeError(UNREADABLE_KEYS_MESSAGE)
            if api_key is not None:
                keys[name] = api_key
                row.llm_api_keys = encrypt_credentials(json.dumps(keys))
            row.llm_provider = name
            row.llm_model = model
            return {"provider": name, "model": model, "key_stored": api_key is not None}

        await self._write(
            mutate, actor_id=actor_id, action="provider_updated", endpoint="/api/setup/provider"
        )
        await self._changed("llm")

    # ── Telegram ───────────────────────────────────────────────────────

    async def telegram_token(self) -> Optional[str]:
        env_value = (getattr(self._config, "TELEGRAM_BOT_TOKEN", "") or "").strip()
        if env_value:
            return env_value
        return (await self._load()).telegram_bot_token or None

    async def set_telegram_token(self, token: Optional[str], *, actor_id: uuid.UUID) -> None:
        token = (token or "").strip() or None

        def mutate(row: Installation) -> Mapping[str, Any]:
            row.telegram_bot_token = encrypt_credentials(token) if token is not None else None
            return {"configured": token is not None}

        await self._write(
            mutate, actor_id=actor_id, action="telegram_updated", endpoint="/api/setup/telegram"
        )
        await self._changed("telegram")

    # ── secrets ────────────────────────────────────────────────────────

    async def secrets_unreadable(self) -> bool:
        """True while a stored provider-key or bot-token blob exists that
        the current ENCRYPTION_KEY cannot decrypt."""
        snap = await self._load()
        return snap.keys_unreadable or snap.token_unreadable

    async def clear_stored_secrets(self, actor_id: uuid.UUID) -> None:
        """Discard every stored provider key and the stored bot token. The
        explicit escape hatch when they no longer decrypt; environment
        values are untouched."""
        cleared: dict[str, bool] = {}

        def mutate(row: Installation) -> Mapping[str, Any]:
            cleared["llm"] = bool(row.llm_api_keys)
            cleared["telegram"] = bool(row.telegram_bot_token)
            row.llm_api_keys = None
            row.telegram_bot_token = None
            return {
                "provider_keys_cleared": cleared["llm"],
                "telegram_cleared": cleared["telegram"],
            }

        await self._write(
            mutate,
            actor_id=actor_id,
            action="installation_secrets_cleared",
            endpoint="/api/setup/secrets",
        )
        if cleared["llm"]:
            await self._changed("llm")
        if cleared["telegram"]:
            await self._changed("telegram")

    # ── setup state ────────────────────────────────────────────────────

    async def has_users(self) -> bool:
        async with self._session_factory() as session:
            return (await session.execute(select(func.count()).select_from(User))).scalar_one() > 0

    async def setup_completed(self) -> bool:
        return (await self._load()).setup_completed_at is not None

    async def needs_setup(self) -> bool:
        """No account yet, or the wizard is unfinished."""
        return not await self.has_users() or not await self.setup_completed()

    # ── registration ───────────────────────────────────────────────────
    #
    # One rule, in order: an explicit ALLOW_REGISTRATION=false in the
    # environment or .env locks registration closed; otherwise, once setup
    # is complete, the owner's stored switch decides; before that it is
    # closed (with no users too: the first account comes from /setup/owner
    # only). An explicit true opens nothing by itself — it only seeds the
    # switch when stamp_setup_if_legacy() carries an upgraded install past
    # the wizard.

    def _registration_env_explicit(self) -> bool:
        """Whether ALLOW_REGISTRATION came from the environment or .env
        rather than the field default. pydantic-settings records every
        value it read from either in model_fields_set. A stand-in config
        without that record counts as explicit when it has the attribute,
        so a lock is never read as open."""
        fields_set = getattr(self._config, "model_fields_set", None)
        if fields_set is None:
            return hasattr(self._config, "ALLOW_REGISTRATION")
        return "ALLOW_REGISTRATION" in fields_set

    def registration_env_locked(self) -> bool:
        """True when ALLOW_REGISTRATION=false is set explicitly: registration
        is closed whatever the stored switch says, and the switch cannot be
        changed from the app."""
        return self._registration_env_explicit() and not bool(
            getattr(self._config, "ALLOW_REGISTRATION", True)
        )

    async def registration_allowed(self) -> bool:
        """Whether /auth/register may create an account now (see the rule
        above)."""
        if self.registration_env_locked():
            return False
        snap = await self._load()
        return snap.setup_completed_at is not None and snap.allow_registration

    async def set_registration(self, allow: bool, *, actor_id: uuid.UUID) -> None:
        """Store the owner's open-registration switch (Settings). Refused
        with RegistrationLocked while the environment locks it: the stored
        value would do nothing until someone removed the lock, and then it
        would silently open sign-up."""
        if not isinstance(allow, bool):
            raise ValueError("allow_registration must be true or false")
        if self.registration_env_locked():
            raise RegistrationLocked(REGISTRATION_LOCKED_MESSAGE)

        def mutate(row: Installation) -> Mapping[str, Any]:
            row.allow_registration = allow
            return {"allow_registration": allow}

        await self._write(
            mutate,
            actor_id=actor_id,
            action="registration_updated",
            endpoint="/api/setup/registration",
        )
        await self._changed("registration")

    async def mark_setup_complete(self, *, allow_registration: bool, actor_id: uuid.UUID) -> None:
        """Stamp setup complete and store the registration switch. Under
        the environment lock the switch is stored closed, whatever was
        asked: completing setup must not fail on it, and an open switch
        must not be waiting for the day the lock is removed."""
        allow = bool(allow_registration) and not self.registration_env_locked()

        def mutate(row: Installation) -> Mapping[str, Any]:
            row.setup_completed_at = datetime.now(timezone.utc)
            row.allow_registration = allow
            return {"allow_registration": allow}

        await self._write(
            mutate, actor_id=actor_id, action="setup_completed", endpoint="/api/setup/complete"
        )
        await self._changed("setup")

    def _env_supplies_provider_key(self) -> bool:
        provider = (self._config.LLM_PROVIDER or "").strip().lower()
        return provider == "ollama" or bool(self._env_api_key(provider))

    async def stamp_setup_if_legacy(self) -> bool:
        """An install that predates the wizard (users exist, provider key
        in .env) must not be forced through it after an upgrade.

        Only an environment-configured install qualifies: once the wizard
        has stored a provider, the owner is mid-wizard (or done) and a
        restart must resume it rather than skip past it.

        The stamp also seeds the registration switch, which governs from
        then on: open only when the environment explicitly says
        ALLOW_REGISTRATION=true. Unset (or false) seeds it closed, so an
        upgrade never leaves an install open by accident; the owner can
        open it later in Settings."""
        if not self._env_supplies_provider_key() or not await self.has_users():
            return False
        allow = self._registration_env_explicit() and bool(
            getattr(self._config, "ALLOW_REGISTRATION", False)
        )
        stamped = False
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session, for_update=True)
                if row.setup_completed_at is None and row.llm_provider is None:
                    row.setup_completed_at = datetime.now(timezone.utc)
                    row.allow_registration = allow
                    await session.commit()
                    stamped = True
            self.invalidate()
        if stamped:
            logger.info("installation_setup_stamped_legacy")
        return stamped
