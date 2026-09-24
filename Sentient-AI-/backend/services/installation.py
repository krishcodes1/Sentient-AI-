"""Owner-level configuration of this Crawler install.

One row (models.installation) holds the capability switches, the default
AI provider/model, encrypted provider keys and the encrypted Telegram bot
token. Precedence is environment > database > default: a key in .env
(Docker, CI) always wins, so nothing there changes; the wizard fills the
row for native installs where there is no .env to edit.

Secrets are encrypted at rest with core.security.encrypt_credentials and
are never logged: log lines name what failed, never the value or an
exception message that could embed it (a Telegram API URL carries the
bot token in its path).
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from core.config import PROVIDER_KEY_FIELDS, settings
from core.security import decrypt_credentials, encrypt_credentials
from models.audit import AuditStatus
from models.installation import INSTALLATION_ROW_ID, Installation
from models.user import User
from services import capabilities as registry
from services.audit import append_audit_log
from services.capabilities.base import CapabilityStatus, ReportContext

logger = structlog.get_logger(__name__)

ChangeCallback = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class _Snapshot:
    capabilities: dict[str, bool]
    llm_provider: Optional[str]
    llm_model: Optional[str]
    llm_api_keys: dict[str, str]
    telegram_bot_token: Optional[str]
    allow_registration: bool
    setup_completed_at: Optional[datetime]


class InstallationService:
    CACHE_TTL_S = 5.0

    def __init__(self, session_factory: Callable[[], Any], *, config: Any = settings) -> None:
        self._session_factory = session_factory
        self._config = config
        self._snapshot: Optional[tuple[float, _Snapshot]] = None
        self._callbacks: list[ChangeCallback] = []
        self._lock = asyncio.Lock()

    # ── loading ────────────────────────────────────────────────────────

    async def _get_or_create(self, session: Any) -> Installation:
        """The row migration 0008 seeds. Created here too so a database
        built from metadata (tests, adoption) works without the migration.
        Must be the first thing a session does: losing a creation race
        rolls the session back, then reads the winner's row."""
        row = await session.get(Installation, INSTALLATION_ROW_ID)
        if row is not None:
            return row
        row = Installation(id=INSTALLATION_ROW_ID, capabilities={})
        session.add(row)
        try:
            await session.flush()
        except IntegrityError:
            await session.rollback()
            row = await session.get(Installation, INSTALLATION_ROW_ID)
            if row is None:
                raise
        return row

    @staticmethod
    def _decrypt_keys(blob: Optional[bytes]) -> dict[str, str]:
        if not blob:
            return {}
        try:
            data = json.loads(decrypt_credentials(blob))
        except Exception:  # wrong ENCRYPTION_KEY or corrupt blob: treat as absent
            logger.warning("installation_keys_undecryptable")
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    @staticmethod
    def _decrypt_token(blob: Optional[bytes]) -> Optional[str]:
        if not blob:
            return None
        try:
            return decrypt_credentials(blob)
        except Exception:  # wrong ENCRYPTION_KEY or corrupt blob: treat as absent
            logger.warning("installation_token_undecryptable")
            return None

    async def _load(self) -> _Snapshot:
        now = time.monotonic()
        if self._snapshot is not None and now - self._snapshot[0] < self.CACHE_TTL_S:
            return self._snapshot[1]
        async with self._session_factory() as session:
            row = await self._get_or_create(session)
            # Read before commit so a factory that expires on commit never
            # triggers a lazy (and, under asyncio, illegal) refresh.
            snap = _Snapshot(
                capabilities={str(k): bool(v) for k, v in (row.capabilities or {}).items()},
                llm_provider=row.llm_provider,
                llm_model=row.llm_model,
                llm_api_keys=self._decrypt_keys(row.llm_api_keys),
                telegram_bot_token=self._decrypt_token(row.telegram_bot_token),
                allow_registration=bool(row.allow_registration),
                setup_completed_at=row.setup_completed_at,
            )
            await session.commit()
        self._snapshot = (now, snap)
        return snap

    def invalidate(self) -> None:
        self._snapshot = None

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

    async def _audit(self, actor_id: Any, action: str, endpoint: str, data: dict[str, Any]) -> None:
        async with self._session_factory() as session:
            await append_audit_log(
                session,
                user_id=actor_id,
                connector_name="installation",
                action=action,
                endpoint=endpoint,
                scope_used="admin",
                status=AuditStatus.approved,
                request_data=data,
            )
            await session.commit()

    # ── capabilities ───────────────────────────────────────────────────

    async def capabilities(self) -> dict[str, bool]:
        stored = (await self._load()).capabilities
        known = set(registry.keys())
        return {**registry.default_switches(), **{k: v for k, v in stored.items() if k in known}}

    async def set_capabilities(
        self, patch: Mapping[str, bool], *, actor_id: Any
    ) -> list[CapabilityStatus]:
        unknown = sorted(set(patch) - set(registry.keys()))
        if unknown:
            raise ValueError(f"Unknown capabilities: {', '.join(unknown)}")
        changes = {k: bool(v) for k, v in patch.items()}
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                row.capabilities = {**(row.capabilities or {}), **changes}
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(actor_id, "capabilities_updated", "/api/capabilities", {"changes": changes})
        await self._changed("capabilities")
        return await self.report()

    async def context(self) -> ReportContext:
        return registry.default_context(telegram_configured=bool(await self.telegram_token()))

    async def report(self) -> list[CapabilityStatus]:
        return registry.report(await self.capabilities(), await self.context())

    async def enabled_keys(self) -> frozenset[str]:
        return registry.enabled_keys(await self.capabilities(), await self.context())

    # ── AI provider ────────────────────────────────────────────────────

    async def llm_defaults(self) -> tuple[str, str]:
        """Owner-first: a wizard choice must not be silently undone by a
        stale .env default, so the stored provider/model win here (keys,
        by contrast, are environment-first)."""
        snap = await self._load()
        provider = (snap.llm_provider or self._config.LLM_PROVIDER or "").strip().lower()
        model = (snap.llm_model or self._config.LLM_MODEL or "").strip()
        return provider, model

    async def llm_api_key(self, provider: str) -> Optional[str]:
        name = (provider or "").strip().lower()
        if name == "ollama":
            return ""
        attr = PROVIDER_KEY_FIELDS.get(name)
        env_value = (getattr(self._config, attr, "") or "").strip() if attr else ""
        if env_value:
            return env_value
        stored = (await self._load()).llm_api_keys.get(name, "").strip()
        return stored or None

    async def stored_provider_keys(self) -> set[str]:
        """Providers with a key saved through the wizard: names only, never
        the values, so a caller cannot leak what it was never handed."""
        return {name for name, key in (await self._load()).llm_api_keys.items() if key.strip()}

    async def provider_configured(self) -> bool:
        provider, _model = await self.llm_defaults()
        return bool(provider) and (await self.llm_api_key(provider)) is not None

    async def set_llm(
        self, provider: str, model: str, api_key: Optional[str], *, actor_id: Any
    ) -> None:
        name = (provider or "").strip().lower()
        if name not in PROVIDER_KEY_FIELDS and name != "ollama":
            raise ValueError(f"Unknown provider '{provider}'")
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                keys = self._decrypt_keys(row.llm_api_keys)
                if api_key:
                    keys[name] = api_key.strip()
                row.llm_api_keys = encrypt_credentials(json.dumps(keys)) if keys else None
                row.llm_provider = name
                row.llm_model = model.strip()
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(
            actor_id,
            "provider_updated",
            "/api/setup/provider",
            {"provider": name, "model": model, "key_stored": bool(api_key)},
        )
        await self._changed("llm")

    # ── Telegram ───────────────────────────────────────────────────────

    async def telegram_token(self) -> Optional[str]:
        env_value = (getattr(self._config, "TELEGRAM_BOT_TOKEN", "") or "").strip()
        if env_value:
            return env_value
        return (await self._load()).telegram_bot_token or None

    async def set_telegram_token(self, token: Optional[str], *, actor_id: Any) -> None:
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                row.telegram_bot_token = encrypt_credentials(token.strip()) if token else None
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(
            actor_id, "telegram_updated", "/api/setup/telegram", {"configured": bool(token)}
        )
        await self._changed("telegram")

    # ── setup state ────────────────────────────────────────────────────

    async def has_users(self) -> bool:
        async with self._session_factory() as session:
            return (await session.execute(select(func.count()).select_from(User))).scalar_one() > 0

    async def setup_completed(self) -> bool:
        return (await self._load()).setup_completed_at is not None

    async def needs_setup(self) -> bool:
        return not await self.has_users() or not await self.setup_completed()

    async def registration_allowed(self) -> bool:
        """Before setup completes the environment decides (so the owner can
        register); after, the owner's stored switch does."""
        snap = await self._load()
        if snap.setup_completed_at is None:
            return bool(self._config.ALLOW_REGISTRATION)
        return snap.allow_registration

    async def mark_setup_complete(self, *, allow_registration: bool, actor_id: Any) -> None:
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                row.setup_completed_at = datetime.now(timezone.utc)
                row.allow_registration = bool(allow_registration)
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(
            actor_id,
            "setup_completed",
            "/api/setup/complete",
            {"allow_registration": bool(allow_registration)},
        )
        await self._changed("setup")

    async def stamp_setup_if_legacy(self) -> bool:
        """An install that predates the wizard (users exist, key in .env)
        must not be forced through it after an upgrade.

        The stamp also carries today's ALLOW_REGISTRATION into the row:
        once setup is complete the stored switch governs, and the column
        default (closed) would otherwise silently change an upgraded
        deployment's behaviour."""
        if await self.setup_completed() or not await self.has_users():
            return False
        if not await self.provider_configured():
            return False
        stamped = False
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                if row.setup_completed_at is None:  # not stamped while we checked
                    row.setup_completed_at = datetime.now(timezone.utc)
                    row.allow_registration = bool(self._config.ALLOW_REGISTRATION)
                    await session.commit()
                    stamped = True
        self.invalidate()
        if stamped:
            logger.info("installation_setup_stamped_legacy")
        return stamped
