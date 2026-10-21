"""Builds the FastAPI application: configures logging, migrates the database,
wires the runtime services onto ``app.state``, installs the middleware stack
in its required order, mounts every router under /api and defines the health
and error handlers.

Why it exists: This is the process entry point uvicorn and the tests load;
keeping the wiring in ``wire_services`` and the middleware order in one file
lets tests build an app against their own session factory and keeps the rate
limiter from serving responses without security headers or a request id.

Crawler AI — Secure-by-Design Agentic AI Platform.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any, Callable, Optional
from collections.abc import Awaitable, Coroutine

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.trustedhost import TrustedHostMiddleware

from core.config import settings
from core.database import async_session, engine, get_db, init_db
from core.http_pinning import warm_ssl_context
from core.logging_config import configure_logging

configure_logging()
from api.middleware.security import (
    RateLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from api.routes import (
    agent,
    app_approvals,
    audit,
    auth,
    capabilities,
    connectors,
    memory,
    oauth,
    reminders,
    setup,
    slack,
    telegram,
    usage,
    vault,
)
from services.agent import cancel as agent_cancel
from services.agent.app_approvals import DEVICE_HEADER, DbAppApprovalStore
from services.agent.approvals import DbApprovalStore
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
)
from services.audit import RuntimeAuditLogger
from services.connectors.oauth import shutdown_background_tasks as stop_oauth_tasks
from services.installation import InstallationService
from services.mcp.integration import MCPConnectorLoader, MCPToolCatalog
from services.notifications.page_watch import PageWatchService
from services.notifications.reminders import ReminderService
from services.notifications.slack import SlackChannel
from services.notifications.slack_manager import SlackManager
from services.notifications.telegram import NotifyingApprovalStore, TelegramService
from services.notifications.telegram_manager import TelegramManager
from services.notifications.voice import voice_notes_for  # top10:voice_notes
from services.tools.system import SystemToolkit
from services.platform import current as current_platform
from services.tools.browser import guard as browser_guard
from services.tools.browser import handoff as browser_handoff
from services.tools.browser.guard import EgressHooks
from services.tools.browser.act import BrowserActToolkit
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.checkout.ledger import PurchaseLedger
from services.tools.browser.checkout.toolkit import BrowserCheckoutToolkit
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.session import BrowserSessionManager
from services.tools.computer import ComputerToolkit
from services.tools.computer import backend as computer_backend
from services.tools.knowledge import KnowledgeToolkit
from services.tools.net import validated_addresses
from services.tools.watch import PageSnapshot, WatchToolkit, fetch_snapshot
from services.tools.web import WebToolkit
from services.vault.keys import select_key_provider
from services.vault.service import VaultService

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(
        "starting_crawler_ai",
        environment=settings.ENVIRONMENT,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.LLM_MODEL,
    )
    for warning in settings.production_warnings():
        logger.warning("production_config_warning", detail=warning)
    try:
        await init_db()
        logger.info("database_initialized")
    except Exception as exc:
        logger.error("database_init_failed", error=str(exc))
        if settings.ENVIRONMENT == "production":
            # Fail fast: a DB-less API 500s on every real request while
            # passing a naive healthcheck. Exiting lets the container
            # restart-loop until the database is reachable.
            raise
        logger.warning("app_starting_without_database")

    # Load the CA bundle once, off the event loop, before any outbound call.
    await warm_ssl_context()
    await wire_services(app)
    await start_slack_channels(app)
    start_browser_reaper(app)
    reminder_service: ReminderService = app.state.reminders
    await reminder_service.start()
    page_watch_service: PageWatchService = app.state.page_watches
    await page_watch_service.start()

    # top10:secret_pii_redaction

    # top10:file_extraction
    # Uploads whose 30 days since their last read have passed are purged
    # once at startup (and lazily per user on every upload, list and read).
    try:
        await app.state.file_intake.store.purge_expired()
    except Exception as exc:  # a purge must never keep the API down
        logger.warning("user_files_purge_failed", error_type=type(exc).__name__)

    # top10:scheduler_briefing
    await app.state.schedules.start()

    # top10:tutor_mode

    # top10:knowledge_base
    # The meaning-index sweeper; it sends nothing while its switch is off.
    await app.state.knowledge_embedder.start()

    # top10:flashcards_quizzes

    # top10:event_triggers
    await app.state.triggers.start()

    # top10:permission_tiers

    # top10:voice_notes

    # top10:video_transcripts
    await app.state.transcript_janitor.start()

    # Security wave (security10): the background security sweepers. Each
    # re-reads its owner switch before every pass and sends nothing while it
    # is off (each is inert until its skill lands).
    await app.state.mail_scan.start()
    await app.state.breach_monitor.start()
    await app.state.file_reputation_sweeper.start()

    yield
    logger.info("shutting_down_crawler_ai")
    await reminder_service.stop()
    await page_watch_service.stop()
    # top10:video_transcripts
    await app.state.transcript_janitor.stop()

    # top10:voice_notes

    # top10:permission_tiers

    # top10:event_triggers
    await app.state.triggers.stop()

    # top10:flashcards_quizzes

    # top10:knowledge_base
    await app.state.knowledge_embedder.stop()

    # top10:tutor_mode

    # top10:scheduler_briefing
    await app.state.schedules.stop()

    # top10:file_extraction

    # top10:secret_pii_redaction

    # Security wave (security10): the security sweepers, in reverse order of
    # their start, before the channels they send through stop.
    await app.state.file_reputation_sweeper.stop()
    await app.state.breach_monitor.stop()
    await app.state.mail_scan.stop()
    # Site-rule hit rows (site_rule_blocked from a navigation, site_rule_noted)
    # are written by background tasks; let the last few land before the
    # engine goes away. Bounded, and never in the way of the rest of shutdown.
    site_rules = getattr(app.state, "site_rules", None)
    if site_rules is not None:
        try:
            await asyncio.wait_for(site_rules.drain(), timeout=5.0)
        except Exception as exc:  # shutdown must finish regardless
            logger.warning("site_rules_drain_failed", error_type=type(exc).__name__)

    await app.state.telegram_manager.stop()
    await app.state.slack_manager.stop()
    # Release every provider's HTTP client (cached, and retired but still
    # leased by a turn being torn down) before the loop goes away.
    runtime = getattr(app.state, "agent_runtime", None)
    if runtime is not None:
        try:
            await runtime.aclose()
        except Exception as exc:  # shutdown must finish regardless
            logger.warning("agent_runtime_close_failed", error=str(exc))
    await close_browser_sessions(app)
    # Device-flow pollers and revoke tasks use the engine; stop them first.
    await stop_oauth_tasks()
    await engine.dispose()


def _wire_telegram(
    app: FastAPI,
    service: TelegramService,
    session_factory: Callable[[], Any] = async_session,
) -> None:
    """Point a poller at the agent pipelines. The manager calls this on
    every (re)start, so a bot token saved while the server runs gets the
    same approval and chat wiring as one present at boot. Both pipelines
    open sessions from the factory wire_services was given. The purchase
    card's picture comes from the executor (the checkout toolkit keeps it
    in memory), so the photo card works only in the process that made it."""
    service.decide = agent.build_decision_applier(app, session_factory)
    service.chat = agent.build_chat_applier(app, session_factory)
    # /tutor on|off|status (services/tutor): no model call, outside the turn lock.
    service.tutor = agent.build_tutor_applier(app, session_factory, channel="telegram")
    # top10:voice_notes: voice notes go through the process's one
    # VoiceNoteService (made on first use; wire_services makes it before the
    # poller first starts, at its very end).
    service.voice = voice_notes_for(app, session_factory)
    # Security wave (S3): /scam goes through the process's one
    # ScamCheckService (None until the skill lands: no interceptor runs).
    from services.scam_check.service import scam_check_for

    service.scam_check = scam_check_for(app, session_factory)
    executor = getattr(app.state, "tool_executor", None)
    if executor is not None:
        service.approval_image = lambda action: executor.approval_image(
            action.tool_name, action.arguments or {}, action.user_id
        )


@dataclass(frozen=True)
class BrowserToolkits:
    """The three browser toolkits one process runs, sharing a session
    manager and a page memory: read (browser.read), act (browser.act) and
    checkout (browser.checkout)."""

    read: BrowserReadToolkit
    act: BrowserActToolkit
    checkout: BrowserCheckoutToolkit
    # Security wave (S7): the shared page memory, so the site-rules call
    # check can read the origin of the page a user's last read observed.
    memory: PageMemory


def build_browser_toolkits(
    sessions: Any,
    *,
    session_factory: Callable[[], Any],
    vault: VaultService,
    settings_source: Any,
    cancel_flag: Callable[[str], bool],
    egress_hooks: Optional[EgressHooks] = None,
) -> BrowserToolkits:
    """Build the browser toolkits for this process. One PageMemory is shared
    by all three (the read toolkit's _observe remembers every page), so an
    act or a checkout is checked against the page the last read observed.
    checkout pays with the card in *vault* under the caps *settings_source*
    answers (purchases spec §6); in a container the vault is disabled and
    the toolkit refuses before any card. *egress_hooks* (security wave: the
    owner's site rules and the link lookup) are attached to every context
    each toolkit guards; without them the guard behaves exactly as before."""
    memory = PageMemory()
    read = BrowserReadToolkit(
        sessions,
        guard=browser_guard,
        handoff=browser_handoff,
        page_memory=memory,
        egress_hooks=egress_hooks,
    )
    act = BrowserActToolkit(
        sessions,
        guard=browser_guard,
        handoff=browser_handoff,
        memory=memory,
        cancel_flag=cancel_flag,
        egress_hooks=egress_hooks,
    )
    checkout = BrowserCheckoutToolkit(
        sessions,
        guard=browser_guard,
        handoff=browser_handoff,
        memory=memory,
        vault=vault,
        ledger=PurchaseLedger(session_factory),
        settings=settings_source,
        cancel_flag=cancel_flag,
        egress_hooks=egress_hooks,
    )
    return BrowserToolkits(read=read, act=act, checkout=checkout, memory=memory)


REAP_INTERVAL_S = 60.0


def browser_spend_sink(sessions: Any) -> Callable[[str, str, float], Any]:
    """Adds a turn's estimated cost to the task the browser toolkit caps.

    Only on the session that is already open for that task: recording a
    cost must never launch a browser (sessions.get would, after a failed
    launch, a reap or a refused action) nor reset another task's caps."""

    async def add(user_id: str, task_id: str, usd: float) -> None:
        session = sessions.sessions.get(user_id)
        if session is None or session.task.task_id != task_id:
            return
        session.task.spend_usd += usd

    return add


def start_browser_reaper(app: Any) -> None:
    """Close idle browser sessions every REAP_INTERVAL_S (spec §4); never
    one parked on an approval or handoff (the manager skips those)."""

    async def loop() -> None:
        while True:
            await asyncio.sleep(REAP_INTERVAL_S)
            try:
                await app.state.browser_sessions.reap_idle()
            except Exception as exc:  # the reaper must outlive one bad sweep
                logger.warning("browser_reap_failed", error_type=type(exc).__name__)

    app.state.browser_reaper = asyncio.create_task(loop())


async def close_browser_sessions(app: Any) -> None:
    """Stop the reaper and close every browser the agent opened. Shutdown
    must finish regardless: a browser that will not quit is logged, not raised."""
    reaper = getattr(app.state, "browser_reaper", None)
    if reaper is not None and not reaper.done():
        reaper.cancel()
        # cancel() only asks; wait until the loop has actually stopped so
        # no sweep races close_all below. wait() never raises the task's
        # CancelledError into shutdown.
        await asyncio.wait({reaper})
    sessions = getattr(app.state, "browser_sessions", None)
    if sessions is None:
        return
    try:
        await sessions.close_all()
    except Exception as exc:
        logger.warning("browser_sessions_close_failed", error_type=type(exc).__name__)


def _wire_slack(
    app: FastAPI,
    channel: SlackChannel,
    session_factory: Callable[[], Any] = async_session,
) -> None:
    """Point a Slack DM channel at the agent pipelines, as _wire_telegram
    does for the poller. The manager calls this for every channel it starts;
    turns write into the user's "Slack" conversation."""
    channel.decide = agent.build_decision_applier(app, session_factory)
    channel.chat = agent.build_chat_applier(app, session_factory, channel="slack")
    # "tutor on|off|status" in the DM (services/tutor).
    channel.tutor = agent.build_tutor_applier(app, session_factory, channel="slack")
    # Security wave (S3): the "scam" keyword and file shares go through the
    # process's one ScamCheckService (None until the skill lands).
    from services.scam_check.service import scam_check_for

    channel.scam_check = scam_check_for(app, session_factory)


def fan_out_notify(
    channels: dict[str, Callable[[Any], Awaitable[Any]]],
) -> Callable[[Any], Coroutine[Any, Any, None]]:
    """One approval notifier over every chat channel. The channels run side
    by side and each one's failure is logged and contained, so Telegram
    being down never costs the Slack card and the reverse. The approval
    itself never waits on this (NotifyingApprovalStore fires it as a task)."""

    async def one(name: str, notify: Callable[[Any], Awaitable[Any]], action: Any) -> None:
        try:
            await notify(action)
        except Exception as exc:
            logger.warning("approval_notify_failed", channel=name, error_type=type(exc).__name__)

    async def notify_all(action: Any) -> None:
        await asyncio.gather(*(one(name, fn, action) for name, fn in channels.items()))

    return notify_all


def fan_out_send(
    channels: dict[str, Callable[[str, str], Awaitable[Any]]],
) -> Callable[[str, str], Coroutine[Any, Any, bool]]:
    """One reminder sender over every chat channel: True when at least one
    channel delivered (a channel that raises counts as not delivered)."""

    async def one(name: str, send: Callable[[str, str], Awaitable[Any]], user_id: str, text: str) -> bool:
        try:
            return (await send(user_id, text)) is True
        except Exception as exc:
            logger.warning("reminder_send_failed", channel=name, error_type=type(exc).__name__)
            return False

    async def send_all(user_id: str, text: str) -> bool:
        results = await asyncio.gather(
            *(one(name, fn, user_id, text) for name, fn in channels.items())
        )
        return any(results)

    return send_all


async def start_slack_channels(app: Any) -> None:
    """Start the Slack DM channels the database asks for (lifespan). A Slack
    outage or a bad token never keeps the API down: channels retry on their
    own, and a failure here is logged by type only."""
    try:
        await app.state.slack_manager.reconcile()
    except Exception as exc:
        logger.warning("slack_start_failed", error_type=type(exc).__name__)


async def wire_services(
    app: FastAPI,
    session_factory: Callable[[], Any] = async_session,
    *,
    telegram_service_factory: Callable[..., TelegramService] = TelegramService,
    slack_manager_factory: Callable[..., SlackManager] = SlackManager,
) -> None:
    """Build the owner-configurable services and hang them on app.state.

    Everything the owner can change at runtime (capability switches, AI
    provider and key, Telegram token) lives in the InstallationService,
    and every consumer reads it through a seam that picks changes up
    without a restart: the tool gates and the <permissions> block ask it
    per turn, the runtime resolves its provider from it per turn (and
    drops cached providers on an "llm" change), and the TelegramManager is
    re-applied on a "telegram" or "capabilities" change. The approval
    store and the reminder sweeper are wired to the manager once; its
    proxies are no-ops while no poller runs.

    Split out of the lifespan so tests can wire an app against their own
    database and a fake Telegram service. Does not start the reminder or
    page-watch sweepers or the Slack DM channels (the lifespan does); a
    Slack connector or capability change reconciles the Slack manager.
    """
    installation = InstallationService(session_factory)
    app.state.installation = installation
    try:
        # An install that predates the setup wizard must not be pushed
        # through it after an upgrade.
        await installation.stamp_setup_if_legacy()
    except Exception as exc:
        # Only reachable in development without a database (production
        # already failed fast above); every request would fail anyway.
        logger.warning("installation_stamp_failed", error_type=type(exc).__name__)

    telegram_manager = TelegramManager(
        session_factory,
        on_start=lambda service: _wire_telegram(app, service, session_factory),
        service_factory=telegram_service_factory,
    )
    app.state.telegram_manager = telegram_manager

    async def _slack_enabled() -> bool:
        return (await installation.capabilities()).get("slack", False) is True

    slack_manager = slack_manager_factory(
        session_factory,
        on_start=lambda channel: _wire_slack(app, channel, session_factory),
        enabled=_slack_enabled,
        on_change=installation.invalidate,
    )
    app.state.slack_manager = slack_manager
    installation.set_slack_status(lambda: slack_manager.is_running)

    # Pending actions are pushed to each user's linked Telegram chat and
    # Slack DM while those channels run, and an Approve/Deny press flows
    # through the same decision pipeline as the web UI.
    approval_store = NotifyingApprovalStore(
        DbApprovalStore(session_factory=session_factory),
        notify=fan_out_notify(
            {"telegram": telegram_manager.notify_pending, "slack": slack_manager.notify_pending}
        ),
    )
    # Security wave (S2, S10): background services and routes that park or
    # read cards out of a turn reach the same store the runtime uses.
    app.state.approval_store = approval_store

    # One installer for the whole process: the agent's approved
    # system.install_capability and the owner's Install button on the
    # Permissions page share this instance, and with it the lock that keeps
    # two installs of the same component from racing two pip processes.
    system_toolkit = SystemToolkit(report_source=installation.report)
    app.state.system_toolkit = system_toolkit

    # Security wave (security10): core services the browser toolkits, the
    # executor and the call checks below are built with, each inert until
    # its skill lands. One owner sender over Telegram and Slack, as the
    # reminders use (security skills alert through it; it never raises).
    # The link lookups (S4): local checks always, Google only with the
    # owner's key. The owner's site rules (S7), read per navigation from an
    # in-memory snapshot; a switch that cannot be read counts as on, so the
    # rules fail closed. The browser guard gets both as per-context hooks
    # (no module-level state). The MCP tool pins (S5), off until their
    # switch is on, so MCP behaves as before.
    from services.mcp.pin_store import McpPinService
    from services.reputation.links import LinkReputation, owner_alert
    from services.site_rules.service import SiteRulesService

    app.state.owner_send = fan_out_send(
        {"telegram": telegram_manager.send_text, "slack": slack_manager.send_text}
    )
    link_reputation = LinkReputation(
        installation,
        owner_alert=owner_alert(
            session_factory,
            app.state.owner_send,
            RuntimeAuditLogger(session_factory=session_factory).log,
        ),
    )
    app.state.link_reputation = link_reputation

    async def _site_rules_enabled() -> bool:
        try:
            return "browser_site_rules" in await installation.enabled_keys()
        except Exception as exc:
            logger.warning("site_rules_switch_unreadable", error_type=type(exc).__name__)
            return True

    site_rules = SiteRulesService(session_factory, enabled=_site_rules_enabled)
    app.state.site_rules = site_rules
    installation.on_change(site_rules.on_installation_change)
    egress_hooks = EgressHooks(
        site_rules=site_rules.guard_hook_for,
        reputation=lambda _user_id: link_reputation.navigation_check,
    )

    async def _mcp_pinning_enabled() -> bool:
        return "mcp_pinning" in await installation.enabled_keys()

    mcp_pins = McpPinService(
        session_factory,
        enabled=_mcp_pinning_enabled,
        notify=app.state.owner_send,
        audit=RuntimeAuditLogger(session_factory=session_factory).log,
    )
    app.state.mcp_pins = mcp_pins

    # All security-relevant services own short-lived sessions via the
    # application session factory: the executor decrypts credentials and
    # dispatches real connectors, the audit logger writes hash-chained
    # rows, and the approval store persists pending actions across
    # restarts and workers. The capability gate (the owner's report by
    # key) is enforced at both the permission seam (blocked before
    # anything runs, audited as capability_off / capability_blocked) and
    # the executor (the backstop).
    #
    # No fallback: the runtime needs no provider key at boot (a turn
    # without one answers "not configured"), so a construction error is a
    # genuine bug and must fail startup rather than leave /api/health
    # reporting healthy with no agent behind it.
    #
    # One browser per process, launched on the first browser.read: the
    # installed Chrome/Edge with a window on a Mac or PC (the window is the
    # handoff surface), headless Chromium in the container. Sessions are
    # per process, so this holds only with a single uvicorn worker.
    platform = current_platform()
    browser_sessions = BrowserSessionManager(
        headless=platform.name == "container", platform=platform
    )
    app.state.browser_sessions = browser_sessions
    # vault: the owner's card, sealed under a key only the OS store holds
    # (Keychain / DPAPI; disabled in a container). Nothing is read until
    # the Settings page or an approved checkout asks.
    vault = VaultService(session_factory, select_key_provider(platform))
    app.state.vault = vault
    # desktop.observe / desktop.act run on this platform's backend (Mac or
    # Windows; an unavailable stand-in anywhere else, the container
    # included). Nothing is loaded or touched until the first call, and the
    # computer_control switch (off by default) gates every one. The stop
    # check is the per-user one the runtime answers for the turn or
    # approved action in progress (services.agent.cancel).
    computer_toolkit = ComputerToolkit(
        computer_backend.select_backend(platform.name),
        cancel_flag=agent_cancel.is_cancelled,
    )
    # browser.read, browser.act and browser.checkout share the one browser
    # and one page memory. checkout pays with the card in the vault
    # (app.state.vault), under the caps the owner set (installation
    # .purchase_caps), and only after the owner approves its card; the
    # purchases switch (off by default) gates every call.
    browser_toolkits = build_browser_toolkits(
        browser_sessions,
        session_factory=session_factory,
        vault=vault,
        settings_source=installation,
        cancel_flag=agent_cancel.is_cancelled,
        egress_hooks=egress_hooks,
    )
    # Security wave (S7): the owner's Blocked sites hold for every fetch
    # that opens a web page for the owner, not only the browser and web.*:
    # watch.create, every background page-watch check (a watch saved before
    # its site was Blocked included) and a web page saved to the knowledge
    # base. These fail closed: while no rules were ever read they fetch
    # nothing, since a background check has no call check in front of it.
    # With no rule matching, the plain network policy answers as before.
    site_resolver = site_rules.wrap_resolver(validated_addresses, fail_closed=True)
    tool_executor = ConnectorToolExecutor(
        session_factory=session_factory,
        capability_gate=installation.capability_statuses,
        system_toolkit=system_toolkit,
        browser_toolkit=browser_toolkits.read,
        computer_toolkit=computer_toolkit,
        act_toolkit=browser_toolkits.act,
        checkout_toolkit=browser_toolkits.checkout,
        # Security wave (S7): web.fetch_page, research and screenshots refuse
        # a Blocked host on every hop, before a socket opens.
        web_toolkit=WebToolkit(resolver=site_rules.wrap_resolver(validated_addresses)),
        watch_toolkit=WatchToolkit(session_factory, resolver=site_resolver),
        knowledge_toolkit=KnowledgeToolkit(session_factory, url_resolver=site_resolver),
    )
    # Security wave (S5): the dispatcher and the catalog read the MCP pins.
    tool_executor.use_mcp_pins(mcp_pins)
    # The Telegram poller reads a purchase card's picture through it.
    app.state.tool_executor = tool_executor
    app.state.agent_runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(
            capability_gate=installation.capability_statuses
        ),
        tool_executor=tool_executor,
        audit_service=RuntimeAuditLogger(session_factory=session_factory),
        approval_store=approval_store,
        settings_source=installation,
        browser_spend=browser_spend_sink(browser_sessions),
        app_approval_store=DbAppApprovalStore(session_factory=session_factory),
    )
    logger.info("agent_runtime_initialized")

    # Tool discovery for user-registered MCP servers (short-TTL cache).
    app.state.mcp_catalog = MCPToolCatalog(MCPConnectorLoader(session_factory), pins=mcp_pins)

    async def _apply_telegram() -> None:
        switches = await installation.capabilities()
        await telegram_manager.apply(
            await installation.telegram_token(), switches.get("telegram", False)
        )

    async def _on_change(topic: str) -> None:
        if topic == "llm":
            runtime = getattr(app.state, "agent_runtime", None)
            if runtime is not None:
                runtime.invalidate_providers()
        if topic in ("telegram", "capabilities"):
            await _apply_telegram()
        if topic == "capabilities":
            # In the background, as the connector routes do: stopping a
            # channel can wait on its running turn, and PUT
            # /api/capabilities must never wait on that.
            slack_manager.schedule_reconcile()

    installation.on_change(_on_change)
    # The Telegram poller itself starts at the very end (below): messages
    # queued while the server was down arrive as soon as it polls, and the
    # turns they start must meet the call checks, not an empty pipeline.

    # Reminders sweep regardless of whether a delivery channel runs — the
    # rows are still user-visible in the API; only the out-of-band push
    # needs Telegram or Slack, and each manager's send_text reports False
    # while none of its channels runs.
    app.state.reminders = ReminderService(
        session_factory=session_factory,
        send=fan_out_send(
            {"telegram": telegram_manager.send_text, "slack": slack_manager.send_text}
        ),
    )

    # Page watches fetch pages in the background, so the sweeper re-reads
    # the owner's page_watch switch before every check and checks nothing
    # while it is off or blocked (no Telegram token, or Telegram switched
    # off). Alerts go through the same manager as reminders; with no linked
    # chat the change is still recorded for watch.list.
    async def _page_watch_enabled() -> bool:
        return "page_watch" in await installation.enabled_keys()

    # Security wave (S7): each check meets the owner's site rules on every
    # hop (site_resolver, above). Nothing else re-reads the rules for a
    # background check, so the snapshot (its age and the switch) is brought
    # up to date first; a Blocked site is then refused with S7's sentence
    # before a socket opens, and the watch records it as a failed check.
    async def _page_watch_fetch(url: str) -> PageSnapshot:
        await site_rules.ensure_fresh()
        return await fetch_snapshot(url, resolver=site_resolver)

    app.state.page_watches = PageWatchService(
        session_factory=session_factory,
        send=telegram_manager.send_text,
        enabled=_page_watch_enabled,
        fetch=_page_watch_fetch,
    )

    # top10:secret_pii_redaction
    # "Hide personal details from the AI provider": the runtime reads it once
    # per turn (a gate error counts as hide; a local Ollama turn ignores it).
    async def _personal_details_hidden() -> bool:
        return "hide_personal_details" in await installation.enabled_keys()

    app.state.agent_runtime.use_personal_details_gate(_personal_details_hidden)

    # top10:file_extraction
    # Documents: the executor built the files toolkit (the parser sandbox,
    # the opened-document registry and the encrypted upload store). The
    # upload route, the chat paths and the channels share them through the
    # intake, which reads "Read files and documents" through the executor's
    # capability gate and writes file_uploaded / file_upload_refused rows.
    from services.files.intake import FileIntake

    app.state.files = tool_executor.files_toolkit
    app.state.file_intake = FileIntake(
        tool_executor.files_toolkit.store,
        gate=tool_executor.file_reading_refusal,
        audit=RuntimeAuditLogger(session_factory=session_factory).log,
    )

    # top10:scheduler_briefing
    # Scheduled tasks and the daily briefing: the unattended runner (fenced
    # agent turns), the toolkit the REST routes and chat commands share, and
    # the sweeper, which re-reads each kind's switch before every claim and
    # run and sends results only to the user's own linked chats.
    from services.notifications.schedules import ScheduleService
    from services.scheduler import commands as schedule_commands
    from services.scheduler.briefing import BriefingReader
    from services.tools.schedule import ScheduleToolkit

    app.state.unattended_runner = agent.build_unattended_runner(app, session_factory)
    app.state.schedule_toolkit = ScheduleToolkit(session_factory)
    app.state.schedules = ScheduleService(
        session_factory,
        runner=app.state.unattended_runner,
        senders={"telegram": telegram_manager.send_text, "slack": slack_manager.send_text},
        enabled_keys=installation.enabled_keys,
        briefing_reader=BriefingReader(
            permissions=RuntimePermissionAdapter(capability_gate=installation.capability_statuses),
            executor=tool_executor,
            audit=RuntimeAuditLogger(session_factory=session_factory),
        ),
        runtime=lambda: getattr(app.state, "agent_runtime", None),
    )
    schedule_commands.configure(
        schedule_commands.ScheduleBackend(
            toolkit=app.state.schedule_toolkit,
            service=app.state.schedules,
            session_factory=session_factory,
        )
    )

    # top10:tutor_mode

    # top10:knowledge_base
    # The knowledge base: the executor built its toolkit (connector sources
    # run through the executor itself, uploads through the files toolkit).
    # Here it gets the owner's limits and the embedding source (the
    # install-wide provider, or Ollama); the meaning-index sweeper re-reads
    # knowledge_semantic before every sweep; Telegram's "/kb <collection>"
    # caption saves a file while knowledge_base is on.
    from services.knowledge import channels as knowledge_channels
    from services.knowledge.embedder import KnowledgeEmbedService
    from services.knowledge.embeddings import EmbeddingSource
    from services.notifications.sweeper import capability_gate

    knowledge = tool_executor.knowledge_toolkit
    knowledge_embeddings = EmbeddingSource(installation)

    async def _knowledge_settings() -> dict[str, Any]:
        return await installation.capability_settings("knowledge_base")

    knowledge.use_settings(_knowledge_settings)
    knowledge.use_embeddings(knowledge_embeddings)
    app.state.knowledge = knowledge
    app.state.knowledge_embedder = KnowledgeEmbedService(
        session_factory,
        source=knowledge_embeddings,
        enabled=capability_gate(installation, "knowledge_semantic"),
        settings=_knowledge_settings,
        vector_cache=knowledge.service.vector_cache,
    )
    knowledge_channels.configure(
        knowledge_channels.TelegramBackend(
            toolkit=knowledge,
            enabled=capability_gate(installation, "knowledge_base"),
            audit=RuntimeAuditLogger(session_factory=session_factory).log,
        )
    )

    # top10:flashcards_quizzes
    # Flashcards: the executor built the study toolkit. Its daily "cards are
    # due" reminder is a nudge on the schedule service (the study_due
    # renderer registers on import), the one-time download links are shared
    # with the export route, and the model-free Telegram and Slack reviews
    # re-read the owner's study switch for every command.
    from services.agent.tool_registry import study_toolkit_of
    from services.study import channel as study_channel
    from services.study import nudges as _study_nudges  # noqa: F401 - registers study_due

    study_toolkit = study_toolkit_of(tool_executor)
    study_toolkit.use_nudges(app.state.schedules)
    app.state.study_exports = study_toolkit.exports

    async def _study_enabled() -> bool:
        return "study" in await installation.enabled_keys()

    study_channel.configure(
        study_channel.StudyChannel(
            study_toolkit.engine, enabled=_study_enabled, session_factory=session_factory
        )
    )

    # top10:event_triggers
    # App-event triggers: the toolkit the executor built (told whether the
    # unattended runner is wired, so run_task is refused before a card when
    # it is not), the chat commands' backend, and the sweeper, which re-reads
    # both switches before every check and run, reads apps only through the
    # executor, runs tasks only through the one unattended runner, and
    # messages only the user's own linked chats. Page-watch changes reach the
    # page.changed triggers through the watch sweeper's hook.
    from services.notifications.event_triggers import TriggerService
    from services.triggers import commands as trigger_commands

    trigger_toolkit = tool_executor.triggers_toolkit
    trigger_toolkit.set_runner_available(
        lambda: getattr(app.state, "unattended_runner", None) is not None
    )
    app.state.trigger_toolkit = trigger_toolkit

    async def _triggers_enabled() -> bool:
        return "event_triggers" in await installation.enabled_keys()

    async def _trigger_runs_enabled() -> bool:
        return "trigger_runs" in await installation.enabled_keys()

    app.state.triggers = TriggerService(
        session_factory,
        executor=tool_executor,
        send=fan_out_send(
            {"telegram": telegram_manager.send_text, "slack": slack_manager.send_text}
        ),
        enabled=_triggers_enabled,
        runs_enabled=_trigger_runs_enabled,
        runner=getattr(app.state, "unattended_runner", None),
    )
    app.state.page_watches.on_change = app.state.triggers.enqueue_page_change
    trigger_commands.configure(
        trigger_commands.TriggerBackend(toolkit=trigger_toolkit, session_factory=session_factory)
    )

    # top10:permission_tiers
    # Low-risk grants ("Allow low-risk changes on <account> for 7 days"): one
    # store for the runtime (decisions, cards, approvals) and the executor's
    # standing-consent backstop.
    from services.agent.permission_grants import DbPermissionGrantStore

    permission_grants = DbPermissionGrantStore(session_factory=session_factory)
    app.state.agent_runtime.use_permission_grants(permission_grants)
    tool_executor.use_permission_grants(permission_grants)

    # top10:voice_notes
    # Telegram voice notes: one VoiceNoteService per process (the local
    # worker slot and the per-user quota live on it), reading the owner's
    # two voice switches through the capability gate per note.
    voice_notes_for(app, session_factory)

    # top10:video_transcripts
    # Video and podcast transcripts: the executor built the toolkit (its
    # transcript cache shares the app's session factory). The owner's limits
    # (minutes per call and per day, days kept) and the audit log that gets
    # video_provider_read rows are wired in here, and the janitor purges
    # expired transcripts every 6 hours whether or not the switch is on.
    from services.notifications.transcripts import TranscriptJanitor

    tool_executor.video_toolkit.use(
        settings=installation,
        audit=RuntimeAuditLogger(session_factory=session_factory).log,
    )

    async def _keep_transcripts_days() -> int:
        return (await installation.video_limits())["keep_transcripts_days"]

    app.state.transcript_janitor = TranscriptJanitor(
        tool_executor.video_toolkit.store, keep_days=_keep_transcripts_days
    )

    # Security wave (security10): the skills' services, then the call checks
    # every one of them plugs into. Each is a stub that changes nothing until
    # its skill lands; none starts here (the lifespan starts the sweepers).
    from services.agent.tool_registry import security_toolkit_of
    from services.notifications.sweeper import capability_gate as security_gate

    # Security wave (S1): outbound message checks. The hidden-character floor
    # is the executor's default; this adds the audit row, the sent-to
    # history, the organisation's domains and the call check (slot 4).
    from services.security.outbound import OutboundCheck, OutboundService
    from services.security.outbound_store import (
        KnownRecipientStore,
        OrganisationDomainStore,
        OrgDomains,
        UserEmails,
    )

    known_recipients = KnownRecipientStore(session_factory)
    outbound = OutboundService(
        known=known_recipients, audit=RuntimeAuditLogger(session_factory=session_factory).log
    )
    tool_executor.use_outbound(outbound)
    app.state.outbound = outbound
    app.state.organisation_domains = OrganisationDomainStore(session_factory)
    # S9's rule B3 reads one user's organisation domains; it shares the
    # owner list's cache invalidation.
    app.state.org_domains = OrgDomains(session_factory, domains=app.state.organisation_domains)

    async def _outbound_checks_enabled() -> bool:
        return "outbound_checks" in await installation.enabled_keys()

    outbound_check = OutboundCheck(
        executor=tool_executor,
        known=known_recipients,
        org_domains=app.state.organisation_domains,
        users=UserEmails(session_factory),
        links=link_reputation,
        enabled=_outbound_checks_enabled,
    )

    # Security wave (S9): rules on tool arguments (slot 1). A broken rule
    # raises a card that names it; the owner edits rules on the Security page.
    from services.security.tool_rules import DbToolRuleStore, ToolRulesCheck

    tool_rules_store = DbToolRuleStore(session_factory)
    app.state.tool_rules_store = tool_rules_store

    async def _tool_rules_enabled() -> bool:
        return "tool_rules" in await installation.enabled_keys()

    app.state.tool_rules_check = ToolRulesCheck(
        tool_rules_store,
        enabled=_tool_rules_enabled,
        org_domains=app.state.org_domains.for_user,
    )

    # Security wave (S10): file reputation. One service per process (the
    # VirusTotal client, the quota, the verdict cache and the bytes an
    # approved upload card may send). The intake fingerprints every upload
    # through it, and the security.* family's file tools and the upload's
    # card hooks go through its toolkit.
    from services.file_reputation.service import FileReputationService
    from services.file_reputation.sweeper import FileReputationSweeper
    from services.file_reputation.toolkit import FileReputationToolkit

    runtime = app.state.agent_runtime

    async def _pending_ids(user_id: str) -> set[str]:
        return {p.action_id for p in await runtime.list_pending_approvals(user_id)}

    file_reputation = FileReputationService(
        session_factory,
        settings=installation,
        audit=RuntimeAuditLogger(session_factory=session_factory).log,
        send=app.state.owner_send,
        telegram_fetch=telegram_manager.download_file,
        connector_read=tool_executor.execute,
        park_card=runtime.park_card,
        pending_ids=_pending_ids,
    )
    app.state.file_reputation = file_reputation
    app.state.file_intake.use_screen(file_reputation)
    security_toolkit_of(tool_executor).use_file_reputation(FileReputationToolkit(file_reputation))
    app.state.file_reputation_sweeper = FileReputationSweeper(file_reputation)

    # Security wave (S3): scam checks. One ScamCheckService per process (its
    # quota and recent answers live on it); it reads the scam_check switch per
    # check. The in-turn security.check_scam tool is registered only once the
    # service exists; until then the family answers "not available".
    from services.scam_check.service import scam_check_for

    scam = scam_check_for(app, session_factory)
    if scam is not None:
        security_toolkit_of(tool_executor).register("check_scam", scam.check_for_tool)

    # Security wave (S2): every new email in each connected Gmail and Outlook
    # inbox is checked on this computer; flagged mail gets one AI review (its
    # own daily cap, not the unattended budget) and an alert to the person's
    # own chats, then a Move-to-Spam/Junk approval card. Nothing is moved
    # without one.
    from services.notifications.mail_scan import MailScanService

    app.state.mail_scan = MailScanService(
        session_factory,
        executor=tool_executor,
        send=app.state.owner_send,
        enabled=security_gate(installation, "mail_scam_scan"),
        settings=installation,
        approvals=approval_store,
        runtime=runtime,
        links=link_reputation,
        files=file_reputation,
        local_model=settings.MAIL_REVIEW_OLLAMA_MODEL,
        ollama_base_url=settings.OLLAMA_BASE_URL,
    )

    # Security wave (S6): weekly Have I Been Pwned lookups of the owners'
    # addresses with the owner's own key, paced to the key's limit; alerts
    # only to the owners' own linked chats. The gate is re-read before every
    # lookup, and a key or switch change runs one sweep at once.
    from services.notifications.breach_monitor import BreachMonitorService

    async def _hibp_key() -> Optional[str]:
        return await installation.service_key("hibp")

    breach_monitor = BreachMonitorService(
        session_factory,
        api_key=_hibp_key,
        send=app.state.owner_send,
        enabled=security_gate(installation, "breach_monitor"),
    )
    app.state.breach_monitor = breach_monitor

    async def _breach_on_change(topic: str) -> None:
        if topic == "capabilities":
            breach_monitor.kick()

    installation.on_change(_breach_on_change)

    # Security wave: the pre-dispatch call checks, in their fixed order (tool
    # rules, MCP pins, site rules, outbound, file reputation). The runtime
    # (turn and approve stages) and the executor's fail-closed backstop run
    # the same pipeline object; a check that is still a stub applies to no
    # call, so nothing changes until its skill lands.
    from services.file_reputation.call_check import FileReputationCallCheck
    from services.mcp.pin_check import McpPinCallCheck
    from services.security.call_checks import standard_pipeline

    page_memory = browser_toolkits.memory

    def _page_origin(user_id: str) -> Optional[str]:
        page = page_memory.get(user_id)
        return page.origin if page is not None else None

    pipeline = standard_pipeline(
        tool_rules=app.state.tool_rules_check,
        mcp_pin=McpPinCallCheck(mcp_pins),
        site_rules=site_rules.call_check(page_origin=_page_origin),
        outbound=outbound_check,
        file_reputation=FileReputationCallCheck(session_factory),
        audit=RuntimeAuditLogger(session_factory=session_factory).log,
    )
    app.state.call_checks = pipeline
    runtime.use_call_checks(pipeline)
    tool_executor.use_call_checks(pipeline)

    # The first site-rules snapshot. A failed read is logged by type only;
    # the rules then fail closed until the next refresh succeeds.
    try:
        await site_rules.refresh()
    except Exception as exc:
        logger.warning("site_rules_initial_load_failed", error_type=type(exc).__name__)

    # Last: start the Telegram poller, once everything a turn it starts runs
    # through is wired (the call checks, the outbound floor, the file
    # screen, the site-rules snapshot). Slack's channels start after
    # wire_services, in the lifespan.
    try:
        await _apply_telegram()
    except Exception as exc:
        # A bad token or an unreachable Telegram must not keep the API
        # down; the owner can fix the token in Settings. Type only: the
        # message can quote a bot-token URL.
        logger.warning("telegram_start_failed", error_type=type(exc).__name__)


_is_production = settings.ENVIRONMENT == "production"

app = FastAPI(
    title="Crawler AI",
    description="Secure-by-Design Agentic AI Platform",
    version="0.1.0",
    lifespan=lifespan,
    # The interactive docs and schema are developer conveniences; in
    # production they hand an attacker the full authenticated API surface.
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)

# ── Middleware (the LAST one added is the outermost) ──────────────────────────
# Rate limiting is added before the header/request-id layers so it ends up
# INSIDE them. A throttled request short-circuits with a 429 from the
# limiter itself and never reaches anything further in, so anything that
# must appear on every response — the security headers and the correlation
# id — has to wrap the limiter, not sit under it. Otherwise exactly the
# responses an attacker provokes are the ones served unhardened and
# untraceable.
if settings.ALLOWED_HOSTS and settings.ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=settings.RATE_LIMIT_PER_MINUTE,
    auth_max_requests=settings.AUTH_RATE_LIMIT_PER_MINUTE,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    # Enumerate exactly what the SPA uses; wildcards + credentials is a
    # combination browsers reject and an unnecessarily wide surface anyway.
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    # DEVICE_HEADER: the browser's device id, for weekly app approvals;
    # X-Crawler-Timezone: the browser's IANA zone, for scheduled tasks.
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", DEVICE_HEADER, "X-Crawler-Timezone"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api")
app.include_router(agent.router, prefix="/api")
app.include_router(connectors.router, prefix="/api")
app.include_router(oauth.router, prefix="/api")
app.include_router(slack.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(memory.router, prefix="/api")
app.include_router(reminders.router, prefix="/api")
app.include_router(telegram.router, prefix="/api")
app.include_router(usage.router, prefix="/api")
app.include_router(capabilities.router, prefix="/api")
app.include_router(setup.router, prefix="/api")
app.include_router(vault.router, prefix="/api")  # vault
app.include_router(app_approvals.router, prefix="/api")
# top10:secret_pii_redaction

# top10:file_extraction
from api.routes import files as files_routes

app.include_router(files_routes.router, prefix="/api")

# top10:scheduler_briefing
from api.routes import schedules as schedules_routes

app.include_router(schedules_routes.router, prefix="/api")

# top10:tutor_mode
from api.routes import tutor as tutor_routes  # noqa: E402

app.include_router(tutor_routes.router, prefix="/api")

# top10:knowledge_base

# top10:flashcards_quizzes
from api.routes import study as study_routes

app.include_router(study_routes.router, prefix="/api")

# top10:event_triggers
from api.routes import triggers as triggers_routes  # noqa: E402

app.include_router(triggers_routes.router, prefix="/api")

# top10:permission_tiers
from api.routes import permission_grants as permission_grants_routes

app.include_router(permission_grants_routes.router, prefix="/api")

# top10:voice_notes

# top10:video_transcripts

# Security wave (security10): the Security page's routes, one router per
# module, all under /api/security. Service keys first (WAVE 0, real); the
# skills' routers follow in this block.
from api.routes import security_keys as security_keys_routes

app.include_router(security_keys_routes.router, prefix="/api")
from api.routes import link_reputation as link_reputation_routes
from api.routes import security_breach as security_breach_routes
from api.routes import security_files as security_files_routes
from api.routes import security_mail as security_mail_routes
from api.routes import security_mcp as security_mcp_routes
from api.routes import security_outbound as security_outbound_routes
from api.routes import security_scam as security_scam_routes
from api.routes import security_site_rules as security_site_rules_routes
from api.routes import security_tool_rules as security_tool_rules_routes

app.include_router(link_reputation_routes.router, prefix="/api")
app.include_router(security_outbound_routes.router, prefix="/api")
app.include_router(security_mail_routes.router, prefix="/api")
app.include_router(security_scam_routes.router, prefix="/api")
app.include_router(security_mcp_routes.router, prefix="/api")
app.include_router(security_breach_routes.router, prefix="/api")
app.include_router(security_site_rules_routes.router, prefix="/api")
app.include_router(security_tool_rules_routes.router, prefix="/api")
app.include_router(security_files_routes.router, prefix="/api")


@app.get("/")
async def root() -> dict[str, str]:
    info = {
        "name": "Crawler AI",
        "version": "0.1.0",
        "health": "/api/health",
    }
    if not _is_production:
        info["docs"] = "/docs"
    return info


@app.get("/api/health")
async def health_check(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Liveness + database reachability.

    The Docker healthcheck polls this endpoint; returning 503 when the
    database is unreachable keeps the container (and everything gated on
    its health, like the frontend's depends_on) honest about whether the
    API can actually serve requests.
    """
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        logger.warning("health_check_database_unreachable")
        # Reset the session so get_db's trailing commit doesn't raise a
        # second time and turn this 503 into a 500.
        try:
            await db.rollback()
        except Exception:
            pass
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "reason": "database unreachable"},
        )
    return JSONResponse(content={"status": "healthy", "version": "0.1.0"})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """422 that says where and why, never what was sent.

    FastAPI's stock body repeats each failing field's ``input`` (for a
    missing field, the whole request body) plus the validator's ``ctx``,
    so a login or setup request missing one field would send the password
    or API key next to it straight back into the response, the browser's
    devtools and any proxy log. Only type, location and message survive.
    """
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"type": err.get("type"), "loc": list(err.get("loc", ())), "msg": err.get("msg")}
                for err in exc.errors()
            ]
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for anything a route/dependency didn't handle.

    Logs only the exception's type plus the request it happened on —
    never ``str(exc)``, which can embed secrets from the very error that
    triggered it (a bad API key echoed into a driver's error message, a
    token in a failed URL, etc). The response body already withheld that
    detail from the client; the log must too.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        "unhandled_exception",
        request_id=request_id,
        error_type=type(exc).__name__,
        path=request.url.path,
        method=request.method,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
    )


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.ENVIRONMENT == "development",
    )
