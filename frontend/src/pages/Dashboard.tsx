import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Radio,
  Activity,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  Wifi,
  WifiOff,
  MessageSquare,
  ExternalLink,
  Server,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { ChannelResponse } from "@/types";
import {
  getChannels,
  getOpenClawStatus,
  getStoredUser,
  getAuditLogs,
  getAuditStats,
  getConnectors,
} from "@/services/api";
import { OPENCLAW_BROWSER_URL } from "@/lib/env";
import { Skeleton } from "@/components/ui/Skeleton";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { EmptyState } from "@/components/ui/EmptyState";

const CHART_OK = "#22d3ee";
const CHART_ALERT = "#f87171";
const CHART_BLOCK = CHART_ALERT;

const statusColors: Record<string, string> = {
  approved: "var(--accent-success)",
  blocked: "var(--accent-danger)",
  pending: "var(--accent-warning)",
  escalated: "var(--accent-warning)",
};

const statusIcons: Record<string, LucideIcon> = {
  approved: CheckCircle2,
  blocked: XCircle,
  pending: Clock,
  escalated: ShieldAlert,
};

const channelColors: Record<string, string> = {
  telegram: "#22d3ee",
  discord: "#a78bfa",
  slack: "#fbbf24",
  whatsapp: "#34d399",
  signal: "#38bdf8",
  webchat: "#5eead4",
};

// ─── Types defensively shaped to match the foundation agent's API ──────────

interface AuditStatsResponse {
  /** Total audit events in the past 24 hours. */
  last_24h_count?: number;
  /** Approved actions in the past 24 hours. */
  approved_24h?: number;
  /** Blocked actions in the past 24 hours. */
  blocked_24h?: number;
  /** Per-day breakdown for the timeline chart. */
  timeline?: Array<{ date: string; approved: number; blocked: number }>;
  /** Aggregate counters (compat with existing AuditStats). */
  total?: number;
  approved?: number;
  blocked?: number;
}

interface AuditLogEntry {
  id: string;
  connector_name?: string;
  action?: string;
  status?: "approved" | "blocked" | "pending" | "escalated" | string;
  timestamp?: string;
}

interface ConnectorEntry {
  id: string;
  status?: string;
  is_enabled?: boolean;
}

// ─── Layout primitives ─────────────────────────────────────────────────────

function Panel({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-[var(--radius-xl)] border border-[var(--claw-border)] bg-[var(--claw-panel)] ${className}`}
      style={{ boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04)" }}
    >
      {children}
    </div>
  );
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; dataKey?: string | number }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-md border border-[var(--claw-border)] px-3 py-2 text-[12px] font-mono"
      style={{ backgroundColor: "var(--claw-surface)", color: "var(--text-primary)" }}
    >
      <p className="text-[var(--text-muted)] mb-1">{label}</p>
      <div className="space-y-0.5">
        {payload.map((p) => (
          <div key={String(p.dataKey ?? p.name)} className="flex justify-between gap-6 tabular-nums">
            <span className="text-[var(--text-secondary)]">{p.name}</span>
            <span>{p.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function MetricTile({
  label,
  value,
  icon: Icon,
  accent,
  loading = false,
}: {
  label: string;
  value: number | string;
  icon: LucideIcon;
  accent: string;
  loading?: boolean;
}) {
  return (
    <Panel className="p-4 flex flex-col gap-2 min-w-0">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)] truncate">
          {label}
        </span>
        <Icon className="w-4 h-4 shrink-0" style={{ color: accent }} strokeWidth={2} />
      </div>
      {loading ? (
        <Skeleton width="w-16" height="h-7" />
      ) : (
        <p className="text-[26px] font-semibold tabular-nums tracking-tight text-[var(--text-primary)] leading-none font-mono">
          {value}
        </p>
      )}
    </Panel>
  );
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function formatRelativeTimestamp(ts?: string): string {
  if (!ts) return "—";
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.round(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return date.toLocaleDateString();
}

function buildTimelineFromStats(stats?: AuditStatsResponse) {
  if (stats?.timeline && stats.timeline.length > 0) return stats.timeline;
  const approved = stats?.last_24h_count ?? stats?.total ?? stats?.approved ?? 0;
  const blocked = stats?.blocked_24h ?? stats?.blocked ?? 0;
  // Fallback single-bucket timeline so the chart still renders.
  return [{ date: "24h", approved, blocked }];
}

// ─── Page ──────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const channelsQuery = useQuery({
    queryKey: ["channels"],
    queryFn: getChannels,
  });

  const openclawQuery = useQuery({
    queryKey: ["openclaw-status"],
    queryFn: getOpenClawStatus,
    refetchInterval: 30_000,
  });

  const auditStatsQuery = useQuery({
    queryKey: ["audit-stats-24h"],
    queryFn: () => getAuditStats() as Promise<AuditStatsResponse>,
  });

  const auditRecentQuery = useQuery({
    queryKey: ["audit-recent"],
    queryFn: () =>
      getAuditLogs({ limit: 10 }) as Promise<AuditLogEntry[]>,
  });

  const connectorsQuery = useQuery({
    queryKey: ["connectors"],
    queryFn: getConnectors as () => Promise<ConnectorEntry[]>,
  });

  const channels: ChannelResponse[] = channelsQuery.data ?? [];
  const activeChannels = channels.filter((c) => c.is_enabled);
  const user = getStoredUser();
  const gatewayOnline = openclawQuery.data?.gateway_online ?? false;
  const modelLabel = user ? `${user.llm_provider} · ${user.llm_model}` : "—";

  const stats = auditStatsQuery.data;
  const timelineData = buildTimelineFromStats(stats);
  const recentLogs = auditRecentQuery.data ?? [];

  const connectors = connectorsQuery.data ?? [];
  const activeConnectorCount = connectors.filter(
    (c) => c.is_enabled !== false && c.status !== "disconnected" && c.status !== "error",
  ).length;

  const messages24h = stats?.last_24h_count ?? stats?.approved ?? 0;
  const blocked24h = stats?.blocked_24h ?? stats?.blocked ?? 0;

  const metricsLoading = auditStatsQuery.isLoading || channelsQuery.isLoading;

  return (
    <div className="space-y-6 min-w-0">
      {/* Header */}
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between min-w-0">
        <div className="min-w-0 pr-2">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-[var(--claw-accent)] px-2 py-0.5 rounded border border-[rgba(34,211,238,0.35)] bg-[var(--claw-glow)]">
              Control center
            </span>
            <span className="text-[10px] font-mono text-[var(--text-muted)]">SentientAI shell</span>
          </div>
          <h1 className="text-[22px] sm:text-[26px] font-semibold tracking-tight text-[var(--text-primary)]">
            Gateway & workspace
          </h1>
          <p className="text-[13px] text-[var(--text-muted)] mt-1 max-w-2xl leading-relaxed font-mono">
            Mirror of the native OpenClaw dashboard: manage channels here, then open the Control UI for
            sessions, config, and WebChat — same port as upstream OpenClaw.
          </p>
        </div>
        <div className="flex flex-col sm:items-end gap-2 shrink-0">
          <a
            href={OPENCLAW_BROWSER_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-[13px] font-mono font-medium text-[var(--bg-primary)] bg-[var(--claw-accent)] hover:brightness-110 transition-all"
          >
            <ExternalLink className="w-4 h-4" strokeWidth={2} />
            Open OpenClaw UI
          </a>
          <span className="text-[10px] font-mono text-[var(--text-muted)] text-right max-w-[240px]">
            {OPENCLAW_BROWSER_URL}
          </span>
        </div>
      </header>

      {/* Surface query errors at the top so users don't miss them */}
      {openclawQuery.isError && (
        <ErrorBanner
          title="Gateway status unavailable"
          error={openclawQuery.error}
          onRetry={() => openclawQuery.refetch()}
          retrying={openclawQuery.isFetching}
        />
      )}

      {/* Gateway runtime strip */}
      <Panel className="p-4 sm:p-5">
        <div className="flex flex-col lg:flex-row lg:items-center gap-4 min-w-0">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 border border-[var(--claw-border)]"
              style={{ background: "var(--claw-surface)" }}
            >
              <Server className="w-5 h-5 text-[var(--claw-accent)]" strokeWidth={1.75} />
            </div>
            <div className="min-w-0">
              <p className="text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
                Gateway
              </p>
              <p className="text-[14px] font-mono text-[var(--text-primary)] truncate tabular-nums">
                {openclawQuery.isLoading
                  ? "…"
                  : openclawQuery.data?.gateway_url || OPENCLAW_BROWSER_URL}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:ml-auto">
            <span
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono border"
              style={{
                borderColor: gatewayOnline ? "rgba(52,211,153,0.35)" : "rgba(248,113,113,0.35)",
                background: gatewayOnline ? "rgba(52,211,153,0.1)" : "rgba(248,113,113,0.1)",
                color: gatewayOnline ? "var(--accent-success)" : "var(--accent-danger)",
              }}
            >
              {gatewayOnline ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
              {openclawQuery.isLoading
                ? "checking"
                : gatewayOnline
                ? "reachable"
                : "unreachable"}
            </span>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono border border-[var(--claw-border)] bg-[var(--claw-surface)] text-[var(--text-secondary)] max-w-full">
              <Radio className="w-3 h-3 text-[var(--claw-accent)] shrink-0" />
              <span className="truncate">{activeChannels.length} channels</span>
            </span>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono border border-[var(--claw-border)] bg-[var(--claw-surface)] text-[var(--text-secondary)] max-w-full truncate">
              {modelLabel}
            </span>
          </div>
        </div>
      </Panel>

      {/* Metrics */}
      <section aria-label="Summary" className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <MetricTile
          label="Gateway"
          value={openclawQuery.isLoading ? "…" : gatewayOnline ? "OK" : "Down"}
          icon={gatewayOnline ? Wifi : WifiOff}
          accent={gatewayOnline ? "var(--accent-success)" : "var(--accent-danger)"}
          loading={openclawQuery.isLoading}
        />
        <MetricTile
          label="Active connectors"
          value={activeConnectorCount}
          icon={Radio}
          accent="var(--claw-accent)"
          loading={connectorsQuery.isLoading}
        />
        <MetricTile
          label="Msgs (24h)"
          value={messages24h}
          icon={Activity}
          accent="var(--accent-success)"
          loading={metricsLoading}
        />
        <MetricTile
          label="Blocked (24h)"
          value={blocked24h}
          icon={ShieldAlert}
          accent="var(--accent-danger)"
          loading={metricsLoading}
        />
      </section>

      <section
        aria-label="Charts and activity"
        className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-stretch min-w-0"
      >
        <Panel className="xl:col-span-8 p-5 min-w-0 flex flex-col">
          <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-4 shrink-0">
            <div>
              <h2 className="text-[13px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
                Policy timeline
              </h2>
              <p className="text-[15px] font-medium text-[var(--text-primary)] mt-1">
                Approved vs blocked (last 24h)
              </p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono text-[var(--text-muted)] shrink-0">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: CHART_OK }} />
                ok
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: CHART_BLOCK }} />
                block
              </span>
            </div>
          </div>
          <div className="h-[260px] w-full min-h-0 min-w-0 flex-1 rounded-lg border border-[var(--claw-border)] bg-[var(--claw-surface)] px-2 py-2">
            {auditStatsQuery.isLoading ? (
              <div className="h-full w-full flex items-center justify-center">
                <Skeleton width="w-[90%]" height="h-[80%]" />
              </div>
            ) : auditStatsQuery.isError ? (
              <div className="h-full flex items-center justify-center px-4">
                <ErrorBanner
                  title="Couldn't load timeline"
                  error={auditStatsQuery.error}
                  onRetry={() => auditStatsQuery.refetch()}
                  retrying={auditStatsQuery.isFetching}
                />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="okGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={CHART_OK} stopOpacity={0.25} />
                      <stop offset="95%" stopColor={CHART_OK} stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={CHART_BLOCK} stopOpacity={0.2} />
                      <stop offset="95%" stopColor={CHART_BLOCK} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "rgba(161,161,170,0.9)", fontSize: 11, fontFamily: "ui-monospace" }}
                    tickLine={false}
                    axisLine={false}
                    dy={8}
                  />
                  <YAxis
                    tick={{ fill: "rgba(161,161,170,0.9)", fontSize: 11, fontFamily: "ui-monospace" }}
                    tickLine={false}
                    axisLine={false}
                    width={32}
                  />
                  <Tooltip
                    content={<ChartTooltip />}
                    cursor={{ stroke: "rgba(255,255,255,0.08)", strokeWidth: 1 }}
                  />
                  <Area
                    type="monotone"
                    dataKey="approved"
                    name="Approved"
                    stroke={CHART_OK}
                    fill="url(#okGrad)"
                    strokeWidth={1.5}
                    dot={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked"
                    stroke={CHART_BLOCK}
                    fill="url(#blockGrad)"
                    strokeWidth={1.5}
                    dot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </Panel>

        <Panel className="xl:col-span-4 p-5 min-w-0 flex flex-col min-h-[300px] xl:min-h-0">
          <h2 className="text-[13px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-1">
            Live feed
          </h2>
          <p className="text-[15px] font-medium text-[var(--text-primary)] mb-3">
            Recent activity
          </p>
          {auditRecentQuery.isLoading ? (
            <ul className="flex flex-col gap-1 flex-1 min-h-0 overflow-y-auto font-mono text-[12px]">
              {Array.from({ length: 5 }).map((_, i) => (
                <li
                  key={i}
                  className="rounded-md border border-[var(--claw-border)] bg-[var(--claw-surface)] px-2.5 py-2"
                >
                  <Skeleton height="h-3" width="w-full" />
                </li>
              ))}
            </ul>
          ) : auditRecentQuery.isError ? (
            <ErrorBanner
              title="Couldn't load activity"
              error={auditRecentQuery.error}
              onRetry={() => auditRecentQuery.refetch()}
              retrying={auditRecentQuery.isFetching}
            />
          ) : recentLogs.length === 0 ? (
            <EmptyState
              icon={Activity}
              title="No activity yet"
              description="Once your agent starts handling actions, they'll show up here."
            />
          ) : (
            <ul className="flex flex-col gap-1 flex-1 min-h-0 overflow-y-auto font-mono text-[12px]">
              {recentLogs.map((entry) => {
                const StatusIcon =
                  statusIcons[entry.status ?? "approved"] ?? CheckCircle2;
                return (
                  <li
                    key={entry.id}
                    className="rounded-md border border-[var(--claw-border)] bg-[var(--claw-surface)] px-2.5 py-2 min-w-0 flex gap-2 items-start"
                  >
                    <StatusIcon
                      className="w-3.5 h-3.5 shrink-0 mt-0.5"
                      style={{
                        color: statusColors[entry.status ?? "approved"] ?? "var(--text-muted)",
                      }}
                      strokeWidth={2}
                    />
                    <div className="flex-1 min-w-0">
                      <span className="text-[var(--text-primary)]">{entry.action ?? "—"}</span>
                      <span className="text-[var(--text-muted)]">
                        {" · "}
                        {entry.connector_name ?? "system"}
                      </span>
                    </div>
                    <span className="text-[var(--text-muted)] shrink-0 tabular-nums">
                      {formatRelativeTimestamp(entry.timestamp)}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
      </section>

      <Panel className="p-5 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
          <div>
            <h2 className="text-[13px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
              Integrations
            </h2>
            <p className="text-[15px] font-medium text-[var(--text-primary)] mt-1">
              OpenClaw channel bindings
            </p>
          </div>
          <Link
            to="/channels"
            className="inline-flex items-center justify-center px-4 py-2 rounded-lg text-[13px] font-mono font-medium border border-[var(--claw-border)] text-[var(--claw-accent-bright)] bg-[var(--claw-glow)] hover:bg-[rgba(34,211,238,0.18)] transition-colors shrink-0"
          >
            Configure channels →
          </Link>
        </div>

        {channelsQuery.isLoading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="rounded-lg border border-[var(--claw-border)] bg-[var(--claw-surface)] p-3"
              >
                <Skeleton height="h-4" width="w-1/2" className="mb-2" />
                <Skeleton height="h-3" width="w-3/4" />
              </div>
            ))}
          </div>
        ) : channelsQuery.isError ? (
          <ErrorBanner
            title="Couldn't load channels"
            error={channelsQuery.error}
            onRetry={() => channelsQuery.refetch()}
            retrying={channelsQuery.isFetching}
          />
        ) : channels.length === 0 ? (
          <EmptyState
            icon={MessageSquare}
            title="No channels yet"
            description="Wire Telegram, Discord, Slack, and more — tokens sync into openclaw.json for the gateway."
            action={
              <Link
                to="/channels"
                className="inline-flex px-4 py-2 rounded-lg text-[13px] font-mono font-medium bg-[var(--claw-accent)] text-[var(--bg-primary)] hover:brightness-110"
              >
                Add your first channel
              </Link>
            }
          />
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {channels.map((ch) => (
              <div
                key={ch.id}
                className="rounded-lg border border-[var(--claw-border)] bg-[var(--claw-surface)] p-3 min-w-0"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div
                      className="w-7 h-7 rounded-md flex items-center justify-center shrink-0 border border-[var(--claw-border)]"
                      style={{ background: `${channelColors[ch.channel_type] || "#22d3ee"}18` }}
                    >
                      <Radio
                        className="w-3.5 h-3.5"
                        style={{ color: channelColors[ch.channel_type] || "#22d3ee" }}
                        strokeWidth={2}
                      />
                    </div>
                    <span className="text-[13px] font-medium text-[var(--text-primary)] truncate">
                      {ch.display_name}
                    </span>
                  </div>
                  <span
                    className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border shrink-0"
                    style={{
                      borderColor: ch.is_enabled ? "rgba(52,211,153,0.35)" : "rgba(248,113,113,0.35)",
                      color: ch.is_enabled ? "var(--accent-success)" : "var(--accent-danger)",
                    }}
                  >
                    {ch.is_enabled ? "on" : "off"}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-muted)]">
                  <span className="capitalize">{ch.channel_type}</span>
                  <span>{new Date(ch.updated_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
