/**
 * Dashboard page: stat cards, the pending-approval queue, the security-events chart, the recent
 * activity feed, token usage and connector health, polled every 30s.
 *
 * Why it exists: It is the first page after sign-in and the one place every source is loaded
 * together, with each fetch failing independently so one dead source does not blank the others.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Plug,
  Activity,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldQuestion,
  Loader2,
  RefreshCw,
  Coins,
  type LucideIcon,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type {
  AuditLog,
  AuditStats,
  Connector,
  ConnectorHealthEntry,
  PendingApproval,
  UsageSummary,
} from "@/types";
import {
  decideApproval,
  getAuditLogs,
  getAuditStats,
  getConnectorHealth,
  getConnectors,
  getPendingApprovals,
  getUsageSummary,
} from "@/services/api";
import UsagePanel from "@/components/UsagePanel";
import { formatCost, formatTokens } from "@/components/usageFormat";
// Countdown logic lives beside Chat's ApprovalCard so both approval queues
// expire in lockstep with the server-side TTL.
import { formatCountdown, useCountdown } from "@/pages/approvalCountdown";
import { useResolvedColors } from "@/hooks/useResolvedColors";

const FEED_LIMIT = 6;
const POLL_INTERVAL_MS = 30_000;

const statusColors = {
  approved: "var(--accent-success)",
  blocked: "var(--accent-danger)",
  pending: "var(--accent-warning)",
};

const statusIcons = {
  approved: CheckCircle2,
  blocked: XCircle,
  pending: Clock,
};

function formatRelative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diffSec = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return new Date(iso).toLocaleDateString();
}

function ApprovalRow({
  approval,
  onDecide,
}: {
  approval: PendingApproval;
  onDecide: (approved: boolean) => Promise<void>;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const remaining = useCountdown(approval.expires_at);
  // The server enforces the TTL, so a click after this point would 404 —
  // disable the buttons instead of letting the user walk into that.
  const expired = remaining !== null && remaining <= 0;

  const decide = async (approved: boolean) => {
    setPending(true);
    setError(null);
    try {
      await onDecide(approved);
    } catch (err) {
      setError((err as Error).message);
      setPending(false);
    }
  };

  return (
    <div
      className="rounded-[10px] p-3"
      style={{
        background: "var(--claw-surface)",
        border: "1px solid var(--claw-border)",
        opacity: expired ? 0.75 : 1,
      }}
    >
      {/* Backend-flagged risk: the request was shaped by external/untrusted
          content. Danger colors, ABOVE the action row — placing it below the
          buttons meant the reader reached Approve before the warning. */}
      {approval.risk_note && (
        <div
          className="flex items-start gap-2 p-2.5 rounded-[8px] mb-3"
          style={{
            background: "var(--fill-danger)",
            border: "1px solid var(--border-danger)",
          }}
        >
          <AlertTriangle
            className="w-4 h-4 mt-0.5 shrink-0"
            style={{ color: "var(--accent-danger)" }}
          />
          <div className="min-w-0">
            <div className="eyebrow" style={{ color: "var(--accent-danger)" }}>
              Risk warning
            </div>
            <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
              {approval.risk_note}
            </p>
          </div>
        </div>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
            <span className="mono-tag">{approval.tool_name}</span>
            {remaining !== null && (
              <span
                className="mono-tag inline-flex items-center gap-1 ml-2"
                style={{
                  color: expired ? "var(--accent-danger)" : "var(--accent-warning)",
                }}
              >
                <Clock className="w-3 h-3" />
                {expired ? "expired" : `expires in ${formatCountdown(remaining)}`}
              </span>
            )}
          </p>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
            {expired
              ? "This request expired without a decision. Ask the agent again if the action is still needed."
              : approval.reason}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={pending || expired}
            onClick={() => void decide(true)}
            className="px-3 rounded-[8px] text-xs font-semibold disabled:opacity-50 inline-flex items-center gap-1.5"
            style={{
              minHeight: 36,
              background: "var(--accent-success)",
              color: "var(--text-on-accent)",
            }}
          >
            {pending ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
            Approve
          </button>
          <button
            type="button"
            disabled={pending || expired}
            onClick={() => void decide(false)}
            className="px-3 rounded-[8px] text-xs font-medium disabled:opacity-50"
            style={{
              minHeight: 36,
              border: "1px solid var(--border-danger)",
              color: "var(--accent-danger)",
            }}
          >
            Deny
          </button>
        </div>
      </div>
      {Object.keys(approval.arguments ?? {}).length > 0 && (
        <pre
          className="text-xs mt-2 p-2 rounded-[8px] overflow-x-auto"
          style={{
            background: "var(--bg-primary)",
            color: "var(--text-secondary)",
            border: "1px solid var(--border-subtle)",
          }}
        >
          {JSON.stringify(approval.arguments, null, 2)}
        </pre>
      )}
      {error && (
        <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * Status tints, as token triples. The previous version took a hex string and
 * built its fill by appending an alpha suffix (`${color}1f`), which no
 * custom property can survive — `var(--accent-success)1f` is not a color and
 * the fill silently disappeared.
 */
const TONES = {
  success: {
    fg: "var(--accent-success)",
    fill: "var(--fill-success)",
    border: "var(--border-success)",
  },
  accent: {
    fg: "var(--accent-primary)",
    fill: "var(--accent-glow)",
    border: "var(--border-accent)",
  },
  danger: {
    fg: "var(--accent-danger)",
    fill: "var(--fill-danger)",
    border: "var(--border-danger)",
  },
  warning: {
    fg: "var(--accent-warning)",
    fill: "var(--fill-warning)",
    border: "var(--border-warning)",
  },
} as const;

type Tone = keyof typeof TONES;

function StatCard({
  label,
  value,
  icon: Icon,
  tone,
  eyebrow,
}: {
  label: string;
  value: number | string;
  icon: LucideIcon;
  tone: Tone;
  eyebrow: string;
}) {
  const { fg, fill, border } = TONES[tone];
  return (
    <div
      className="rounded-[14px] p-5 transition-all duration-200"
      style={{
        background: "var(--claw-panel)",
        border: "1px solid var(--claw-border)",
        boxShadow: "var(--shadow-card)",
      }}
      onMouseOver={(e) => {
        e.currentTarget.style.borderColor = "var(--border-accent-strong)";
        e.currentTarget.style.transform = "translateY(-2px)";
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.borderColor = "var(--claw-border)";
        e.currentTarget.style.transform = "translateY(0)";
      }}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex flex-col gap-1">
          <span className="eyebrow">{eyebrow}</span>
          <span className="text-sm" style={{ color: "var(--text-secondary)" }}>
            {label}
          </span>
        </div>
        <div
          aria-hidden
          className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
          style={{ background: fill, border: `1px solid ${border}` }}
        >
          <Icon size={16} strokeWidth={2} style={{ color: fg }} />
        </div>
      </div>
      <p className="metric">{value}</p>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [health, setHealth] = useState<ConnectorHealthEntry[]>([]);
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // `background` refreshes (polling, post-approval) skip the loading state
  // so the page does not flicker every 30 seconds. A foreground refresh is
  // started by `reload` below, which raises the loading state in the click;
  // on mount it already starts out true. Nothing here touches state before
  // the first await, so the mount effect does not render twice.
  const load = useCallback(async (background = false) => {
    const failures: string[] = [];
    const fallback = <T,>(label: string, empty: T) => (err: Error): T => {
      failures.push(label);
      console.error(`dashboard: ${label} failed`, err);
      return empty;
    };
    try {
      const [
        statsResult,
        logResult,
        connResult,
        healthResult,
        approvalResult,
        usageResult,
      ] = await Promise.all([
          getAuditStats().catch(fallback("stats", null as AuditStats | null)),
          getAuditLogs({ limit: FEED_LIMIT }).catch(
            fallback("audit logs", [] as AuditLog[])
          ),
          getConnectors().catch(fallback("connectors", [] as Connector[])),
          getConnectorHealth().catch(
            fallback("connector health", [] as ConnectorHealthEntry[])
          ),
          getPendingApprovals().catch(
            fallback("pending approvals", [] as PendingApproval[])
          ),
          getUsageSummary().catch(fallback("usage", null as UsageSummary | null)),
        ]);
      // On a failed stats fetch keep the previous numbers on screen rather
      // than blanking them; the banner below reports the failure.
      if (statsResult) setStats(statsResult);
      if (usageResult) setUsage(usageResult);
      setLogs(logResult);
      setConnectors(connResult);
      setHealth(healthResult);
      setApprovals(approvalResult);
      // Replaces the previous run's banner once this run has an answer, so a
      // background poll against a still-failing source does not blink it off
      // and back on.
      setLoadError(
        failures.length > 0
          ? `Some data could not be loaded (${failures.join(", ")}).`
          : null,
      );
    } finally {
      if (!background) setLoading(false);
    }
  }, []);

  // Refresh and Retry: an explicit reload clears the banner and shows the
  // loading state straight away, as the reader asked for it.
  const reload = () => {
    setLoading(true);
    setLoadError(null);
    void load();
  };

  useEffect(() => {
    void load();
    const interval = setInterval(() => void load(true), POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [load]);

  const handleApproval = async (actionId: string, approved: boolean) => {
    await decideApproval(actionId, approved);
    setApprovals((prev) => prev.filter((a) => a.action_id !== actionId));
    // Refresh stats and the feed so the decided action shows up immediately.
    void load(true);
  };

  const timeline = useMemo(
    () =>
      (stats?.by_day ?? []).map((d) => {
        const parsed = new Date(`${d.date}T00:00:00`);
        return {
          date: Number.isNaN(parsed.getTime())
            ? d.date
            : parsed.toLocaleDateString(undefined, {
                month: "short",
                day: "2-digit",
              }),
          approved: d.approved,
          blocked: d.blocked,
        };
      }),
    [stats]
  );
  // recharts writes these onto SVG presentation attributes, which never
  // substitute var(), so the tokens are resolved to real colors first and
  // re-resolved whenever the theme changes.
  const chart = useResolvedColors({
    "--chart-ok": "#22d3ee",
    "--chart-block": "#f87171",
    "--chart-axis": "#a1a1aa",
    "--claw-panel": "#131316",
    "--claw-border": "rgba(63,63,70,0.65)",
    "--text-primary": "#f4f4f5",
  });

  const timelineDays = stats?.by_day.length ?? 7;
  const recentActivity = useMemo(() => logs.slice(0, FEED_LIMIT), [logs]);

  const activeConnectors = connectors.filter((c) => c.is_active).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div>
          <div className="eyebrow mb-2">Control center</div>
          <h1 style={{ color: "var(--text-primary)" }}>Gateway &amp; workspace</h1>
          <p
            className="text-sm mt-1.5 max-w-2xl"
            style={{ color: "var(--text-secondary)" }}
          >
            Live agent activity, blocked actions, pending approvals, and
            connector health — everything the agent does flows through the
            policy layer and lands here. Refreshes every{" "}
            {POLL_INTERVAL_MS / 1000}s.
          </p>
        </div>
        <button
          type="button"
          onClick={reload}
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 px-3.5 rounded-[10px] text-sm font-medium disabled:opacity-50 shrink-0 self-start"
          style={{
            minHeight: 44,
            background: "var(--bg-input)",
            border: "1px solid var(--claw-border)",
            color: "var(--text-primary)",
          }}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
          Refresh
        </button>
      </div>

      {/* Load error banner */}
      {loadError && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-3 rounded-[12px] px-4 py-3"
          style={{
            background: "var(--fill-warning)",
            border: "1px solid var(--border-warning)",
          }}
        >
          <div className="flex items-center gap-2 min-w-0">
            <AlertTriangle
              className="w-4 h-4 shrink-0"
              style={{ color: "var(--accent-warning)" }}
            />
            <span className="text-sm truncate" style={{ color: "var(--text-secondary)" }}>
              {loadError}
            </span>
          </div>
          <button
            type="button"
            onClick={reload}
            className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-[8px] shrink-0"
            style={{
              border: "1px solid var(--border-warning)",
              color: "var(--accent-warning)",
            }}
          >
            <RefreshCw className="w-3 h-3" />
            Retry
          </button>
        </div>
      )}

      {/* Pending approvals — the consent queue. Shown above everything
          else because these are actions waiting on the user. */}
      {approvals.length > 0 && (
        <div
          className="rounded-[14px] p-5"
          style={{
            background: "var(--claw-panel)",
            border: "1px solid var(--border-warning)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div className="flex items-center gap-2 mb-1">
            <ShieldQuestion className="w-4 h-4" style={{ color: "var(--accent-warning)" }} />
            <div className="eyebrow" style={{ color: "var(--accent-warning)" }}>
              Awaiting your approval
            </div>
          </div>
          <h2 className="mb-1">
            {approvals.length} action{approvals.length === 1 ? "" : "s"} need
            {approvals.length === 1 ? "s" : ""} a decision
          </h2>
          <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
            The agent will not run these until you approve them. Undecided
            requests expire automatically.
          </p>
          <div className="space-y-3">
            {approvals.map((approval) => (
              <ApprovalRow
                key={approval.action_id}
                approval={approval}
                onDecide={(approved) =>
                  handleApproval(approval.action_id, approved)
                }
              />
            ))}
          </div>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        <StatCard
          eyebrow="Connectors"
          label="Active"
          value={loading ? "…" : activeConnectors}
          icon={Plug}
          tone="success"
        />
        <StatCard
          eyebrow="Actions"
          label="Last 24h"
          value={loading ? "…" : stats ? stats.total_actions_24h : "—"}
          icon={Activity}
          tone="accent"
        />
        <StatCard
          eyebrow="Blocked"
          label="Last 24h"
          value={loading ? "…" : stats ? stats.blocked_24h : "—"}
          icon={ShieldAlert}
          tone="danger"
        />
        <StatCard
          eyebrow="Pending"
          label="Awaiting approval"
          value={loading ? "…" : stats ? stats.pending_approvals : "—"}
          icon={Clock}
          tone="warning"
        />
        <StatCard
          eyebrow="Tokens today"
          label={
            usage
              ? `Est. cost ${formatCost(usage.windows.today.estimated_cost_usd)}`
              : "Est. cost —"
          }
          value={
            loading && !usage
              ? "…"
              : usage
                ? formatTokens(usage.windows.today.total_tokens)
                : "—"
          }
          icon={Coins}
          tone="accent"
        />
      </div>

      {/* Charts + Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Timeline */}
        <div
          className="lg:col-span-2 rounded-[14px] p-5"
          style={{
            background: "var(--claw-panel)",
            border: "1px solid var(--claw-border)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div className="eyebrow mb-1">Policy timeline</div>
          <h2 className="mb-4">Security events · last {timelineDays} days</h2>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="approvedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={chart["--chart-ok"]} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={chart["--chart-ok"]} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={chart["--chart-block"]} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={chart["--chart-block"]} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="date"
                stroke={chart["--chart-axis"]}
                fontSize={11}
                tickLine={false}
                axisLine={false}
                style={{ fontFamily: "var(--font-mono)" }}
              />
              <YAxis
                stroke={chart["--chart-axis"]}
                fontSize={11}
                tickLine={false}
                axisLine={false}
                style={{ fontFamily: "var(--font-mono)" }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: chart["--claw-panel"],
                  border: `1px solid ${chart["--claw-border"]}`,
                  borderRadius: "10px",
                  color: chart["--text-primary"],
                  fontSize: "13px",
                  fontFamily: "var(--font-mono)",
                }}
              />
              <Area
                type="monotone"
                dataKey="approved"
                stroke={chart["--chart-ok"]}
                fill="url(#approvedGrad)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke={chart["--chart-block"]}
                fill="url(#blockedGrad)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Activity Feed */}
        <div
          className="rounded-[14px] p-5"
          style={{
            background: "var(--claw-panel)",
            border: "1px solid var(--claw-border)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div className="eyebrow mb-1">Live feed</div>
          <h2 className="mb-4">Recent activity</h2>
          <div className="space-y-3">
            {loading && (
              <p role="status" className="text-sm" style={{ color: "var(--text-muted)" }}>
                Loading...
              </p>
            )}
            {!loading && recentActivity.length === 0 && (
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                No agent activity yet.
              </p>
            )}
            {!loading &&
              recentActivity.map((entry) => {
                const StatusIcon = statusIcons[entry.status];
                return (
                  <div
                    key={entry.id}
                    className="flex items-start gap-3 py-2 border-b last:border-b-0"
                    style={{ borderColor: "var(--border-primary)" }}
                  >
                    <StatusIcon
                      className="w-4 h-4 mt-0.5 shrink-0"
                      style={{ color: statusColors[entry.status] }}
                    />
                    <div className="flex-1 min-w-0">
                      <p
                        className="text-sm font-medium truncate"
                        style={{ color: "var(--text-primary)" }}
                      >
                        {entry.action}
                      </p>
                      <p
                        className="text-xs"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {entry.connector_name}
                      </p>
                    </div>
                    <span
                      className="text-xs shrink-0"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {formatRelative(entry.timestamp)}
                    </span>
                  </div>
                );
              })}
          </div>
        </div>
      </div>

      <UsagePanel usage={usage} loading={loading} />

      {/* Connector Health */}
      <div
        className="rounded-[14px] p-5"
        style={{
          background: "var(--claw-panel)",
          border: "1px solid var(--claw-border)",
          boxShadow: "var(--shadow-card)",
        }}
      >
        <div className="eyebrow mb-1">Integrations</div>
        <h2 className="mb-4">Connector health</h2>
        {!loading && health.length === 0 && (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            No connectors configured. Add one from the Connectors page.
          </p>
        )}
        {loading && (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Loading...
          </p>
        )}
        {!loading && health.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
            {health.map((c) => {
              const lastCheckLabel =
                c.last_check === "Never"
                  ? "Never"
                  : new Date(c.last_check).toLocaleString();
              return (
                <div
                  key={c.id}
                  className="rounded-lg border p-4"
                  style={{
                    backgroundColor: "var(--bg-primary)",
                    borderColor: "var(--border-primary)",
                  }}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className="text-sm font-medium truncate"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {c.name}
                    </span>
                    <span
                      className="text-xs px-2 py-0.5 rounded-full font-medium shrink-0"
                      style={{
                        backgroundColor:
                          c.status === "healthy"
                            ? "var(--fill-success)"
                            : c.status === "degraded"
                            ? "var(--fill-warning)"
                            : "var(--fill-danger)",
                        color:
                          c.status === "healthy"
                            ? "var(--accent-success)"
                            : c.status === "degraded"
                            ? "var(--accent-warning)"
                            : "var(--accent-danger)",
                      }}
                    >
                      {c.status}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span
                      className="text-xs"
                      style={{ color: "var(--text-muted)" }}
                    >
                      Uptime: {c.uptime}%
                    </span>
                    <span
                      className="text-xs truncate"
                      style={{ color: "var(--text-muted)" }}
                      title={lastCheckLabel}
                    >
                      {lastCheckLabel}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
