import { useEffect, useMemo, useState } from "react";
import {
  Plug,
  Activity,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
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
  Connector,
  ConnectorHealthEntry,
  SecurityTimelineEntry,
} from "@/types";
import {
  getAuditLogs,
  getConnectorHealth,
  getConnectors,
  getMe,
} from "@/services/api";

const TIMELINE_DAYS = 7;
const FEED_LIMIT = 6;

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

function bucketByDay(logs: AuditLog[], days: number): SecurityTimelineEntry[] {
  const now = new Date();
  const buckets: SecurityTimelineEntry[] = [];
  const keyByDay = new Map<string, SecurityTimelineEntry>();

  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const label = d.toLocaleDateString(undefined, { month: "short", day: "2-digit" });
    const entry: SecurityTimelineEntry = { date: label, approved: 0, blocked: 0 };
    buckets.push(entry);
    keyByDay.set(key, entry);
  }

  for (const log of logs) {
    const key = new Date(log.timestamp).toISOString().slice(0, 10);
    const bucket = keyByDay.get(key);
    if (!bucket) continue;
    if (log.status === "approved") bucket.approved += 1;
    else if (log.status === "blocked") bucket.blocked += 1;
  }
  return buckets;
}

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

function StatCard({
  label,
  value,
  icon: Icon,
  color,
  eyebrow,
}: {
  label: string;
  value: number | string;
  icon: any;
  color: string;
  eyebrow: string;
}) {
  return (
    <div
      className="rounded-[14px] p-5"
      style={{
        background: "var(--claw-panel)",
        border: "1px solid var(--claw-border)",
        boxShadow: "var(--shadow-card)",
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
          className="w-8 h-8 rounded-[8px] flex items-center justify-center"
          style={{
            background: `${color}1f`,
            border: `1px solid ${color}40`,
          }}
        >
          <Icon size={16} strokeWidth={2} style={{ color }} />
        </div>
      </div>
      <p className="metric">{value}</p>
    </div>
  );
}

export default function Dashboard() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [health, setHealth] = useState<ConnectorHealthEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const user = await getMe();
        if (cancelled) return;
        const [logResult, connResult, healthResult] = await Promise.all([
          getAuditLogs(user.id, { limit: 500 }).catch((): AuditLog[] => []),
          getConnectors(user.id).catch((): Connector[] => []),
          getConnectorHealth(user.id).catch((): ConnectorHealthEntry[] => []),
        ]);
        if (cancelled) return;
        setLogs(logResult);
        setConnectors(connResult);
        setHealth(healthResult);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const timeline = useMemo(() => bucketByDay(logs, TIMELINE_DAYS), [logs]);
  const recentActivity = useMemo(() => logs.slice(0, FEED_LIMIT), [logs]);
  const counts24h = useMemo(() => {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    let total = 0;
    let blocked = 0;
    let pending = 0;
    for (const l of logs) {
      if (new Date(l.timestamp).getTime() < cutoff) continue;
      total += 1;
      if (l.status === "blocked") blocked += 1;
      else if (l.status === "pending") pending += 1;
    }
    return { total, blocked, pending };
  }, [logs]);

  const activeConnectors = connectors.filter((c) => c.is_active).length;

  return (
    <div className="space-y-6">
      <div>
        <div className="eyebrow mb-2">Control center</div>
        <h1 style={{ color: "var(--text-primary)" }}>Gateway &amp; workspace</h1>
        <p
          className="text-sm mt-1.5 max-w-2xl"
          style={{ color: "var(--text-secondary)" }}
        >
          Mirror of the native OpenClaw dashboard. Live agent activity, blocked
          actions, and connector health — all flowing through the policy layer.
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          eyebrow="Connectors"
          label="Active"
          value={loading ? "…" : activeConnectors}
          icon={Plug}
          color="#34d399"
        />
        <StatCard
          eyebrow="Actions"
          label="Last 24h"
          value={loading ? "…" : counts24h.total}
          icon={Activity}
          color="#22d3ee"
        />
        <StatCard
          eyebrow="Blocked"
          label="Last 24h"
          value={loading ? "…" : counts24h.blocked}
          icon={ShieldAlert}
          color="#f87171"
        />
        <StatCard
          eyebrow="Pending"
          label="Last 24h"
          value={loading ? "…" : counts24h.pending}
          icon={Clock}
          color="#fbbf24"
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
          <h2 className="mb-4">Security events · last {TIMELINE_DAYS} days</h2>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="approvedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f87171" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="date"
                stroke="#a1a1aa"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                style={{ fontFamily: "var(--font-mono)" }}
              />
              <YAxis
                stroke="#a1a1aa"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                style={{ fontFamily: "var(--font-mono)" }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#131316",
                  border: "1px solid rgba(63,63,70,0.65)",
                  borderRadius: "10px",
                  color: "#f4f4f5",
                  fontSize: "13px",
                  fontFamily: "var(--font-mono)",
                }}
              />
              <Area
                type="monotone"
                dataKey="approved"
                stroke="#22d3ee"
                fill="url(#approvedGrad)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="#f87171"
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
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
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
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
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
                            ? "rgba(34,197,94,0.1)"
                            : c.status === "degraded"
                            ? "rgba(245,158,11,0.1)"
                            : "rgba(239,68,68,0.1)",
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
