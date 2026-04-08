import {
  Plug,
  Activity,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
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
import type {
  ActivityEntry,
  SecurityTimelineEntry,
  ConnectorHealthEntry,
} from "@/types";

const stats = {
  active_connectors: 3,
  total_actions_24h: 142,
  blocked_threats: 7,
  pending_approvals: 2,
};

const mockTimeline: SecurityTimelineEntry[] = [
  { date: "Mar 31", approved: 45, blocked: 2 },
  { date: "Apr 01", approved: 52, blocked: 3 },
  { date: "Apr 02", approved: 38, blocked: 1 },
  { date: "Apr 03", approved: 61, blocked: 4 },
  { date: "Apr 04", approved: 49, blocked: 2 },
  { date: "Apr 05", approved: 55, blocked: 3 },
  { date: "Apr 06", approved: 42, blocked: 1 },
];

const mockActivity: ActivityEntry[] = [
  { id: "1", connector: "Canvas LMS", action: "get_assignments", status: "approved", timestamp: "2 min ago" },
  { id: "2", connector: "Gmail", action: "search_emails", status: "approved", timestamp: "5 min ago" },
  { id: "3", connector: "Robinhood", action: "execute_trade", status: "blocked", timestamp: "12 min ago" },
  { id: "4", connector: "Google Calendar", action: "create_event", status: "pending", timestamp: "18 min ago" },
  { id: "5", connector: "Canvas LMS", action: "get_grades", status: "approved", timestamp: "25 min ago" },
  { id: "6", connector: "Gmail", action: "send_email", status: "pending", timestamp: "31 min ago" },
];

const mockHealth: ConnectorHealthEntry[] = [
  { id: "1", name: "Canvas LMS", type: "canvas", status: "healthy", uptime: 99.9, last_check: "1 min ago" },
  { id: "2", name: "Google Workspace", type: "google", status: "healthy", uptime: 99.7, last_check: "2 min ago" },
  { id: "3", name: "Robinhood Crypto", type: "robinhood", status: "degraded", uptime: 95.2, last_check: "3 min ago" },
];

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

const CHART_APPROVED = "#0a84ff";
const CHART_BLOCKED = "#ff453a";

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
      className="rounded-[10px] border px-3 py-2.5 text-[13px] shadow-lg"
      style={{
        backgroundColor: "var(--bg-tertiary)",
        borderColor: "var(--border-primary)",
        color: "var(--text-primary)",
        boxShadow: "var(--shadow-card)",
      }}
    >
      <p className="text-[12px] text-[var(--text-muted)] mb-1.5">{label}</p>
      <div className="space-y-1">
        {payload.map((p) => (
          <div
            key={String(p.dataKey ?? p.name)}
            className="flex items-center justify-between gap-6"
          >
            <span style={{ color: "var(--text-secondary)" }}>{p.name}</span>
            <span className="font-medium tabular-nums">{p.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number;
  icon: LucideIcon;
  accent: string;
}) {
  return (
    <div
      className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-5 min-w-0 flex flex-col gap-3"
      style={{
        backgroundColor: "var(--bg-secondary)",
        boxShadow: "var(--shadow-card)",
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <span className="text-[13px] font-medium leading-snug text-[var(--text-secondary)]">
          {label}
        </span>
        <div
          className="w-10 h-10 rounded-[12px] flex items-center justify-center shrink-0"
          style={{
            backgroundColor: `color-mix(in srgb, ${accent} 20%, transparent)`,
          }}
        >
          <Icon className="w-5 h-5" style={{ color: accent }} strokeWidth={2} />
        </div>
      </div>
      <p className="text-[34px] font-semibold tracking-tight leading-none text-[var(--text-primary)] tabular-nums">
        {value}
      </p>
    </div>
  );
}

export default function Dashboard() {
  return (
    <div className="space-y-10 min-w-0">
      <header className="space-y-1">
        <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)] md:text-[32px]">
          Dashboard
        </h1>
        <p className="text-[15px] text-[var(--text-secondary)] max-w-xl leading-relaxed">
          Real-time monitoring of agent activity and security events.
        </p>
      </header>

      <section aria-label="Summary">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 md:gap-5">
          <StatCard
            label="Active Connectors"
            value={stats.active_connectors}
            icon={Plug}
            accent="var(--accent-success)"
          />
          <StatCard
            label="Actions (24h)"
            value={stats.total_actions_24h}
            icon={Activity}
            accent="var(--accent-primary)"
          />
          <StatCard
            label="Blocked Threats"
            value={stats.blocked_threats}
            icon={ShieldAlert}
            accent="var(--accent-danger)"
          />
          <StatCard
            label="Pending Approvals"
            value={stats.pending_approvals}
            icon={Clock}
            accent="var(--accent-warning)"
          />
        </div>
      </section>

      <section
        aria-label="Charts and activity"
        className="grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-8 items-stretch min-w-0"
      >
        <div
          className="lg:col-span-8 rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7 min-w-0 flex flex-col"
          style={{
            backgroundColor: "var(--bg-secondary)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-2 mb-5 shrink-0">
            <div>
              <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)]">
                Security events
              </h2>
              <p className="text-[13px] text-[var(--text-muted)] mt-0.5">
                Last 7 days — approved vs blocked
              </p>
            </div>
            <div className="flex items-center gap-4 text-[12px] text-[var(--text-muted)] shrink-0">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: CHART_APPROVED }} />
                Approved
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: CHART_BLOCKED }} />
                Blocked
              </span>
            </div>
          </div>
          {/* Fixed height + min-h-0 prevents Recharts from overflowing and overlapping siblings */}
          <div className="h-[280px] w-full min-h-0 min-w-0 flex-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mockTimeline} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="approvedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={CHART_APPROVED} stopOpacity={0.35} />
                    <stop offset="95%" stopColor={CHART_APPROVED} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={CHART_BLOCKED} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={CHART_BLOCKED} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="date"
                  tick={{ fill: "rgba(235,235,245,0.45)", fontSize: 12 }}
                  tickLine={false}
                  axisLine={false}
                  dy={8}
                />
                <YAxis
                  tick={{ fill: "rgba(235,235,245,0.45)", fontSize: 12 }}
                  tickLine={false}
                  axisLine={false}
                  width={36}
                />
                <Tooltip
                  content={<ChartTooltip />}
                  cursor={{ stroke: "rgba(255,255,255,0.12)", strokeWidth: 1 }}
                />
                <Area
                  type="monotone"
                  dataKey="approved"
                  name="Approved"
                  stroke={CHART_APPROVED}
                  fill="url(#approvedGrad)"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, strokeWidth: 0 }}
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  name="Blocked"
                  stroke={CHART_BLOCKED}
                  fill="url(#blockedGrad)"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, strokeWidth: 0 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div
          className="lg:col-span-4 rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7 min-w-0 flex flex-col min-h-[320px] lg:min-h-0"
          style={{
            backgroundColor: "var(--bg-secondary)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div className="mb-4 shrink-0">
            <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)]">
              Recent activity
            </h2>
            <p className="text-[13px] text-[var(--text-muted)] mt-0.5">
              Latest connector actions
            </p>
          </div>
          <ul className="flex flex-col gap-2 flex-1 min-h-0 overflow-y-auto pr-1 -mr-1">
            {mockActivity.map((entry) => {
              const StatusIcon = statusIcons[entry.status];
              return (
                <li
                  key={entry.id}
                  className="rounded-[12px] border border-[var(--border-subtle)] bg-[rgba(255,255,255,0.03)] px-3 py-3 min-w-0"
                >
                  <div className="flex gap-3 min-w-0">
                    <StatusIcon
                      className="w-[18px] h-[18px] shrink-0 mt-0.5"
                      style={{ color: statusColors[entry.status] }}
                      strokeWidth={2}
                    />
                    <div className="flex-1 min-w-0 flex flex-col gap-1.5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
                      <div className="min-w-0">
                        <p className="text-[15px] font-medium text-[var(--text-primary)] break-words">
                          {entry.action}
                        </p>
                        <p className="text-[13px] text-[var(--text-muted)] mt-0.5 break-words">
                          {entry.connector}
                        </p>
                      </div>
                      <span className="text-[12px] text-[var(--text-muted)] tabular-nums whitespace-nowrap shrink-0 sm:pt-0.5 sm:text-right">
                        {entry.timestamp}
                      </span>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      </section>

      <section
        aria-label="Connector health"
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7"
        style={{
          backgroundColor: "var(--bg-secondary)",
          boxShadow: "var(--shadow-card)",
        }}
      >
        <div className="mb-5">
          <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)]">
            Connector health
          </h2>
          <p className="text-[13px] text-[var(--text-muted)] mt-0.5">
            Uptime and last successful check
          </p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {mockHealth.map((c) => (
            <div
              key={c.id}
              className="rounded-[14px] border border-[var(--border-subtle)] p-4 min-w-0 bg-[var(--bg-tertiary)]"
            >
              <div className="flex items-start justify-between gap-3 mb-3">
                <span className="text-[15px] font-medium text-[var(--text-primary)] leading-snug break-words">
                  {c.name}
                </span>
                <span
                  className="text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-full shrink-0"
                  style={{
                    backgroundColor:
                      c.status === "healthy"
                        ? "rgba(48,209,88,0.18)"
                        : c.status === "degraded"
                          ? "rgba(255,159,10,0.18)"
                          : "rgba(255,69,58,0.18)",
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
              <div className="flex flex-wrap items-center justify-between gap-2 text-[13px] text-[var(--text-muted)]">
                <span>Uptime {c.uptime}%</span>
                <span className="tabular-nums">{c.last_check}</span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
