import { useState, useEffect } from "react";
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
  Loader2,
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
  ChannelResponse,
  OpenClawStatus,
} from "@/types";
import { getChannels, getOpenClawStatus } from "@/services/api";

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
  { id: "1", connector: "Telegram", action: "message_received", status: "approved", timestamp: "2 min ago" },
  { id: "2", connector: "Discord", action: "dm_response", status: "approved", timestamp: "5 min ago" },
  { id: "3", connector: "WebChat", action: "chat_session", status: "approved", timestamp: "12 min ago" },
  { id: "4", connector: "Slack", action: "channel_reply", status: "pending", timestamp: "18 min ago" },
  { id: "5", connector: "WhatsApp", action: "voice_message", status: "approved", timestamp: "25 min ago" },
  { id: "6", connector: "Telegram", action: "group_message", status: "blocked", timestamp: "31 min ago" },
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
  value: number | string;
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

const channelColors: Record<string, string> = {
  telegram: "#0088cc",
  discord: "#5865F2",
  slack: "#4A154B",
  whatsapp: "#25D366",
  signal: "#3A76F0",
  webchat: "#0a84ff",
};

export default function Dashboard() {
  const [clawStatus, setClawStatus] = useState<OpenClawStatus | null>(null);
  const [channels, setChannels] = useState<ChannelResponse[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getOpenClawStatus().catch(() => null),
      getChannels().catch(() => []),
    ]).then(([status, chs]) => {
      setClawStatus(status);
      setChannels(chs);
      setLoading(false);
    });
  }, []);

  const activeChannels = channels.filter((c) => c.is_enabled);

  return (
    <div className="space-y-10 min-w-0">
      <header className="space-y-1">
        <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)] md:text-[32px]">
          Dashboard
        </h1>
        <p className="text-[15px] text-[var(--text-secondary)] max-w-xl leading-relaxed">
          Real-time monitoring of your AI agent, channels, and security events.
        </p>
      </header>

      <section aria-label="Summary">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 md:gap-5">
          <StatCard
            label="Gateway Status"
            value={loading ? "..." : clawStatus?.gateway_online ? "Online" : "Offline"}
            icon={clawStatus?.gateway_online ? Wifi : WifiOff}
            accent={clawStatus?.gateway_online ? "var(--accent-success)" : "var(--accent-danger)"}
          />
          <StatCard
            label="Active Channels"
            value={loading ? "..." : activeChannels.length}
            icon={Radio}
            accent="var(--accent-primary)"
          />
          <StatCard
            label="Messages Today"
            value={142}
            icon={Activity}
            accent="var(--accent-success)"
          />
          <StatCard
            label="Blocked Threats"
            value={7}
            icon={ShieldAlert}
            accent="var(--accent-danger)"
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
                Last 7 days &mdash; approved vs blocked
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
              Latest channel events
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
        aria-label="Channel status"
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7"
        style={{
          backgroundColor: "var(--bg-secondary)",
          boxShadow: "var(--shadow-card)",
        }}
      >
        <div className="mb-5">
          <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)]">
            Channel status
          </h2>
          <p className="text-[13px] text-[var(--text-muted)] mt-0.5">
            Connected messaging platforms via OpenClaw
          </p>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-5 h-5 animate-spin text-[var(--text-muted)]" />
          </div>
        ) : channels.length === 0 ? (
          <div className="text-center py-8">
            <MessageSquare className="w-8 h-8 text-[var(--text-muted)] mx-auto mb-2" strokeWidth={1.5} />
            <p className="text-[14px] text-[var(--text-muted)]">
              No channels connected yet. Go to <span className="text-[var(--accent-primary)]">Channels</span> to get started.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
            {channels.map((ch) => (
              <div
                key={ch.id}
                className="rounded-[14px] border border-[var(--border-subtle)] p-4 min-w-0 bg-[var(--bg-tertiary)]"
              >
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div
                      className="w-8 h-8 rounded-[8px] flex items-center justify-center shrink-0"
                      style={{
                        backgroundColor: `${channelColors[ch.channel_type] || "#0a84ff"}22`,
                      }}
                    >
                      <Radio
                        className="w-4 h-4"
                        style={{ color: channelColors[ch.channel_type] || "#0a84ff" }}
                        strokeWidth={1.75}
                      />
                    </div>
                    <span className="text-[15px] font-medium text-[var(--text-primary)] leading-snug break-words">
                      {ch.display_name}
                    </span>
                  </div>
                  <span
                    className="text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-full shrink-0"
                    style={{
                      backgroundColor: ch.is_enabled
                        ? "rgba(48,209,88,0.18)"
                        : "rgba(255,69,58,0.18)",
                      color: ch.is_enabled
                        ? "var(--accent-success)"
                        : "var(--accent-danger)",
                    }}
                  >
                    {ch.is_enabled ? "Active" : "Disabled"}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[13px] text-[var(--text-muted)]">
                  <span className="capitalize">{ch.channel_type}</span>
                  <span className="tabular-nums">
                    {new Date(ch.updated_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
