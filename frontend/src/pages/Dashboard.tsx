import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
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
import type {
  ActivityEntry,
  SecurityTimelineEntry,
  ChannelResponse,
  OpenClawStatus,
} from "@/types";
import { getChannels, getOpenClawStatus, getStoredUser } from "@/services/api";

const GATEWAY_BASE = "http://127.0.0.1:18789";
const GATEWAY_OPEN = `${GATEWAY_BASE}/`;

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

const CHART_OK = "#22d3ee";
const CHART_BLOCK = "#f87171";

const statusColors: Record<string, string> = {
  approved: "var(--accent-success)",
  blocked: "var(--accent-danger)",
  pending: "var(--accent-warning)",
};

const statusIcons = {
  approved: CheckCircle2,
  blocked: XCircle,
  pending: Clock,
};

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
}: {
  label: string;
  value: number | string;
  icon: LucideIcon;
  accent: string;
}) {
  return (
    <Panel className="p-4 flex flex-col gap-2 min-w-0">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)] truncate">
          {label}
        </span>
        <Icon className="w-4 h-4 shrink-0" style={{ color: accent }} strokeWidth={2} />
      </div>
      <p className="text-[26px] font-semibold tabular-nums tracking-tight text-[var(--text-primary)] leading-none font-mono">
        {value}
      </p>
    </Panel>
  );
}

const channelColors: Record<string, string> = {
  telegram: "#22d3ee",
  discord: "#a78bfa",
  slack: "#fbbf24",
  whatsapp: "#34d399",
  signal: "#38bdf8",
  webchat: "#5eead4",
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
  const user = getStoredUser();
  const gatewayOnline = !loading && clawStatus?.gateway_online;
  const modelLabel = user ? `${user.llm_provider} · ${user.llm_model}` : "—";

  return (
    <div className="space-y-6 min-w-0">
      {/* Header — Control UI density */}
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
            href={GATEWAY_OPEN}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-[13px] font-mono font-medium text-[var(--bg-primary)] bg-[var(--claw-accent)] hover:brightness-110 transition-all"
          >
            <ExternalLink className="w-4 h-4" strokeWidth={2} />
            Open OpenClaw UI
          </a>
          <span className="text-[10px] font-mono text-[var(--text-muted)] text-right max-w-[240px]">
            {GATEWAY_OPEN}
          </span>
        </div>
      </header>

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
                {loading ? "…" : clawStatus?.gateway_url || GATEWAY_BASE}
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
              {loading ? "checking" : gatewayOnline ? "reachable" : "unreachable"}
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
          value={loading ? "…" : gatewayOnline ? "OK" : "Down"}
          icon={gatewayOnline ? Wifi : WifiOff}
          accent={gatewayOnline ? "var(--accent-success)" : "var(--accent-danger)"}
        />
        <MetricTile
          label="Channels"
          value={loading ? "…" : activeChannels.length}
          icon={Radio}
          accent="var(--claw-accent)"
        />
        <MetricTile
          label="Msgs (sample)"
          value={142}
          icon={Activity}
          accent="var(--accent-success)"
        />
        <MetricTile
          label="Blocked"
          value={7}
          icon={ShieldAlert}
          accent="var(--accent-danger)"
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
                Approved vs blocked (sample)
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
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mockTimeline} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
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
          </div>
        </Panel>

        <Panel className="xl:col-span-4 p-5 min-w-0 flex flex-col min-h-[300px] xl:min-h-0">
          <h2 className="text-[13px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-1">
            Live feed
          </h2>
          <p className="text-[15px] font-medium text-[var(--text-primary)] mb-3">
            Channel events
          </p>
          <ul className="flex flex-col gap-1 flex-1 min-h-0 overflow-y-auto font-mono text-[12px]">
            {mockActivity.map((entry) => {
              const StatusIcon = statusIcons[entry.status];
              return (
                <li
                  key={entry.id}
                  className="rounded-md border border-[var(--claw-border)] bg-[var(--claw-surface)] px-2.5 py-2 min-w-0 flex gap-2 items-start"
                >
                  <StatusIcon
                    className="w-3.5 h-3.5 shrink-0 mt-0.5"
                    style={{ color: statusColors[entry.status] }}
                    strokeWidth={2}
                  />
                  <div className="flex-1 min-w-0">
                    <span className="text-[var(--text-primary)]">{entry.action}</span>
                    <span className="text-[var(--text-muted)]"> · {entry.connector}</span>
                  </div>
                  <span className="text-[var(--text-muted)] shrink-0 tabular-nums">{entry.timestamp}</span>
                </li>
              );
            })}
          </ul>
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

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-5 h-5 animate-spin text-[var(--claw-accent)]" />
          </div>
        ) : channels.length === 0 ? (
          <div className="rounded-lg border border-dashed border-[var(--claw-border)] bg-[var(--claw-surface)] px-6 py-10 text-center">
            <MessageSquare className="w-8 h-8 text-[var(--text-muted)] mx-auto mb-3" strokeWidth={1.5} />
            <p className="text-[14px] text-[var(--text-secondary)] font-mono max-w-md mx-auto">
              No channels yet. Wire Telegram, Discord, Slack, and more — tokens sync into{" "}
              <code className="text-[var(--claw-accent)]">openclaw.json</code> for the gateway.
            </p>
            <Link
              to="/channels"
              className="inline-flex mt-4 px-4 py-2 rounded-lg text-[13px] font-mono font-medium bg-[var(--claw-accent)] text-[var(--bg-primary)] hover:brightness-110"
            >
              Add your first channel
            </Link>
          </div>
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
