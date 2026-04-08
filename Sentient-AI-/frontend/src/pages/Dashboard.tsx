import { useState } from "react";
import {
  Plug,
  Activity,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
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
  ActivityEntry,
  SecurityTimelineEntry,
  ConnectorHealthEntry,
} from "@/types";

// Mock data for demo
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

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: any;
  color: string;
}) {
  return (
    <div
      className="rounded-xl p-5 border"
      style={{
        backgroundColor: "var(--bg-secondary)",
        borderColor: "var(--border-primary)",
      }}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm" style={{ color: "var(--text-secondary)" }}>
          {label}
        </span>
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: `${color}15` }}
        >
          <Icon className="w-5 h-5" style={{ color }} />
        </div>
      </div>
      <p className="text-3xl font-bold" style={{ color: "var(--text-primary)" }}>
        {value}
      </p>
    </div>
  );
}

export default function Dashboard() {
  return (
    <div className="space-y-6">
      <div>
        <h1
          className="text-2xl font-bold"
          style={{ color: "var(--text-primary)" }}
        >
          Dashboard
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Real-time monitoring of agent activity and security events
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Active Connectors"
          value={stats.active_connectors}
          icon={Plug}
          color="var(--accent-success)"
        />
        <StatCard
          label="Actions (24h)"
          value={stats.total_actions_24h}
          icon={Activity}
          color="var(--accent-primary)"
        />
        <StatCard
          label="Blocked Threats"
          value={stats.blocked_threats}
          icon={ShieldAlert}
          color="var(--accent-danger)"
        />
        <StatCard
          label="Pending Approvals"
          value={stats.pending_approvals}
          icon={Clock}
          color="var(--accent-warning)"
        />
      </div>

      {/* Charts + Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Timeline */}
        <div
          className="lg:col-span-2 rounded-xl border p-5"
          style={{
            backgroundColor: "var(--bg-secondary)",
            borderColor: "var(--border-primary)",
          }}
        >
          <h2
            className="text-lg font-semibold mb-4"
            style={{ color: "var(--text-primary)" }}
          >
            Security Events (7 Days)
          </h2>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={mockTimeline}>
              <defs>
                <linearGradient id="approvedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="date"
                stroke="#64748b"
                fontSize={12}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                stroke="#64748b"
                fontSize={12}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1a1d27",
                  border: "1px solid #2a2d3a",
                  borderRadius: "8px",
                  color: "#f1f5f9",
                  fontSize: "13px",
                }}
              />
              <Area
                type="monotone"
                dataKey="approved"
                stroke="#6366f1"
                fill="url(#approvedGrad)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="#ef4444"
                fill="url(#blockedGrad)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Activity Feed */}
        <div
          className="rounded-xl border p-5"
          style={{
            backgroundColor: "var(--bg-secondary)",
            borderColor: "var(--border-primary)",
          }}
        >
          <h2
            className="text-lg font-semibold mb-4"
            style={{ color: "var(--text-primary)" }}
          >
            Recent Activity
          </h2>
          <div className="space-y-3">
            {mockActivity.map((entry) => {
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
                      {entry.connector}
                    </p>
                  </div>
                  <span
                    className="text-xs shrink-0"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {entry.timestamp}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Connector Health */}
      <div
        className="rounded-xl border p-5"
        style={{
          backgroundColor: "var(--bg-secondary)",
          borderColor: "var(--border-primary)",
        }}
      >
        <h2
          className="text-lg font-semibold mb-4"
          style={{ color: "var(--text-primary)" }}
        >
          Connector Health
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {mockHealth.map((c) => (
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
                  className="text-sm font-medium"
                  style={{ color: "var(--text-primary)" }}
                >
                  {c.name}
                </span>
                <span
                  className="text-xs px-2 py-0.5 rounded-full font-medium"
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
                  className="text-xs"
                  style={{ color: "var(--text-muted)" }}
                >
                  {c.last_check}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
