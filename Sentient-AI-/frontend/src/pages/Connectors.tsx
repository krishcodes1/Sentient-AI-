import { useState } from "react";
import {
  GraduationCap,
  Mail,
  TrendingUp,
  Plus,
  Check,
  X,
  ChevronDown,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import clsx from "clsx";
import type { Connector, ConnectorScope } from "@/types";

const scopeColors = {
  read: { bg: "rgba(34,197,94,0.1)", text: "var(--accent-success)", label: "Read" },
  write: { bg: "rgba(245,158,11,0.1)", text: "var(--accent-warning)", label: "Write" },
  admin: { bg: "rgba(239,68,68,0.1)", text: "var(--accent-danger)", label: "Admin" },
  financial: { bg: "rgba(239,68,68,0.15)", text: "var(--accent-danger)", label: "Financial" },
};

const connectorIcons: Record<string, any> = {
  canvas: GraduationCap,
  google: Mail,
  robinhood: TrendingUp,
};

const mockConnectors: Connector[] = [
  {
    id: "1",
    name: "Canvas LMS",
    type: "canvas",
    auth_method: "oauth2",
    status: "connected",
    base_url: "https://nyit.instructure.com",
    permission_tier: "supervised",
    created_at: "2026-03-15",
    last_used: "2 min ago",
    health: "healthy",
    scopes: [
      { name: "courses.read", description: "List enrolled courses", risk_level: "read", granted: true },
      { name: "assignments.read", description: "View assignments and due dates", risk_level: "read", granted: true },
      { name: "submissions.read", description: "View submission status", risk_level: "read", granted: true },
      { name: "grades.read", description: "Access grade information", risk_level: "read", granted: true },
      { name: "calendar.read", description: "View calendar events", risk_level: "read", granted: true },
      { name: "submissions.write", description: "Submit assignments", risk_level: "write", granted: false },
    ],
  },
  {
    id: "2",
    name: "Google Workspace",
    type: "google",
    auth_method: "oauth2",
    status: "connected",
    base_url: "https://googleapis.com",
    permission_tier: "supervised",
    created_at: "2026-03-16",
    last_used: "5 min ago",
    health: "healthy",
    scopes: [
      { name: "gmail.readonly", description: "Read email messages", risk_level: "read", granted: true },
      { name: "gmail.send", description: "Send emails on your behalf", risk_level: "write", granted: true },
      { name: "calendar.readonly", description: "View calendar events", risk_level: "read", granted: true },
      { name: "calendar.events", description: "Create/modify calendar events", risk_level: "write", granted: true },
    ],
  },
  {
    id: "3",
    name: "Robinhood Crypto",
    type: "robinhood",
    auth_method: "api_key",
    status: "connected",
    base_url: "https://api.robinhood.com",
    permission_tier: "restricted",
    created_at: "2026-03-20",
    last_used: "1h ago",
    health: "degraded",
    scopes: [
      { name: "crypto.portfolio", description: "View crypto portfolio", risk_level: "read", granted: true },
      { name: "crypto.prices", description: "View crypto prices", risk_level: "read", granted: true },
      { name: "crypto.trade", description: "Execute crypto trades", risk_level: "financial", granted: false },
    ],
  },
];

function ScopeTag({ scope }: { scope: ConnectorScope }) {
  const c = scopeColors[scope.risk_level];
  return (
    <div
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs"
      style={{ backgroundColor: c.bg }}
    >
      {scope.granted ? (
        <Check className="w-3 h-3" style={{ color: c.text }} />
      ) : (
        <X className="w-3 h-3" style={{ color: "var(--text-muted)" }} />
      )}
      <span style={{ color: scope.granted ? c.text : "var(--text-muted)" }}>
        {scope.name}
      </span>
      {scope.risk_level === "financial" && (
        <span
          className="text-[10px] px-1 rounded font-bold"
          style={{
            backgroundColor: "rgba(239,68,68,0.2)",
            color: "var(--accent-danger)",
          }}
        >
          BLOCKED
        </span>
      )}
    </div>
  );
}

function ConnectorCard({ connector }: { connector: Connector }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = connectorIcons[connector.type] || Plus;

  return (
    <div
      className="rounded-xl border overflow-hidden"
      style={{
        backgroundColor: "var(--bg-secondary)",
        borderColor: "var(--border-primary)",
      }}
    >
      {/* Header */}
      <div className="p-5">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center"
              style={{ backgroundColor: "rgba(99,102,241,0.15)" }}
            >
              <Icon className="w-5 h-5" style={{ color: "var(--accent-primary)" }} />
            </div>
            <div>
              <h3
                className="text-sm font-semibold"
                style={{ color: "var(--text-primary)" }}
              >
                {connector.name}
              </h3>
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                {connector.auth_method.toUpperCase()} | {connector.base_url}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="text-xs px-2 py-0.5 rounded-full font-medium"
              style={{
                backgroundColor:
                  connector.status === "connected"
                    ? "rgba(34,197,94,0.1)"
                    : "rgba(239,68,68,0.1)",
                color:
                  connector.status === "connected"
                    ? "var(--accent-success)"
                    : "var(--accent-danger)",
              }}
            >
              {connector.status}
            </span>
            {connector.health && connector.health !== "healthy" && (
              <span
                className="text-xs px-2 py-0.5 rounded-full font-medium"
                style={{
                  backgroundColor: "rgba(245,158,11,0.1)",
                  color: "var(--accent-warning)",
                }}
              >
                {connector.health}
              </span>
            )}
          </div>
        </div>

        {/* Permission Tier */}
        <div className="flex items-center gap-4 mb-3">
          <div>
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              Permission Tier
            </span>
            <p
              className="text-sm font-medium capitalize"
              style={{ color: "var(--text-primary)" }}
            >
              {connector.permission_tier}
            </p>
          </div>
          <div>
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              Last Used
            </span>
            <p
              className="text-sm font-medium"
              style={{ color: "var(--text-primary)" }}
            >
              {connector.last_used || "Never"}
            </p>
          </div>
        </div>

        {/* Scopes */}
        <div className="flex flex-wrap gap-1.5">
          {connector.scopes.map((s) => (
            <ScopeTag key={s.name} scope={s} />
          ))}
        </div>
      </div>

      {/* Actions */}
      <div
        className="flex items-center justify-between px-5 py-3 border-t"
        style={{
          borderColor: "var(--border-primary)",
          backgroundColor: "var(--bg-primary)",
        }}
      >
        <button
          className="flex items-center gap-1.5 text-xs font-medium"
          style={{ color: "var(--accent-primary)" }}
        >
          <RefreshCw className="w-3.5 h-3.5" /> Test Connection
        </button>
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-1 text-xs font-medium"
          style={{ color: "var(--text-secondary)" }}
        >
          Configure{" "}
          <ChevronDown
            className={clsx("w-3.5 h-3.5 transition-transform", expanded && "rotate-180")}
          />
        </button>
      </div>
    </div>
  );
}

export default function Connectors() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1
            className="text-2xl font-bold"
            style={{ color: "var(--text-primary)" }}
          >
            Connectors
          </h1>
          <p
            className="text-sm mt-1"
            style={{ color: "var(--text-secondary)" }}
          >
            Manage third-party integrations and their security policies
          </p>
        </div>
        <button
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
          style={{ backgroundColor: "var(--accent-primary)" }}
        >
          <Plus className="w-4 h-4" /> Add Connector
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {mockConnectors.map((c) => (
          <ConnectorCard key={c.id} connector={c} />
        ))}

        {/* Add New Card */}
        <button
          className="rounded-xl border-2 border-dashed p-8 flex flex-col items-center justify-center gap-2 transition-colors hover:opacity-80"
          style={{
            borderColor: "var(--border-primary)",
            color: "var(--text-muted)",
          }}
        >
          <Plus className="w-8 h-8" />
          <span className="text-sm font-medium">Add New Connector</span>
          <span className="text-xs">GitHub, Slack, Notion, Spotify...</span>
        </button>
      </div>
    </div>
  );
}
