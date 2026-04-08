import { useState } from "react";
import {
  GraduationCap,
  Mail,
  TrendingUp,
  Plus,
  Check,
  X,
  ChevronDown,
  RefreshCw,
} from "lucide-react";
import clsx from "clsx";
import type { Connector, ConnectorScope } from "@/types";

const scopeColors = {
  read: { bg: "rgba(48,209,88,0.14)", text: "var(--accent-success)", label: "Read" },
  write: { bg: "rgba(255,159,10,0.14)", text: "var(--accent-warning)", label: "Write" },
  admin: { bg: "rgba(255,69,58,0.14)", text: "var(--accent-danger)", label: "Admin" },
  financial: { bg: "rgba(255,69,58,0.18)", text: "var(--accent-danger)", label: "Financial" },
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
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[8px] text-[12px]"
      style={{ backgroundColor: c.bg }}
    >
      {scope.granted ? (
        <Check className="w-3 h-3" style={{ color: c.text }} strokeWidth={2.5} />
      ) : (
        <X className="w-3 h-3 text-[var(--text-muted)]" strokeWidth={2.5} />
      )}
      <span style={{ color: scope.granted ? c.text : "var(--text-muted)" }}>
        {scope.name}
      </span>
      {scope.risk_level === "financial" && !scope.granted && (
        <span className="text-[10px] px-1.5 py-0.5 rounded-[4px] font-bold bg-[rgba(255,69,58,0.2)] text-[var(--accent-danger)]">
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
      className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] overflow-hidden"
      style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
    >
      <div className="p-5">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-11 h-11 rounded-[12px] bg-[rgba(10,132,255,0.15)] flex items-center justify-center shrink-0">
              <Icon className="w-5 h-5 text-[var(--accent-primary)]" strokeWidth={1.75} />
            </div>
            <div className="min-w-0">
              <h3 className="text-[15px] font-semibold text-[var(--text-primary)] truncate">
                {connector.name}
              </h3>
              <p className="text-[12px] text-[var(--text-muted)] truncate">
                {connector.auth_method.toUpperCase()} &middot; {connector.base_url}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span
              className="text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-full"
              style={{
                backgroundColor: connector.status === "connected" ? "rgba(48,209,88,0.18)" : "rgba(255,69,58,0.18)",
                color: connector.status === "connected" ? "var(--accent-success)" : "var(--accent-danger)",
              }}
            >
              {connector.status}
            </span>
            {connector.health && connector.health !== "healthy" && (
              <span className="text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-full bg-[rgba(255,159,10,0.18)] text-[var(--accent-warning)]">
                {connector.health}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-6 mb-4">
          <div>
            <span className="text-[11px] text-[var(--text-muted)] uppercase tracking-wide font-medium">
              Permission
            </span>
            <p className="text-[14px] font-medium capitalize text-[var(--text-primary)]">
              {connector.permission_tier}
            </p>
          </div>
          <div>
            <span className="text-[11px] text-[var(--text-muted)] uppercase tracking-wide font-medium">
              Last Used
            </span>
            <p className="text-[14px] font-medium text-[var(--text-primary)]">
              {connector.last_used || "Never"}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {connector.scopes.map((s) => (
            <ScopeTag key={s.name} scope={s} />
          ))}
        </div>
      </div>

      <div
        className="flex items-center justify-between px-5 py-3 border-t border-[var(--border-subtle)] bg-[var(--bg-tertiary)]"
      >
        <button
          type="button"
          className="flex items-center gap-1.5 text-[13px] font-medium text-[var(--accent-primary)] hover:underline"
        >
          <RefreshCw className="w-3.5 h-3.5" strokeWidth={2} /> Test Connection
        </button>
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-1 text-[13px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
        >
          Configure
          <ChevronDown className={clsx("w-3.5 h-3.5 transition-transform", expanded && "rotate-180")} />
        </button>
      </div>
    </div>
  );
}

export default function Connectors() {
  return (
    <div className="space-y-8 min-w-0">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <header>
          <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)] md:text-[32px]">
            Connectors
          </h1>
          <p className="text-[15px] text-[var(--text-secondary)] mt-1 max-w-lg leading-relaxed">
            Manage third-party integrations and their security policies.
          </p>
        </header>
        <button
          type="button"
          className="flex items-center gap-2 px-5 py-2.5 rounded-[12px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] hover:brightness-110 transition-all shrink-0"
        >
          <Plus className="w-4 h-4" strokeWidth={2.5} /> Add Connector
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {mockConnectors.map((c) => (
          <ConnectorCard key={c.id} connector={c} />
        ))}

        <button
          type="button"
          className="rounded-[var(--radius-xl)] border-2 border-dashed border-[var(--border-primary)] p-10 flex flex-col items-center justify-center gap-2 transition-colors hover:border-[var(--accent-primary)] hover:bg-[rgba(10,132,255,0.04)] group"
        >
          <Plus className="w-9 h-9 text-[var(--text-muted)] group-hover:text-[var(--accent-primary)] transition-colors" strokeWidth={1.5} />
          <span className="text-[14px] font-medium text-[var(--text-muted)] group-hover:text-[var(--text-primary)] transition-colors">
            Add New Connector
          </span>
          <span className="text-[12px] text-[var(--text-muted)]">
            GitHub, Slack, Notion, Spotify...
          </span>
        </button>
      </div>
    </div>
  );
}
