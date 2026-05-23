import { useEffect, useMemo, useState } from "react";
import {
  GraduationCap,
  Mail,
  TrendingUp,
  Plus,
  Check,
  Plug,
  Trash2,
  Loader2,
  RefreshCw,
} from "lucide-react";
import type { Connector, ConnectorType, User } from "@/types";
import {
  deleteConnector,
  getConnectors,
  getMe,
} from "@/services/api";

const connectorIcons: Record<ConnectorType, typeof GraduationCap> = {
  canvas: GraduationCap,
  google_workspace: Mail,
  robinhood: TrendingUp,
  custom: Plug,
};

const tierLabels: Record<string, { label: string; color: string }> = {
  auto_approve: { label: "Auto Approve", color: "var(--accent-success)" },
  user_confirm: { label: "User Confirm", color: "var(--accent-warning)" },
  admin_only: { label: "Admin Only", color: "var(--accent-primary)" },
  hard_blocked: { label: "Hard Blocked", color: "var(--accent-danger)" },
};

const panelStyle = {
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  boxShadow: "var(--shadow-card)",
};

const inputStyle = {
  background: "var(--bg-input)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

function scopeRisk(scope: string): "read" | "write" | "financial" {
  if (scope.includes("trade") || scope.includes("crypto.trade")) return "financial";
  if (
    scope.includes("write") ||
    scope.includes("send") ||
    scope.includes("create") ||
    scope.includes("modify") ||
    scope.includes("events")
  ) {
    return "write";
  }
  return "read";
}

const riskColors = {
  read: { text: "var(--accent-success)" },
  write: { text: "var(--accent-warning)" },
  financial: { text: "var(--accent-danger)" },
};

function ScopeTag({ name }: { name: string }) {
  const risk = scopeRisk(name);
  const c = riskColors[risk];
  return (
    <div
      className="mono-tag inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px]"
      style={{ backgroundColor: `${c.text}1a`, border: `1px solid ${c.text}33` }}
    >
      <Check className="w-3 h-3" style={{ color: c.text }} />
      <span style={{ color: c.text }}>{name}</span>
      {risk === "financial" && (
        <span
          className="text-[10px] px-1 rounded font-bold"
          style={{
            backgroundColor: "var(--fill-danger)",
            color: "var(--accent-danger)",
          }}
        >
          HIGH RISK
        </span>
      )}
    </div>
  );
}

function ConnectorCard({
  connector,
  onDelete,
}: {
  connector: Connector;
  onDelete: () => Promise<void>;
}) {
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const Icon = connectorIcons[connector.connector_type] || Plug;
  const tier = tierLabels[connector.permission_tier] || {
    label: connector.permission_tier,
    color: "var(--text-muted)",
  };

  const handleDelete = async () => {
    if (deleting) return;
    if (!window.confirm(`Remove connector "${connector.display_name}"?`)) return;
    setDeleting(true);
    setError(null);
    try {
      await onDelete();
    } catch (err) {
      setError((err as Error).message);
      setDeleting(false);
    }
  };

  return (
    <div className="rounded-[14px] overflow-hidden" style={panelStyle}>
      <div className="p-5">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-10 h-10 rounded-[10px] flex items-center justify-center shrink-0"
              style={{
                background: "var(--accent-glow)",
                border: "1px solid rgba(34,211,238,0.35)",
              }}
            >
              <Icon className="w-5 h-5" style={{ color: "var(--accent-primary)" }} />
            </div>
            <div className="min-w-0">
              <h3 className="truncate" style={{ color: "var(--text-primary)" }}>
                {connector.display_name}
              </h3>
              <p className="mono-tag mt-0.5" style={{ color: "var(--text-muted)" }}>
                {connector.auth_method.toUpperCase()} · {connector.connector_type}
              </p>
            </div>
          </div>
          <span
            className="mono-tag px-2 py-1 rounded-[6px] shrink-0"
            style={{
              background: connector.is_active ? "var(--fill-success)" : "rgba(148,163,184,0.12)",
              color: connector.is_active ? "var(--accent-success)" : "var(--text-muted)",
              border: connector.is_active ? "1px solid var(--border-success)" : "1px solid var(--claw-border)",
            }}
          >
            {connector.is_active ? "active" : "inactive"}
          </span>
        </div>

        <div className="flex items-center gap-6 mb-4">
          <div>
            <div className="eyebrow mb-1">Tier</div>
            <p className="text-sm font-medium" style={{ color: tier.color }}>
              {tier.label}
            </p>
          </div>
          <div>
            <div className="eyebrow mb-1">Rate limit</div>
            <p className="text-sm font-medium mono-num" style={{ color: "var(--text-primary)" }}>
              {connector.rate_limit_per_minute}/min
            </p>
          </div>
          <div>
            <div className="eyebrow mb-1">Added</div>
            <p className="text-sm font-medium mono-num" style={{ color: "var(--text-primary)" }}>
              {new Date(connector.created_at).toLocaleDateString()}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {connector.granted_scopes.length === 0 ? (
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              No scopes granted
            </span>
          ) : (
            connector.granted_scopes.map((s) => <ScopeTag key={s} name={s} />)
          )}
        </div>
      </div>

      <div
        className="flex items-center justify-between px-5 py-3"
        style={{
          borderTop: "1px solid var(--border-subtle)",
          background: "var(--claw-surface)",
        }}
      >
        {error ? (
          <span className="text-xs" style={{ color: "var(--accent-danger)" }}>
            {error}
          </span>
        ) : (
          <span className="mono-tag" style={{ color: "var(--text-muted)" }}>
            Updated {new Date(connector.updated_at).toLocaleDateString()}
          </span>
        )}
        <button
          type="button"
          onClick={handleDelete}
          disabled={deleting}
          className="flex items-center gap-1.5 text-xs font-medium disabled:opacity-50"
          style={{ color: "var(--accent-danger)" }}
        >
          {deleting ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Trash2 className="w-3.5 h-3.5" />
          )}
          Remove
        </button>
      </div>
    </div>
  );
}

export default function Connectors() {
  const [me, setMe] = useState<User | null>(null);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((u) => {
        if (!cancelled) setMe(u);
      })
      .catch((err: Error) => {
        if (!cancelled) {
          setError(err.message);
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!me) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    getConnectors(me.id)
      .then((data) => {
        if (!cancelled) setConnectors(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [me, refreshKey]);

  const handleDelete = async (id: string) => {
    await deleteConnector(id);
    setConnectors((prev) => prev.filter((c) => c.id !== id));
  };

  const counts = useMemo(() => {
    let active = 0;
    let inactive = 0;
    for (const c of connectors) {
      if (c.is_active) active += 1;
      else inactive += 1;
    }
    return { active, inactive };
  }, [connectors]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="eyebrow mb-2">Integrations</div>
          <h1 style={{ color: "var(--text-primary)" }}>Connectors</h1>
          <p className="text-sm mt-1.5 max-w-2xl" style={{ color: "var(--text-secondary)" }}>
            Manage third-party integrations and their security policies.
            {!loading && (
              <>
                {" "}
                <span style={{ color: "var(--accent-success)" }}>{counts.active} active</span>
                {counts.inactive > 0 && (
                  <>
                    , <span style={{ color: "var(--text-muted)" }}>{counts.inactive} inactive</span>
                  </>
                )}
              </>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-[10px] text-sm font-medium disabled:opacity-50"
            style={inputStyle}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          {/* Adding a connector requires an OAuth/API-key flow. Disabled
              until that UI is built. */}
          <button
            type="button"
            disabled
            title="Add Connector flow coming soon"
            className="flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50 cursor-not-allowed"
            style={{ background: "var(--accent-primary)", color: "#0a0a0b" }}
          >
            <Plus className="w-4 h-4" /> Add Connector
          </button>
        </div>
      </div>

      {loading && (
        <div
          className="rounded-[14px] p-8 flex items-center justify-center gap-2"
          style={{ ...panelStyle, color: "var(--text-muted)" }}
        >
          <Loader2 className="w-4 h-4 animate-spin" />
          <span className="text-sm">Loading connectors...</span>
        </div>
      )}

      {!loading && error && (
        <div
          className="rounded-[14px] p-6 text-center"
          style={{ ...panelStyle, color: "var(--accent-danger)" }}
        >
          <p className="text-sm">{error}</p>
        </div>
      )}

      {!loading && !error && connectors.length === 0 && (
        <div
          className="rounded-[14px] border-2 border-dashed p-12 flex flex-col items-center justify-center gap-2 text-center"
          style={{
            borderColor: "var(--claw-border)",
            color: "var(--text-muted)",
          }}
        >
          <Plug className="w-10 h-10" />
          <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
            No connectors yet
          </p>
          <p className="text-xs max-w-sm">
            Once an Add Connector flow lands, Canvas, Google Workspace, and
            Robinhood integrations will appear here.
          </p>
        </div>
      )}

      {!loading && !error && connectors.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {connectors.map((c) => (
            <ConnectorCard
              key={c.id}
              connector={c}
              onDelete={() => handleDelete(c.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
