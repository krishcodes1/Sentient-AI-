import { useEffect, useMemo, useState } from "react";
import {
  GraduationCap,
  Mail,
  TrendingUp,
  Plus,
  Check,
  X,
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
  read: { bg: "rgba(34,197,94,0.1)", text: "var(--accent-success)" },
  write: { bg: "rgba(245,158,11,0.1)", text: "var(--accent-warning)" },
  financial: { bg: "rgba(239,68,68,0.15)", text: "var(--accent-danger)" },
};

function ScopeTag({ name }: { name: string }) {
  const risk = scopeRisk(name);
  const c = riskColors[risk];
  return (
    <div
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs"
      style={{ backgroundColor: c.bg }}
    >
      <Check className="w-3 h-3" style={{ color: c.text }} />
      <span style={{ color: c.text }}>{name}</span>
      {risk === "financial" && (
        <span
          className="text-[10px] px-1 rounded font-bold"
          style={{
            backgroundColor: "rgba(239,68,68,0.2)",
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
    <div
      className="rounded-xl border overflow-hidden"
      style={{
        backgroundColor: "var(--bg-secondary)",
        borderColor: "var(--border-primary)",
      }}
    >
      <div className="p-5">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
              style={{ backgroundColor: "rgba(99,102,241,0.15)" }}
            >
              <Icon className="w-5 h-5" style={{ color: "var(--accent-primary)" }} />
            </div>
            <div className="min-w-0">
              <h3
                className="text-sm font-semibold truncate"
                style={{ color: "var(--text-primary)" }}
              >
                {connector.display_name}
              </h3>
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                {connector.auth_method.toUpperCase()} · {connector.connector_type}
              </p>
            </div>
          </div>
          <span
            className="text-xs px-2 py-0.5 rounded-full font-medium shrink-0"
            style={{
              backgroundColor: connector.is_active
                ? "rgba(34,197,94,0.1)"
                : "rgba(148,163,184,0.15)",
              color: connector.is_active ? "var(--accent-success)" : "var(--text-muted)",
            }}
          >
            {connector.is_active ? "active" : "inactive"}
          </span>
        </div>

        <div className="flex items-center gap-4 mb-3">
          <div>
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              Permission Tier
            </span>
            <p className="text-sm font-medium" style={{ color: tier.color }}>
              {tier.label}
            </p>
          </div>
          <div>
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              Rate Limit
            </span>
            <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
              {connector.rate_limit_per_minute}/min
            </p>
          </div>
          <div>
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              Added
            </span>
            <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
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
        className="flex items-center justify-between px-5 py-3 border-t"
        style={{
          borderColor: "var(--border-primary)",
          backgroundColor: "var(--bg-primary)",
        }}
      >
        {error ? (
          <span className="text-xs" style={{ color: "var(--accent-danger)" }}>
            {error}
          </span>
        ) : (
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
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
          <h1 className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>
            Connectors
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
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
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium disabled:opacity-50"
            style={{
              backgroundColor: "var(--bg-input)",
              borderColor: "var(--border-primary)",
              color: "var(--text-primary)",
            }}
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
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50 cursor-not-allowed"
            style={{ backgroundColor: "var(--accent-primary)" }}
          >
            <Plus className="w-4 h-4" /> Add Connector
          </button>
        </div>
      </div>

      {loading && (
        <div
          className="rounded-xl border p-8 flex items-center justify-center gap-2"
          style={{
            backgroundColor: "var(--bg-secondary)",
            borderColor: "var(--border-primary)",
            color: "var(--text-muted)",
          }}
        >
          <Loader2 className="w-4 h-4 animate-spin" />
          <span className="text-sm">Loading connectors...</span>
        </div>
      )}

      {!loading && error && (
        <div
          className="rounded-xl border p-6 text-center"
          style={{
            backgroundColor: "var(--bg-secondary)",
            borderColor: "var(--border-primary)",
            color: "var(--accent-danger)",
          }}
        >
          <p className="text-sm">{error}</p>
        </div>
      )}

      {!loading && !error && connectors.length === 0 && (
        <div
          className="rounded-xl border-2 border-dashed p-12 flex flex-col items-center justify-center gap-2 text-center"
          style={{
            borderColor: "var(--border-primary)",
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
