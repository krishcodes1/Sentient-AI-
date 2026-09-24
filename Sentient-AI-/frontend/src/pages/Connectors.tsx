import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  GraduationCap,
  Mail,
  TrendingUp,
  Plus,
  Check,
  Pencil,
  Plug,
  Power,
  Server,
  ShieldCheck,
  Trash2,
  Loader2,
  RefreshCw,
  X,
  Zap,
  XCircle,
} from "lucide-react";
import type {
  AuthMethod,
  Connector,
  ConnectorType,
  PermissionTier,
  UpdateConnectorRequest,
} from "@/types";
import {
  createConnector,
  deleteConnector,
  getConnectors,
  testConnector,
  updateConnector,
} from "@/services/api";
import ConfirmDialog from "@/components/ConfirmDialog";
import { useFocusTrap } from "@/hooks/useFocusTrap";

const connectorIcons: Record<ConnectorType, typeof GraduationCap> = {
  canvas: GraduationCap,
  google_workspace: Mail,
  robinhood: TrendingUp,
  mcp: Server,
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
    scope.includes("modify")
  ) {
    return "write";
  }
  return "read";
}

// Each tint carries its own fill and border rather than deriving them by
// appending an alpha suffix to `text`: `var(--accent-success)1f` is not a
// color, so those chips were rendering untinted.
const riskColors = {
  read: {
    text: "var(--accent-success)",
    fill: "var(--fill-success)",
    border: "var(--border-success)",
  },
  write: {
    text: "var(--accent-warning)",
    fill: "var(--fill-warning)",
    border: "var(--border-warning)",
  },
  financial: {
    text: "var(--accent-danger)",
    fill: "var(--fill-danger)",
    border: "var(--border-danger)",
  },
};

function ScopeTag({ name }: { name: string }) {
  const risk = scopeRisk(name);
  const c = riskColors[risk];
  return (
    <div
      className="mono-tag inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px]"
      style={{ backgroundColor: c.fill, border: `1px solid ${c.border}` }}
    >
      <Check className="w-3 h-3" style={{ color: c.text }} aria-hidden />
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
  onEdit,
}: {
  connector: Connector;
  onDelete: () => Promise<void>;
  onEdit: () => void;
}) {
  const [deleting, setDeleting] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null);
  const Icon = connectorIcons[connector.connector_type] || Plug;
  const tier = tierLabels[connector.permission_tier] || {
    label: connector.permission_tier,
    color: "var(--text-muted)",
  };

  const handleTest = async () => {
    if (testing) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await testConnector(connector.id);
      setTestResult(result);
    } catch (err) {
      setTestResult({ ok: false, detail: (err as Error).message });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div
      className="rounded-[14px] overflow-hidden transition-all duration-200"
      style={panelStyle}
      onMouseOver={(e) => {
        e.currentTarget.style.borderColor = "var(--border-accent-strong)";
        e.currentTarget.style.transform = "translateY(-2px)";
      }}
      onMouseOut={(e) => {
        e.currentTarget.style.borderColor = "var(--claw-border)";
        e.currentTarget.style.transform = "translateY(0)";
      }}
    >
      {/* Inactive connectors are dimmed so the state is obvious at a glance;
          the footer actions keep full contrast so re-enabling is easy. */}
      <div className="p-5" style={{ opacity: connector.is_active ? 1 : 0.55 }}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-10 h-10 rounded-[10px] flex items-center justify-center shrink-0"
              style={{
                background: connector.is_active
                  ? "var(--accent-glow)"
                  : "var(--fill-neutral)",
                border: connector.is_active
                  ? "1px solid var(--border-accent)"
                  : "1px solid var(--claw-border)",
              }}
            >
              <Icon
                className="w-5 h-5"
                style={{
                  color: connector.is_active
                    ? "var(--accent-primary)"
                    : "var(--text-muted)",
                }}
              />
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
              background: connector.is_active ? "var(--fill-success)" : "var(--fill-neutral)",
              color: connector.is_active ? "var(--accent-success)" : "var(--text-muted)",
              border: connector.is_active ? "1px solid var(--border-success)" : "1px solid var(--claw-border)",
            }}
          >
            {connector.is_active ? "active" : "inactive"}
          </span>
        </div>

        <div className="flex flex-wrap gap-x-6 gap-y-3 mb-4">
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
              No scopes granted — treated as read-only
            </span>
          ) : (
            connector.granted_scopes.map((s) => <ScopeTag key={s} name={s} />)
          )}
        </div>

        {testResult && (
          <div
            role="status"
            className="flex items-start gap-2 mt-3 px-3 py-2 rounded-[8px] text-xs"
            style={{
              background: testResult.ok ? "var(--fill-success)" : "var(--fill-danger)",
              border: `1px solid ${testResult.ok ? "var(--border-success)" : "var(--border-danger)"}`,
              color: testResult.ok ? "var(--accent-success)" : "var(--accent-danger)",
            }}
          >
            {testResult.ok ? (
              <ShieldCheck className="w-3.5 h-3.5 mt-px shrink-0" />
            ) : (
              <XCircle className="w-3.5 h-3.5 mt-px shrink-0" />
            )}
            <span>{testResult.detail}</span>
          </div>
        )}
      </div>

      <div
        className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-5 py-2"
        style={{
          borderTop: "1px solid var(--border-subtle)",
          background: "var(--claw-surface)",
        }}
      >
        {error ? (
          <span role="alert" className="text-xs" style={{ color: "var(--accent-danger)" }}>
            {error}
          </span>
        ) : (
          <span className="mono-tag" style={{ color: "var(--text-muted)" }}>
            Updated {new Date(connector.updated_at).toLocaleDateString()}
          </span>
        )}
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => void handleTest()}
            disabled={testing}
            aria-label={`Test ${connector.display_name}`}
            className="inline-flex items-center gap-1.5 text-xs font-medium disabled:opacity-50"
            style={{ minHeight: 44, color: "var(--accent-primary)" }}
          >
            {testing ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
            ) : (
              <Zap className="w-3.5 h-3.5" aria-hidden />
            )}
            Test
          </button>
          <button
            type="button"
            onClick={onEdit}
            aria-label={`Edit ${connector.display_name}`}
            className="inline-flex items-center gap-1.5 text-xs font-medium"
            style={{ minHeight: 44, color: "var(--text-secondary)" }}
          >
            <Pencil className="w-3.5 h-3.5" aria-hidden />
            Edit
          </button>
          <button
            type="button"
            onClick={() => setConfirmOpen(true)}
            disabled={deleting}
            aria-label={`Remove ${connector.display_name}`}
            className="inline-flex items-center gap-1.5 text-xs font-medium disabled:opacity-50"
            style={{ minHeight: 44, color: "var(--accent-danger)" }}
          >
            {deleting ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
            ) : (
              <Trash2 className="w-3.5 h-3.5" aria-hidden />
            )}
            Remove
          </button>
        </div>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        danger
        title="Remove connector?"
        message={`"${connector.display_name}" will be disconnected and its encrypted credentials permanently deleted. The agent immediately loses access to this service.`}
        confirmLabel="Remove"
        onCancel={() => setConfirmOpen(false)}
        onConfirm={async () => {
          setDeleting(true);
          setError(null);
          try {
            await onDelete();
          } catch (err) {
            setDeleting(false);
            setConfirmOpen(false);
            setError((err as Error).message);
            return;
          }
          setConfirmOpen(false);
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Add-connector modal: service-specific fields and scope presets
// ---------------------------------------------------------------------------

interface FieldDef {
  key: string;
  label: string;
  type: "text" | "password";
  placeholder: string;
  required?: boolean;
  hint?: string;
}

interface ServiceDef {
  value: ConnectorType;
  label: string;
  authMethod: AuthMethod;
  fields: FieldDef[];
  readScopes: string[];
  writeScopes: string[];
  notice?: string;
  noticeTone?: "danger" | "info";
}

const SERVICES: ServiceDef[] = [
  {
    value: "canvas",
    label: "Canvas LMS",
    authMethod: "bearer_token",
    fields: [
      {
        key: "base_url",
        label: "Canvas URL",
        type: "text",
        placeholder: "https://yourschool.instructure.com",
        required: true,
        hint: "Your school's Canvas address.",
      },
      {
        key: "access_token",
        label: "Access token",
        type: "password",
        placeholder: "Paste your Canvas access token",
        required: true,
        hint: "Canvas → Account → Settings → + New access token.",
      },
    ],
    readScopes: [
      "courses.read",
      "assignments.read",
      "grades.read",
      "calendar.read",
      "submissions.read",
    ],
    writeScopes: ["submissions.write"],
  },
  {
    value: "google_workspace",
    label: "Google Workspace",
    authMethod: "oauth2",
    fields: [
      {
        key: "access_token",
        label: "OAuth access token",
        type: "password",
        placeholder: "ya29....",
        required: true,
        hint: "Token with the Gmail / Calendar scopes you grant below.",
      },
      {
        key: "refresh_token",
        label: "Refresh token (strongly recommended)",
        type: "password",
        placeholder: "Without this, the connection stops working in ~1 hour",
        hint:
          "Google access tokens expire after about an hour. With a refresh " +
          "token + client credentials, Crawler AI renews and saves tokens " +
          "automatically; without them you must paste a fresh token every hour.",
      },
      {
        key: "client_id",
        label: "OAuth client ID (needed for auto-refresh)",
        type: "text",
        placeholder: "Required for automatic renewal",
      },
      {
        key: "client_secret",
        label: "OAuth client secret (needed for auto-refresh)",
        type: "password",
        placeholder: "Required for automatic renewal",
      },
    ],
    readScopes: ["gmail.read", "calendar.read"],
    writeScopes: ["gmail.send", "calendar.write"],
  },
  {
    value: "robinhood",
    label: "Robinhood (read-only)",
    authMethod: "api_key",
    fields: [
      {
        key: "api_key",
        label: "API key",
        type: "password",
        placeholder: "Robinhood Crypto API key",
        required: true,
      },
      {
        key: "api_secret",
        label: "API secret",
        type: "password",
        placeholder: "Robinhood Crypto API secret",
        required: true,
      },
    ],
    readScopes: ["crypto.read"],
    writeScopes: [],
    notice:
      "Read-only by design. Crawler AI can review your portfolio but can never trade, transfer, or move money — those actions are permanently blocked on the server and cannot be enabled.",
    noticeTone: "danger",
  },
  {
    value: "mcp",
    label: "MCP server",
    authMethod: "bearer_token",
    fields: [
      {
        key: "url",
        label: "Server URL",
        type: "text",
        placeholder: "https://example.com/mcp",
        required: true,
        hint: "Streamable-HTTP MCP endpoint.",
      },
      {
        key: "headers_json",
        label: "Headers (optional JSON)",
        type: "text",
        placeholder: '{"Authorization": "Bearer ..."}',
        hint: "Sent with every request, e.g. for authentication.",
      },
    ],
    readScopes: [],
    writeScopes: [],
    notice:
      "MCP servers are third-party tools. Every tool call they expose requires your explicit approval, and tools that look financial are blocked entirely.",
    noticeTone: "info",
  },
  // "custom" was removed from the picker: the backend now rejects it with
  // 422. Existing custom connectors still render and can be edited.
];

const TIER_OPTIONS: { value: PermissionTier; label: string }[] = [
  { value: "user_confirm", label: "User Confirm (recommended)" },
  { value: "auto_approve", label: "Auto Approve" },
  { value: "admin_only", label: "Admin Only" },
];

const labelCls = "block mb-1.5 text-sm text-[var(--text-secondary)]";
const fieldCls =
  "w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none transition-colors";

function ScopeChip({
  scope,
  selected,
  onToggle,
}: {
  scope: string;
  selected: boolean;
  onToggle: () => void;
}) {
  const risk = scopeRisk(scope);
  const tint = riskColors[risk];
  return (
    <button
      type="button"
      onClick={onToggle}
      className="mono-tag inline-flex items-center gap-1.5 px-2.5 rounded-[8px] transition-all"
      style={{
        minHeight: 36,
        backgroundColor: selected ? tint.fill : "var(--bg-input)",
        border: `1px solid ${selected ? tint.border : "var(--claw-border)"}`,
        color: selected ? tint.text : "var(--text-muted)",
      }}
      aria-pressed={selected}
    >
      {selected ? (
        <Check className="w-3 h-3" aria-hidden />
      ) : (
        <Plus className="w-3 h-3" aria-hidden />
      )}
      {scope}
    </button>
  );
}

function AddConnectorModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (c: Connector) => void;
}) {
  const [service, setService] = useState<ServiceDef>(SERVICES[0]);
  const [displayName, setDisplayName] = useState("");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [selectedScopes, setSelectedScopes] = useState<string[]>(SERVICES[0].readScopes);
  const [permissionTier, setPermissionTier] =
    useState<PermissionTier>("user_confirm");
  const [rateLimit, setRateLimit] = useState(30);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const ids = {
    title: useId(),
    service: useId(),
    displayName: useId(),
    scopes: useId(),
    tier: useId(),
    rate: useId(),
    field: useId(),
  };

  // Also supplies Escape, so the hand-rolled key listener this replaced is
  // gone — the trap has to own both to keep them from disagreeing.
  useFocusTrap(true, panelRef, onClose);

  const switchService = (value: ConnectorType) => {
    const next = SERVICES.find((s) => s.value === value) ?? SERVICES[0];
    setService(next);
    setFieldValues({});
    setSelectedScopes(next.readScopes); // least privilege: reads preselected
    setError(null);
  };

  const requiredOk = service.fields
    .filter((f) => f.required)
    .every((f) => (fieldValues[f.key] ?? "").trim() !== "");
  const canSubmit = displayName.trim() !== "" && requiredOk && !submitting;

  const buildCredentials = (): Record<string, unknown> => {
    const credentials: Record<string, unknown> = {};
    for (const field of service.fields) {
      const raw = (fieldValues[field.key] ?? "").trim();
      if (!raw) continue;
      if (field.key === "headers_json") {
        credentials["headers"] = JSON.parse(raw);
      } else {
        credentials[field.key] = raw;
      }
    }
    return credentials;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const created = await createConnector({
        connector_type: service.value,
        display_name: displayName.trim(),
        auth_method: service.authMethod,
        credentials: buildCredentials(),
        granted_scopes: selectedScopes,
        permission_tier: permissionTier,
        rate_limit_per_minute: rateLimit,
      });
      onCreated(created);
    } catch (err) {
      const message =
        err instanceof SyntaxError
          ? "Headers must be valid JSON."
          : (err as Error).message || "Failed to create connector";
      setError(message);
      setSubmitting(false);
    }
  };

  const TypeIcon = connectorIcons[service.value] || Plug;
  const hasScopes = service.readScopes.length + service.writeScopes.length > 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "var(--scrim)", backdropFilter: "blur(2px)" }}
      onClick={onClose}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={ids.title}
        className="w-full max-w-lg rounded-[16px] max-h-[90dvh] overflow-y-auto"
        style={{ ...panelStyle, boxShadow: "var(--shadow-modal)" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between px-4 sm:px-6 py-4"
          style={{ borderBottom: "1px solid var(--border-subtle)" }}
        >
          <div className="flex items-center gap-3 min-w-0">
            <div
              aria-hidden
              className="w-9 h-9 rounded-[10px] flex items-center justify-center shrink-0"
              style={{
                background: "var(--accent-glow)",
                border: "1px solid var(--border-accent)",
              }}
            >
              <TypeIcon
                className="w-4 h-4"
                style={{ color: "var(--accent-primary)" }}
              />
            </div>
            <div className="min-w-0">
              <div className="eyebrow">New integration</div>
              <h2 id={ids.title} className="h3" style={{ color: "var(--text-primary)" }}>
                Add connector
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center justify-center rounded-md transition-colors shrink-0"
            style={{ width: 44, height: 44, color: "var(--text-muted)" }}
            aria-label="Close"
          >
            <X className="w-5 h-5" aria-hidden />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="px-4 sm:px-6 py-5 flex flex-col gap-4">
            {error && (
              <div
                role="alert"
                className="px-3 py-2.5 rounded-[8px] text-sm"
                style={{
                  background: "var(--fill-danger)",
                  color: "var(--accent-danger)",
                  border: "1px solid var(--border-danger)",
                }}
              >
                {error}
              </div>
            )}

            <div>
              <label htmlFor={ids.service} className={labelCls}>
                Service
              </label>
              <select
                id={ids.service}
                value={service.value}
                onChange={(e) => switchService(e.target.value as ConnectorType)}
                className={fieldCls}
                style={inputStyle}
              >
                {SERVICES.map((s) => (
                  <option key={s.value} value={s.value}>
                    {s.label}
                  </option>
                ))}
              </select>
            </div>

            {service.notice && (
              <div
                className="px-3 py-2.5 rounded-[8px] text-xs leading-relaxed"
                style={
                  service.noticeTone === "danger"
                    ? {
                        background: "var(--fill-danger)",
                        color: "var(--accent-danger)",
                        border: "1px solid var(--border-danger)",
                      }
                    : {
                        background: "var(--accent-glow)",
                        color: "var(--accent-primary)",
                        border: "1px solid var(--border-accent)",
                      }
                }
              >
                {service.notice}
              </div>
            )}

            <div>
              <label htmlFor={ids.displayName} className={labelCls}>
                Display name
              </label>
              <input
                id={ids.displayName}
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className={fieldCls}
                style={inputStyle}
                placeholder={`e.g. My ${service.label}`}
                required
              />
            </div>

            {service.fields.map((field) => (
              <div key={field.key}>
                <label htmlFor={`${ids.field}-${field.key}`} className={labelCls}>
                  {field.label}
                </label>
                <input
                  id={`${ids.field}-${field.key}`}
                  aria-describedby={
                    field.hint ? `${ids.field}-${field.key}-hint` : undefined
                  }
                  type={field.type}
                  value={fieldValues[field.key] ?? ""}
                  onChange={(e) =>
                    setFieldValues((prev) => ({
                      ...prev,
                      [field.key]: e.target.value,
                    }))
                  }
                  className={fieldCls}
                  style={inputStyle}
                  placeholder={field.placeholder}
                  autoComplete="off"
                />
                {field.hint && (
                  <p
                    id={`${ids.field}-${field.key}-hint`}
                    className="text-xs mt-1.5"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {field.hint}
                  </p>
                )}
              </div>
            ))}

            <p className="text-xs -mt-1" style={{ color: "var(--text-muted)" }}>
              Credentials are encrypted (AES-256-GCM) before they touch the
              database and are never displayed again after saving.
            </p>

            {hasScopes && (
              <div>
                <span id={ids.scopes} className={labelCls}>
                  Permissions to grant
                </span>
                <div
                  role="group"
                  aria-labelledby={ids.scopes}
                  className="flex flex-wrap gap-2"
                >
                  {[...service.readScopes, ...service.writeScopes].map((scope) => (
                    <ScopeChip
                      key={scope}
                      scope={scope}
                      selected={selectedScopes.includes(scope)}
                      onToggle={() =>
                        setSelectedScopes((prev) =>
                          prev.includes(scope)
                            ? prev.filter((s) => s !== scope)
                            : [...prev, scope]
                        )
                      }
                    />
                  ))}
                </div>
                <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                  Read access is preselected. Anything the agent is not granted
                  here is refused at execution time, and write actions always
                  ask for your approval first.
                </p>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor={ids.tier} className={labelCls}>
                  Approval policy
                </label>
                <select
                  id={ids.tier}
                  value={permissionTier}
                  onChange={(e) =>
                    setPermissionTier(e.target.value as PermissionTier)
                  }
                  className={fieldCls}
                  style={inputStyle}
                >
                  {TIER_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor={ids.rate} className={labelCls}>
                  Rate limit (/min)
                </label>
                <input
                  id={ids.rate}
                  type="number"
                  min={1}
                  max={600}
                  value={rateLimit}
                  onChange={(e) =>
                    setRateLimit(
                      Math.max(1, Math.min(600, Number(e.target.value) || 1))
                    )
                  }
                  className={fieldCls}
                  style={inputStyle}
                />
              </div>
            </div>
            <p className="text-xs -mt-2" style={{ color: "var(--text-muted)" }}>
              Sensitive actions (sending email, submitting work, anything
              financial-adjacent) require explicit approval regardless of the
              policy chosen here.
            </p>
          </div>

          <div
            className="flex items-center justify-end gap-2 px-4 sm:px-6 py-4"
            style={{
              borderTop: "1px solid var(--border-subtle)",
              background: "var(--claw-surface)",
            }}
          >
            <button
              type="button"
              onClick={onClose}
              className="px-4 rounded-[10px] text-sm font-medium transition-colors"
              style={{ ...inputStyle, minHeight: 44 }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              className="inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
              style={{
                minHeight: 44,
                background: "var(--accent-primary)",
                color: "var(--text-on-accent)",
              }}
            >
              {submitting ? (
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
              ) : (
                <Plus className="w-4 h-4" aria-hidden />
              )}
              {submitting ? "Creating..." : "Create connector"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Edit-connector modal: activate/deactivate, scopes, policy, rate limit,
// and optional credential rotation (blank fields keep the stored set).
// ---------------------------------------------------------------------------

function EditConnectorModal({
  connector,
  onClose,
  onUpdated,
}: {
  connector: Connector;
  onClose: () => void;
  onUpdated: (c: Connector) => void;
}) {
  const service = SERVICES.find((s) => s.value === connector.connector_type);
  // Legacy connector types with no service definition (e.g. "custom") can
  // still rotate a single API key.
  const credentialFields: FieldDef[] = service?.fields ?? [
    {
      key: "api_key",
      label: "API key",
      type: "password",
      placeholder: "Paste the new API key",
      required: true,
    },
  ];
  const hasPresetScopes =
    (service?.readScopes.length ?? 0) + (service?.writeScopes.length ?? 0) > 0;

  const [displayName, setDisplayName] = useState(connector.display_name);
  const [isActive, setIsActive] = useState(connector.is_active);
  const [selectedScopes, setSelectedScopes] = useState<string[]>(
    connector.granted_scopes,
  );
  const [scopesText, setScopesText] = useState(
    connector.granted_scopes.join(", "),
  );
  const [permissionTier, setPermissionTier] = useState<PermissionTier>(
    connector.permission_tier,
  );
  const [rateLimit, setRateLimit] = useState(connector.rate_limit_per_minute);
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const ids = {
    title: useId(),
    status: useId(),
    displayName: useId(),
    scopes: useId(),
    scopesText: useId(),
    tier: useId(),
    rate: useId(),
    field: useId(),
  };

  // Also supplies Escape, so the hand-rolled key listener this replaced is
  // gone — the trap has to own both to keep them from disagreeing.
  useFocusTrap(true, panelRef, onClose);

  // Chips show the service presets plus anything already granted (covers
  // scopes granted before a preset change). A handful of strings, only ever
  // mapped straight into JSX, so it is not worth a useMemo — whose
  // dependency on the looked-up `service` object the React Compiler could
  // not prove stable, which made it skip this whole component.
  const scopeOptions = Array.from(
    new Set<string>([
      ...(service?.readScopes ?? []),
      ...(service?.writeScopes ?? []),
      ...connector.granted_scopes,
    ]),
  );

  // TIER_OPTIONS omits hard_blocked; keep the current tier selectable if it
  // is outside the normal choices.
  const tierOptions = TIER_OPTIONS.some(
    (o) => o.value === connector.permission_tier,
  )
    ? TIER_OPTIONS
    : [
        {
          value: connector.permission_tier,
          label:
            tierLabels[connector.permission_tier]?.label ??
            connector.permission_tier,
        },
        ...TIER_OPTIONS,
      ];

  // Credentials replace the stored set wholesale on the server, so a partial
  // re-entry would silently drop the untouched fields. Require the same
  // fields as creation once any credential field is filled.
  const anyCredentialEntered = credentialFields.some(
    (f) => (fieldValues[f.key] ?? "").trim() !== "",
  );
  const credentialsComplete =
    !anyCredentialEntered ||
    credentialFields
      .filter((f) => f.required)
      .every((f) => (fieldValues[f.key] ?? "").trim() !== "");
  const canSubmit = displayName.trim() !== "" && credentialsComplete && !submitting;

  const buildCredentials = (): Record<string, unknown> => {
    const credentials: Record<string, unknown> = {};
    for (const field of credentialFields) {
      const raw = (fieldValues[field.key] ?? "").trim();
      if (!raw) continue;
      if (field.key === "headers_json") {
        credentials["headers"] = JSON.parse(raw);
      } else {
        credentials[field.key] = raw;
      }
    }
    return credentials;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const scopes = hasPresetScopes
        ? selectedScopes
        : scopesText
            .split(/[\n,]/)
            .map((s) => s.trim())
            .filter(Boolean);
      const payload: UpdateConnectorRequest = {
        display_name: displayName.trim(),
        is_active: isActive,
        granted_scopes: scopes,
        permission_tier: permissionTier,
        rate_limit_per_minute: rateLimit,
      };
      if (anyCredentialEntered) {
        payload.credentials = buildCredentials();
      }
      const updated = await updateConnector(connector.id, payload);
      onUpdated(updated);
    } catch (err) {
      const message =
        err instanceof SyntaxError
          ? "Headers must be valid JSON."
          : (err as Error).message || "Failed to update connector";
      setError(message);
      setSubmitting(false);
    }
  };

  const TypeIcon = connectorIcons[connector.connector_type] || Plug;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "var(--scrim)", backdropFilter: "blur(2px)" }}
      onClick={onClose}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={ids.title}
        className="w-full max-w-lg rounded-[16px] max-h-[90dvh] overflow-y-auto"
        style={{ ...panelStyle, boxShadow: "var(--shadow-modal)" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between px-4 sm:px-6 py-4"
          style={{ borderBottom: "1px solid var(--border-subtle)" }}
        >
          <div className="flex items-center gap-3 min-w-0">
            <div
              aria-hidden
              className="w-9 h-9 rounded-[10px] flex items-center justify-center shrink-0"
              style={{
                background: "var(--accent-glow)",
                border: "1px solid var(--border-accent)",
              }}
            >
              <TypeIcon
                className="w-4 h-4"
                style={{ color: "var(--accent-primary)" }}
              />
            </div>
            <div className="min-w-0">
              <div className="eyebrow">{connector.connector_type}</div>
              <h2 id={ids.title} className="h3" style={{ color: "var(--text-primary)" }}>
                Edit connector
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center justify-center rounded-md transition-colors shrink-0"
            style={{ width: 44, height: 44, color: "var(--text-muted)" }}
            aria-label="Close"
          >
            <X className="w-5 h-5" aria-hidden />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="px-4 sm:px-6 py-5 flex flex-col gap-4">
            {error && (
              <div
                role="alert"
                className="px-3 py-2.5 rounded-[8px] text-sm"
                style={{
                  background: "var(--fill-danger)",
                  color: "var(--accent-danger)",
                  border: "1px solid var(--border-danger)",
                }}
              >
                {error}
              </div>
            )}

            <div>
              <span id={ids.status} className={labelCls}>
                Status
              </span>
              <button
                type="button"
                onClick={() => setIsActive((v) => !v)}
                role="switch"
                aria-checked={isActive}
                aria-labelledby={ids.status}
                className="inline-flex items-center gap-2 px-3.5 rounded-[10px] text-sm font-medium transition-colors"
                style={{
                  minHeight: 44,
                  background: isActive
                    ? "var(--fill-success)"
                    : "var(--fill-neutral)",
                  border: isActive
                    ? "1px solid var(--border-success)"
                    : "1px solid var(--claw-border)",
                  color: isActive ? "var(--accent-success)" : "var(--text-muted)",
                }}
              >
                <Power className="w-4 h-4" aria-hidden />
                {isActive ? "Active" : "Inactive"}
              </button>
              <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                Inactive connectors keep their encrypted credentials, but the
                agent cannot use them until reactivated.
              </p>
            </div>

            <div>
              <label htmlFor={ids.displayName} className={labelCls}>
                Display name
              </label>
              <input
                id={ids.displayName}
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className={fieldCls}
                style={inputStyle}
                required
              />
            </div>

            {hasPresetScopes ? (
              <div>
                <span id={ids.scopes} className={labelCls}>
                  Permissions to grant
                </span>
                <div
                  role="group"
                  aria-labelledby={ids.scopes}
                  className="flex flex-wrap gap-2"
                >
                  {scopeOptions.map((scope) => (
                    <ScopeChip
                      key={scope}
                      scope={scope}
                      selected={selectedScopes.includes(scope)}
                      onToggle={() =>
                        setSelectedScopes((prev) =>
                          prev.includes(scope)
                            ? prev.filter((s) => s !== scope)
                            : [...prev, scope]
                        )
                      }
                    />
                  ))}
                </div>
                <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                  Anything the agent is not granted here is refused at
                  execution time. Changes apply immediately.
                </p>
              </div>
            ) : (
              <div>
                <label htmlFor={ids.scopesText} className={labelCls}>
                  Granted scopes{" "}
                  <span style={{ color: "var(--text-muted)" }}>(comma-separated)</span>
                </label>
                <input
                  id={ids.scopesText}
                  type="text"
                  value={scopesText}
                  onChange={(e) => setScopesText(e.target.value)}
                  className={fieldCls}
                  style={inputStyle}
                  placeholder="resource.read, resource.write"
                />
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor={ids.tier} className={labelCls}>
                  Approval policy
                </label>
                <select
                  id={ids.tier}
                  value={permissionTier}
                  onChange={(e) =>
                    setPermissionTier(e.target.value as PermissionTier)
                  }
                  className={fieldCls}
                  style={inputStyle}
                >
                  {tierOptions.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor={ids.rate} className={labelCls}>
                  Rate limit (/min)
                </label>
                <input
                  id={ids.rate}
                  type="number"
                  min={1}
                  max={600}
                  value={rateLimit}
                  onChange={(e) =>
                    setRateLimit(
                      Math.max(1, Math.min(600, Number(e.target.value) || 1))
                    )
                  }
                  className={fieldCls}
                  style={inputStyle}
                />
              </div>
            </div>

            <div>
              <div className="eyebrow mb-2">Replace credentials (optional)</div>
              <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
                Stored credentials are never displayed. Leave every field blank
                to keep them; filling any field replaces the whole stored set,
                so complete all required fields.
              </p>
              <div className="flex flex-col gap-4">
                {credentialFields.map((field) => (
                  <div key={field.key}>
                    <label htmlFor={`${ids.field}-${field.key}`} className={labelCls}>
                      {field.label}
                    </label>
                    <input
                      id={`${ids.field}-${field.key}`}
                      type={field.type}
                      value={fieldValues[field.key] ?? ""}
                      onChange={(e) =>
                        setFieldValues((prev) => ({
                          ...prev,
                          [field.key]: e.target.value,
                        }))
                      }
                      className={fieldCls}
                      style={inputStyle}
                      placeholder="Leave blank to keep existing"
                      autoComplete="off"
                    />
                    {field.hint && (
                      <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                        {field.hint}
                      </p>
                    )}
                  </div>
                ))}
              </div>
              {anyCredentialEntered && !credentialsComplete && (
                <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-warning)" }}>
                  Re-entering credentials replaces the stored set — fill in all
                  required fields.
                </p>
              )}
            </div>
          </div>

          <div
            className="flex items-center justify-end gap-2 px-4 sm:px-6 py-4"
            style={{
              borderTop: "1px solid var(--border-subtle)",
              background: "var(--claw-surface)",
            }}
          >
            <button
              type="button"
              onClick={onClose}
              className="px-4 rounded-[10px] text-sm font-medium transition-colors"
              style={{ ...inputStyle, minHeight: 44 }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              className="inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
              style={{
                minHeight: 44,
                background: "var(--accent-primary)",
                color: "var(--text-on-accent)",
              }}
            >
              {submitting ? (
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
              ) : (
                <Check className="w-4 h-4" aria-hidden />
              )}
              {submitting ? "Saving..." : "Save changes"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function Connectors() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [editTarget, setEditTarget] = useState<Connector | null>(null);

  // The only way to re-run the fetch below after mount, so the loading state
  // flips here, in the click, rather than in an extra render from the effect.
  const refresh = () => {
    setLoading(true);
    setError(null);
    setRefreshKey((k) => k + 1);
  };

  useEffect(() => {
    let cancelled = false;
    getConnectors()
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
  }, [refreshKey]);

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
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
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
            onClick={refresh}
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 px-3.5 rounded-[10px] text-sm font-medium disabled:opacity-50"
            style={{ ...inputStyle, minHeight: 44 }}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => setShowAdd(true)}
            className="flex items-center justify-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all"
            style={{
              minHeight: 44,
              background: "var(--accent-primary)",
              color: "var(--text-on-accent)",
            }}
            onMouseOver={(e) => (e.currentTarget.style.filter = "brightness(1.1)")}
            onMouseOut={(e) => (e.currentTarget.style.filter = "none")}
          >
            <Plus className="w-4 h-4" aria-hidden /> Add Connector
          </button>
        </div>
      </div>

      {loading && (
        <div
          role="status"
          className="rounded-[14px] p-8 flex items-center justify-center gap-2"
          style={{ ...panelStyle, color: "var(--text-muted)" }}
        >
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          <span className="text-sm">Loading connectors...</span>
        </div>
      )}

      {!loading && error && (
        <div
          className="rounded-[14px] p-6 flex flex-col items-center gap-3 text-center"
          style={{ ...panelStyle }}
        >
          <p role="alert" className="text-sm" style={{ color: "var(--accent-danger)" }}>
            {error}
          </p>
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 px-3.5 rounded-[10px] text-sm font-medium"
            style={{ ...inputStyle, minHeight: 44 }}
          >
            <RefreshCw className="w-4 h-4" aria-hidden />
            Try again
          </button>
        </div>
      )}

      {!loading && !error && connectors.length === 0 && (
        <div
          className="rounded-[14px] border-2 border-dashed p-12 flex flex-col items-center justify-center gap-3 text-center"
          style={{
            borderColor: "var(--claw-border)",
            color: "var(--text-muted)",
          }}
        >
          <Plug className="w-10 h-10" aria-hidden />
          <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
            No connectors yet
          </p>
          <p className="text-xs max-w-sm">
            Connect Canvas, Google Workspace, Robinhood, or an MCP server so
            the agent can act on your behalf — every action stays governed by
            your granted scopes and approval policy.
          </p>
          <button
            type="button"
            onClick={() => setShowAdd(true)}
            className="mt-2 inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all"
            style={{
              minHeight: 44,
              background: "var(--accent-primary)",
              color: "var(--text-on-accent)",
            }}
            onMouseOver={(e) => (e.currentTarget.style.filter = "brightness(1.1)")}
            onMouseOut={(e) => (e.currentTarget.style.filter = "none")}
          >
            <Plus className="w-4 h-4" aria-hidden /> Add Connector
          </button>
        </div>
      )}

      {!loading && !error && connectors.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {connectors.map((c) => (
            <ConnectorCard
              key={c.id}
              connector={c}
              onDelete={() => handleDelete(c.id)}
              onEdit={() => setEditTarget(c)}
            />
          ))}
        </div>
      )}

      {showAdd && (
        <AddConnectorModal
          onClose={() => setShowAdd(false)}
          onCreated={(c) => {
            setConnectors((prev) => [c, ...prev]);
            setShowAdd(false);
          }}
        />
      )}

      {editTarget && (
        <EditConnectorModal
          connector={editTarget}
          onClose={() => setEditTarget(null)}
          onUpdated={(updated) => {
            setConnectors((prev) =>
              prev.map((c) => (c.id === updated.id ? updated : c))
            );
            setEditTarget(null);
          }}
        />
      )}
    </div>
  );
}
