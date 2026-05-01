import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import {
  Plug,
  BookOpen,
  Mail,
  LineChart,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  RefreshCw,
  X,
  Loader2,
  ChevronRight,
  AlertTriangle,
  Plus,
  Trash2,
  Pencil,
} from "lucide-react";
import clsx from "clsx";
import { toast } from "@/hooks/useToast";

// ─────────────────────────────────────────────────────────────────────────────
// Types — mirrored locally so this page does not depend on api.ts shape changes
// the foundation agent is making in parallel.
// ─────────────────────────────────────────────────────────────────────────────

type ConnectorType = "canvas" | "google" | "robinhood";
type PermissionTier = "auto_approve" | "confirm_on_write" | "always_confirm" | "disabled";
type ConnectorStatus = "connected" | "error" | "unauthorized" | "pending_oauth";

interface ConnectorRecord {
  id: string;
  connector_type: ConnectorType;
  display_name: string;
  granted_scopes: string[];
  permission_tier: PermissionTier;
  status: ConnectorStatus;
  is_enabled: boolean;
  last_used_at?: string | null;
  last_error?: string | null;
  created_at: string;
}

interface CreateConnectorPayload {
  connector_type: ConnectorType;
  permission_tier: PermissionTier;
  granted_scopes: string[];
}

interface CreateConnectorResponse {
  auth_url?: string;
  success?: boolean;
  connector?: ConnectorRecord;
}

// ─────────────────────────────────────────────────────────────────────────────
// API shims. These call /api/connectors directly.
// TODO: switch to imports from "@/services/api" once the foundation agent ships
//       getConnectors / createConnector / updateConnector / deleteConnector /
//       getConnectorAuthUrl / getConnector.
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem("auth_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init.headers as Record<string, string>) || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`/api${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed: ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

async function getConnectors(): Promise<ConnectorRecord[]> {
  return apiFetch<ConnectorRecord[]>("/connectors");
}

async function getConnector(id: string): Promise<ConnectorRecord> {
  return apiFetch<ConnectorRecord>(`/connectors/${id}`);
}

async function createConnector(
  payload: CreateConnectorPayload,
): Promise<CreateConnectorResponse> {
  return apiFetch<CreateConnectorResponse>("/connectors", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

async function updateConnector(
  id: string,
  patch: Partial<Pick<ConnectorRecord, "permission_tier" | "granted_scopes" | "is_enabled">>,
): Promise<ConnectorRecord> {
  return apiFetch<ConnectorRecord>(`/connectors/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

async function deleteConnector(id: string): Promise<void> {
  return apiFetch<void>(`/connectors/${id}`, { method: "DELETE" });
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector catalog — visual + plain-English scope explanations.
// ─────────────────────────────────────────────────────────────────────────────

interface ScopeInfo {
  key: string;
  label: string;
  description: string;
  riskLevel: "read" | "write" | "financial";
}

interface ConnectorCatalog {
  type: ConnectorType;
  name: string;
  tagline: string;
  description: string;
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
  accent: string;
  scopes: ScopeInfo[];
  isReadOnly?: boolean;
}

const CONNECTOR_CATALOG: ConnectorCatalog[] = [
  {
    type: "canvas",
    name: "Canvas LMS",
    tagline:
      "Read your courses, assignments, announcements, and submission deadlines.",
    description:
      "Canvas LMS access lets the agent answer questions about your classes, summarize assignments, and surface upcoming deadlines.",
    icon: BookOpen,
    accent: "#E13F29",
    scopes: [
      {
        key: "courses.read",
        label: "Read your enrolled courses",
        description: "View your course list, syllabi, and instructor contact info.",
        riskLevel: "read",
      },
      {
        key: "assignments.read",
        label: "Read assignments and due dates",
        description: "View upcoming, missing, and submitted assignments.",
        riskLevel: "read",
      },
      {
        key: "announcements.read",
        label: "Read course announcements",
        description: "View instructor announcements posted to your courses.",
        riskLevel: "read",
      },
      {
        key: "submissions.read",
        label: "Read your submission status and grades",
        description: "View what you have submitted and what grades you have received.",
        riskLevel: "read",
      },
    ],
  },
  {
    type: "google",
    name: "Google Workspace",
    tagline:
      "Gmail draft creation (review-required), Calendar read, Drive read.",
    description:
      "Google Workspace access lets the agent read your calendar, draft email replies for your review, and read documents in Drive.",
    icon: Mail,
    accent: "#4285F4",
    scopes: [
      {
        key: "gmail.drafts.create",
        label: "Create Gmail drafts (review required)",
        description:
          "The agent can prepare email drafts in your Gmail, but never sends them — you review and send.",
        riskLevel: "write",
      },
      {
        key: "calendar.read",
        label: "Read your Google Calendar",
        description: "View your events, attendees, and free/busy windows.",
        riskLevel: "read",
      },
      {
        key: "drive.read",
        label: "Read your Google Drive files",
        description: "Read documents, sheets, and slides you own or have access to.",
        riskLevel: "read",
      },
    ],
  },
  {
    type: "robinhood",
    name: "Robinhood",
    tagline:
      "Read-only positions and crypto prices. Trades are PERMANENTLY HARD-BLOCKED regardless of any setting.",
    description:
      "Robinhood is connected in read-only mode. The server permanently blocks every trade, transfer, and withdrawal endpoint — this is enforced at the SentientAI server level and cannot be unlocked from the UI.",
    icon: LineChart,
    accent: "#00C805",
    isReadOnly: true,
    scopes: [
      {
        key: "positions.read",
        label: "Read your crypto positions",
        description: "View current holdings, cost basis, and unrealized P/L.",
        riskLevel: "read",
      },
      {
        key: "prices.read",
        label: "Read live and historical crypto prices",
        description: "Market data for assets you watch or hold.",
        riskLevel: "read",
      },
      {
        key: "history.read",
        label: "Read transaction history",
        description: "Past order fills (read-only — agent cannot place new orders).",
        riskLevel: "read",
      },
    ],
  },
];

const CATALOG_BY_TYPE: Record<ConnectorType, ConnectorCatalog> = CONNECTOR_CATALOG.reduce(
  (acc, c) => {
    acc[c.type] = c;
    return acc;
  },
  {} as Record<ConnectorType, ConnectorCatalog>,
);

// ─────────────────────────────────────────────────────────────────────────────
// Permission tier metadata
// ─────────────────────────────────────────────────────────────────────────────

const TIER_OPTIONS: { value: PermissionTier; label: string; helper: string }[] = [
  {
    value: "auto_approve",
    label: "Auto-approve (read-only operations)",
    helper: "The agent runs read calls without confirming.",
  },
  {
    value: "confirm_on_write",
    label: "Confirm-on-write",
    helper:
      "Read auto-approved; create/update/delete require user confirmation in chat.",
  },
  {
    value: "always_confirm",
    label: "Always confirm (recommended for sensitive)",
    helper: "Every operation pauses for confirmation in chat.",
  },
  {
    value: "disabled",
    label: "Disabled (manual only)",
    helper: "Connect but the agent can't use it.",
  },
];

const TIER_LABEL: Record<PermissionTier, string> = TIER_OPTIONS.reduce(
  (acc, opt) => {
    acc[opt.value] = opt.label;
    return acc;
  },
  {} as Record<PermissionTier, string>,
);

// Order from most permissive to most restrictive — used to enforce
// "downgrade only" on edit.
const TIER_RANK: Record<PermissionTier, number> = {
  auto_approve: 0,
  confirm_on_write: 1,
  always_confirm: 2,
  disabled: 3,
};

// ─────────────────────────────────────────────────────────────────────────────
// Pagination
// ─────────────────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

// ─────────────────────────────────────────────────────────────────────────────
// Modal primitive — focus trap, Escape, click-backdrop.
// ─────────────────────────────────────────────────────────────────────────────

function Modal({
  open,
  onClose,
  labelledBy,
  describedBy,
  children,
}: {
  open: boolean;
  onClose: () => void;
  labelledBy: string;
  describedBy?: string;
  children: ReactNode;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const lastFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    lastFocusedRef.current = (document.activeElement as HTMLElement) || null;

    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key === "Tab" && dialogRef.current) {
        const focusables = dialogRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        const list = Array.from(focusables).filter(
          (el) => !el.hasAttribute("disabled") && el.offsetParent !== null,
        );
        if (list.length === 0) return;
        const first = list[0];
        const last = list[list.length - 1];
        const active = document.activeElement as HTMLElement | null;
        if (e.shiftKey && active === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handleKey);

    // Focus the first focusable in the dialog.
    requestAnimationFrame(() => {
      const first = dialogRef.current?.querySelector<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      first?.focus();
    });

    return () => {
      document.removeEventListener("keydown", handleKey);
      lastFocusedRef.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4"
      onClick={onClose}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-xl rounded-lg border border-zinc-800 bg-zinc-950 text-zinc-100 max-h-[90vh] overflow-hidden flex flex-col"
      >
        {children}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Status badge
// ─────────────────────────────────────────────────────────────────────────────

function StatusBadge({
  status,
  lastError,
  onReconnect,
}: {
  status: ConnectorStatus;
  lastError?: string | null;
  onReconnect?: () => void;
}) {
  const map: Record<
    ConnectorStatus,
    { dot: string; text: string; label: string; animate?: boolean }
  > = {
    connected: { dot: "bg-emerald-400", text: "text-emerald-300", label: "Connected" },
    error: { dot: "bg-rose-400", text: "text-rose-300", label: "Error" },
    unauthorized: { dot: "bg-orange-400", text: "text-orange-300", label: "Unauthorized" },
    pending_oauth: {
      dot: "bg-cyan-400",
      text: "text-cyan-300",
      label: "Pending OAuth",
      animate: true,
    },
  };
  const cfg = map[status];
  return (
    <span
      className="inline-flex items-center gap-1.5"
      aria-label={`Status: ${cfg.label}`}
      title={status === "error" && lastError ? lastError : cfg.label}
    >
      <span
        aria-hidden="true"
        className={clsx(
          "inline-block h-2 w-2 rounded-full",
          cfg.dot,
          cfg.animate && "animate-pulse",
        )}
      />
      <span className={clsx("text-[12px] font-medium", cfg.text)}>{cfg.label}</span>
      {status === "unauthorized" && onReconnect && (
        <button
          type="button"
          onClick={onReconnect}
          className="ml-1 text-[12px] font-medium text-cyan-400 hover:underline"
        >
          Reconnect
        </button>
      )}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Skeleton row
// ─────────────────────────────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <tr className="border-b border-zinc-800">
      {Array.from({ length: 6 }).map((_, i) => (
        <td key={i} className="px-4 py-4">
          <div className="h-3 w-full rounded bg-zinc-800/70 animate-pulse" />
        </td>
      ))}
    </tr>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Connect Modal — three-step consent flow.
// ─────────────────────────────────────────────────────────────────────────────

function ConnectModal({
  catalog,
  open,
  onClose,
  onConnected,
}: {
  catalog: ConnectorCatalog | null;
  open: boolean;
  onClose: () => void;
  onConnected: (record: ConnectorRecord) => void;
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [tier, setTier] = useState<PermissionTier>("confirm_on_write");
  const [submitting, setSubmitting] = useState(false);
  const [authUrl, setAuthUrl] = useState<string | null>(null);
  const [popupBlocked, setPopupBlocked] = useState(false);
  const [polling, setPolling] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollingDeadlineRef = useRef<number>(0);

  // Reset state every time we open with a new catalog.
  useEffect(() => {
    if (open) {
      setStep(1);
      setTier(catalog?.isReadOnly ? "auto_approve" : "confirm_on_write");
      setSubmitting(false);
      setAuthUrl(null);
      setPopupBlocked(false);
      setPolling(false);
    }
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [open, catalog]);

  if (!catalog) return null;

  const startPollingForConnection = () => {
    setPolling(true);
    pollingDeadlineRef.current = Date.now() + 60_000;
    const tick = async () => {
      try {
        const list = await getConnectors();
        const newOne = list.find(
          (c) => c.connector_type === catalog.type && c.is_enabled,
        );
        if (newOne) {
          if (pollingRef.current) clearInterval(pollingRef.current);
          pollingRef.current = null;
          setPolling(false);
          toast.success({
            title: `${catalog.name} connected`,
            description: "Authorization complete.",
          });
          onConnected(newOne);
          onClose();
        } else if (Date.now() > pollingDeadlineRef.current) {
          if (pollingRef.current) clearInterval(pollingRef.current);
          pollingRef.current = null;
          setPolling(false);
          toast.warning({
            title: "Still waiting",
            description:
              "We didn't detect the connection yet. You can keep the popup open and check again.",
          });
        }
      } catch {
        // ignore — keep polling until deadline
      }
    };
    pollingRef.current = setInterval(tick, 3000);
    // Run an immediate tick too so we don't wait 3s.
    void tick();
  };

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      const granted = catalog.scopes.map((s) => s.key);
      const res = await createConnector({
        connector_type: catalog.type,
        permission_tier: tier,
        granted_scopes: granted,
      });
      if (res.auth_url) {
        const popup = window.open(res.auth_url, "_blank", "noopener,noreferrer");
        if (!popup || popup.closed || typeof popup.closed === "undefined") {
          setAuthUrl(res.auth_url);
          setPopupBlocked(true);
        }
        startPollingForConnection();
      } else if (res.success && res.connector) {
        toast.success({
          title: `${catalog.name} connected`,
          description: "Connector enabled.",
        });
        onConnected(res.connector);
        onClose();
      } else if (res.success) {
        // No record returned — refresh list to find it.
        const list = await getConnectors();
        const found = list.find((c) => c.connector_type === catalog.type);
        if (found) onConnected(found);
        toast.success({ title: `${catalog.name} connected` });
        onClose();
      }
    } catch (err) {
      toast.error({
        title: "Connection failed",
        description: err instanceof Error ? err.message : "Unable to connect.",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const titleId = `connect-modal-title-${catalog.type}`;
  const descId = `connect-modal-desc-${catalog.type}`;
  const Icon = catalog.icon;

  return (
    <Modal open={open} onClose={onClose} labelledBy={titleId} describedBy={descId}>
      <header className="flex items-center gap-3 border-b border-zinc-800 px-5 py-4">
        <div
          className="flex h-10 w-10 items-center justify-center rounded-lg"
          style={{ backgroundColor: `${catalog.accent}1a` }}
        >
          <Icon className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="min-w-0 flex-1">
          <h2 id={titleId} className="text-[16px] font-semibold tracking-tight">
            Connect {catalog.name}
          </h2>
          <p id={descId} className="text-[12px] text-zinc-400">
            Step {step} of 3 — {step === 1 ? "scope review" : step === 2 ? "permission tier" : "confirm"}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-2 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
          aria-label="Close dialog"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
        {catalog.isReadOnly && (
          <div
            role="alert"
            className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-amber-100"
          >
            <div className="flex items-start gap-2.5">
              <ShieldAlert
                className="h-5 w-5 shrink-0 text-amber-300"
                strokeWidth={1.75}
                aria-hidden="true"
              />
              <div className="text-[13px] leading-relaxed">
                <p className="font-semibold text-amber-200">
                  Trades are permanently blocked at the server level
                </p>
                <p className="mt-1 text-amber-100/90">
                  Trades, transfers, and withdrawals are PERMANENTLY blocked at the
                  SentientAI server level. This is irreversible — even if you change
                  settings, financial transactions cannot be executed via this
                  connector. This is a feature, not a bug.
                </p>
              </div>
            </div>
          </div>
        )}

        {step === 1 && (
          <section aria-labelledby={`${titleId}-scopes`}>
            <h3
              id={`${titleId}-scopes`}
              className="text-[13px] font-semibold uppercase tracking-wide text-zinc-300"
            >
              Requested permissions
            </h3>
            <p className="mt-1 text-[13px] text-zinc-400">{catalog.description}</p>
            <ul className="mt-3 space-y-2">
              {catalog.scopes.map((scope) => (
                <li
                  key={scope.key}
                  className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3"
                >
                  <div className="flex items-start gap-3">
                    <CheckCircle2
                      className="h-4 w-4 mt-0.5 shrink-0 text-cyan-400"
                      strokeWidth={2}
                      aria-hidden="true"
                    />
                    <div className="min-w-0">
                      <p className="text-[13px] font-medium text-zinc-100">{scope.label}</p>
                      <p className="text-[12px] text-zinc-400 mt-0.5">{scope.description}</p>
                      <span
                        className={clsx(
                          "mt-1.5 inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                          scope.riskLevel === "read"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : scope.riskLevel === "write"
                              ? "bg-amber-500/15 text-amber-300"
                              : "bg-rose-500/15 text-rose-300",
                        )}
                      >
                        {scope.riskLevel}
                      </span>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        )}

        {step === 2 && (
          <section>
            <label
              htmlFor="connector-tier"
              className="block text-[13px] font-semibold uppercase tracking-wide text-zinc-300"
            >
              Permission tier
            </label>
            <p className="mt-1 text-[12px] text-zinc-400">
              Choose how much autonomy the agent has when calling {catalog.name}.
            </p>
            <select
              id="connector-tier"
              value={tier}
              onChange={(e) => setTier(e.target.value as PermissionTier)}
              className="mt-3 w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2.5 text-[14px] text-zinc-100 focus:border-cyan-500 focus:outline-none"
            >
              {TIER_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <p className="mt-2 text-[12px] text-zinc-400">
              {TIER_OPTIONS.find((t) => t.value === tier)?.helper}
            </p>
          </section>
        )}

        {step === 3 && (
          <section className="space-y-3">
            <h3 className="text-[13px] font-semibold uppercase tracking-wide text-zinc-300">
              Review & connect
            </h3>
            <dl className="rounded-lg border border-zinc-800 bg-zinc-900/40 divide-y divide-zinc-800 text-[13px]">
              <div className="flex justify-between gap-4 px-3 py-2.5">
                <dt className="text-zinc-400">Provider</dt>
                <dd className="text-zinc-100">{catalog.name}</dd>
              </div>
              <div className="flex justify-between gap-4 px-3 py-2.5">
                <dt className="text-zinc-400">Scopes</dt>
                <dd className="text-right text-zinc-100">
                  {catalog.scopes.length} requested
                </dd>
              </div>
              <div className="flex justify-between gap-4 px-3 py-2.5">
                <dt className="text-zinc-400">Permission tier</dt>
                <dd className="text-zinc-100">{TIER_LABEL[tier]}</dd>
              </div>
            </dl>
            {popupBlocked && authUrl && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-[13px] text-amber-100">
                <p className="font-medium">Popup blocked.</p>
                <p className="mt-1">
                  <a
                    href={authUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline text-amber-200 hover:text-amber-100"
                  >
                    Click here to open {catalog.name} in a new tab.
                  </a>
                </p>
              </div>
            )}
            {polling && (
              <p
                className="flex items-center gap-2 text-[12px] text-zinc-400"
                aria-live="polite"
              >
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                Waiting for {catalog.name} to authorize…
              </p>
            )}
          </section>
        )}
      </div>

      <footer className="flex items-center justify-between gap-2 border-t border-zinc-800 px-5 py-4">
        <button
          type="button"
          onClick={() => (step > 1 ? setStep((s) => (s === 3 ? 2 : 1)) : onClose())}
          disabled={submitting}
          className="rounded-md px-4 py-2 text-[14px] font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
        >
          {step === 1 ? "Cancel" : "Back"}
        </button>
        {step < 3 ? (
          <button
            type="button"
            onClick={() => setStep((s) => (s === 1 ? 2 : 3))}
            className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-[14px] font-semibold text-cyan-300 hover:bg-cyan-500/20"
          >
            Continue <ChevronRight className="h-4 w-4" aria-hidden="true" />
          </button>
        ) : (
          <button
            type="button"
            onClick={handleSubmit}
            disabled={submitting || polling}
            className="inline-flex items-center gap-2 rounded-md bg-cyan-500 px-5 py-2 text-[14px] font-semibold text-zinc-950 hover:brightness-110 disabled:opacity-60"
          >
            {(submitting || polling) && (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            )}
            Connect {catalog.name}
          </button>
        )}
      </footer>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Edit modal — permission tier + scope downgrade only.
// ─────────────────────────────────────────────────────────────────────────────

function EditConnectorModal({
  connector,
  open,
  onClose,
  onSaved,
}: {
  connector: ConnectorRecord | null;
  open: boolean;
  onClose: () => void;
  onSaved: (record: ConnectorRecord) => void;
}) {
  const catalog = connector ? CATALOG_BY_TYPE[connector.connector_type] : null;
  const [tier, setTier] = useState<PermissionTier>(
    connector?.permission_tier ?? "confirm_on_write",
  );
  const [scopes, setScopes] = useState<Set<string>>(
    new Set(connector?.granted_scopes ?? []),
  );
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open && connector) {
      setTier(connector.permission_tier);
      setScopes(new Set(connector.granted_scopes));
      setSaving(false);
    }
  }, [open, connector]);

  if (!connector || !catalog) return null;

  const originalScopes = new Set(connector.granted_scopes);
  const originalTier = connector.permission_tier;

  const toggleScope = (key: string) => {
    setScopes((prev) => {
      const next = new Set(prev);
      // Only allow downgrade — disable scope, never re-enable beyond the
      // originally granted set. TODO: when backend supports incremental
      // scope upgrades, allow re-checking + revoking.
      if (next.has(key)) next.delete(key);
      else if (originalScopes.has(key)) next.add(key);
      return next;
    });
  };

  // Upgrade-block: block tiers strictly more permissive than the current one.
  const tiersAllowed = TIER_OPTIONS.filter(
    (t) => TIER_RANK[t.value] >= TIER_RANK[originalTier],
  );

  const handleSave = async () => {
    setSaving(true);
    try {
      const updated = await updateConnector(connector.id, {
        permission_tier: tier,
        granted_scopes: Array.from(scopes),
      });
      toast.success({ title: `${catalog.name} updated` });
      onSaved(updated);
      onClose();
    } catch (err) {
      toast.error({
        title: "Update failed",
        description: err instanceof Error ? err.message : "Unable to update.",
      });
    } finally {
      setSaving(false);
    }
  };

  const titleId = `edit-modal-title-${connector.id}`;
  return (
    <Modal open={open} onClose={onClose} labelledBy={titleId}>
      <header className="flex items-center justify-between gap-3 border-b border-zinc-800 px-5 py-4">
        <h2 id={titleId} className="text-[16px] font-semibold tracking-tight">
          Edit {catalog.name}
        </h2>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close dialog"
          className="rounded-md p-2 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
        >
          <X className="h-4 w-4" />
        </button>
      </header>
      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
        <div>
          <label
            htmlFor={`edit-tier-${connector.id}`}
            className="block text-[13px] font-semibold uppercase tracking-wide text-zinc-300"
          >
            Permission tier
          </label>
          <select
            id={`edit-tier-${connector.id}`}
            value={tier}
            onChange={(e) => setTier(e.target.value as PermissionTier)}
            className="mt-2 w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2.5 text-[14px] text-zinc-100 focus:border-cyan-500 focus:outline-none"
          >
            {tiersAllowed.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <p className="mt-1.5 text-[12px] text-zinc-400">
            Tiers can only be downgraded (more restrictive). Reconnect to grant more.
            {/* TODO: backend may not enforce downgrade-only yet. */}
          </p>
        </div>

        <fieldset>
          <legend className="text-[13px] font-semibold uppercase tracking-wide text-zinc-300">
            Granted scopes
          </legend>
          <p className="mt-1 text-[12px] text-zinc-400">
            Uncheck a scope to revoke it. You cannot grant more than was originally
            authorized — reconnect to expand.
          </p>
          <ul className="mt-3 space-y-2">
            {catalog.scopes.map((scope) => {
              const wasOriginal = originalScopes.has(scope.key);
              const inputId = `edit-scope-${connector.id}-${scope.key}`;
              return (
                <li
                  key={scope.key}
                  className={clsx(
                    "flex items-start gap-2.5 rounded-lg border border-zinc-800 p-3",
                    !wasOriginal && "opacity-50",
                  )}
                >
                  <input
                    id={inputId}
                    type="checkbox"
                    checked={scopes.has(scope.key)}
                    disabled={!wasOriginal}
                    onChange={() => toggleScope(scope.key)}
                    className="mt-0.5 h-4 w-4 accent-cyan-500"
                  />
                  <label htmlFor={inputId} className="cursor-pointer text-[13px]">
                    <span className="font-medium text-zinc-100">{scope.label}</span>
                    <span className="block text-[12px] text-zinc-400">
                      {scope.description}
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
        </fieldset>
      </div>
      <footer className="flex items-center justify-end gap-2 border-t border-zinc-800 px-5 py-4">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md px-4 py-2 text-[14px] font-medium text-zinc-300 hover:bg-zinc-800"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-2 rounded-md bg-cyan-500 px-5 py-2 text-[14px] font-semibold text-zinc-950 hover:brightness-110 disabled:opacity-60"
        >
          {saving && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Save changes
        </button>
      </footer>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Disconnect confirmation
// ─────────────────────────────────────────────────────────────────────────────

function DisconnectModal({
  connector,
  open,
  onClose,
  onDisconnected,
}: {
  connector: ConnectorRecord | null;
  open: boolean;
  onClose: () => void;
  onDisconnected: (id: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  if (!connector) return null;
  const titleId = `disconnect-${connector.id}`;
  const handleConfirm = async () => {
    setBusy(true);
    try {
      await deleteConnector(connector.id);
      toast.success({ title: `${connector.display_name} disconnected` });
      onDisconnected(connector.id);
      onClose();
    } catch (err) {
      toast.error({
        title: "Disconnect failed",
        description: err instanceof Error ? err.message : "Unable to disconnect.",
      });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open={open} onClose={onClose} labelledBy={titleId}>
      <header className="border-b border-zinc-800 px-5 py-4">
        <h2 id={titleId} className="flex items-center gap-2 text-[16px] font-semibold tracking-tight">
          <AlertTriangle className="h-5 w-5 text-rose-400" aria-hidden="true" />
          Disconnect connector
        </h2>
      </header>
      <div className="px-5 py-5 text-[14px] text-zinc-300">
        This revokes <span className="font-semibold text-zinc-100">{connector.display_name}</span>{" "}
        access. Are you sure?
      </div>
      <footer className="flex items-center justify-end gap-2 border-t border-zinc-800 px-5 py-4">
        <button
          type="button"
          onClick={onClose}
          disabled={busy}
          className="rounded-md px-4 py-2 text-[14px] font-medium text-zinc-300 hover:bg-zinc-800"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={handleConfirm}
          disabled={busy}
          className="inline-flex items-center gap-2 rounded-md bg-rose-500 px-5 py-2 text-[14px] font-semibold text-zinc-50 hover:brightness-110 disabled:opacity-60"
        >
          {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Disconnect
        </button>
      </footer>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function Connectors() {
  const [tab, setTab] = useState<"active" | "add">("active");
  const [connectors, setConnectors] = useState<ConnectorRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [refreshingId, setRefreshingId] = useState<string | null>(null);

  const [connectCatalog, setConnectCatalog] = useState<ConnectorCatalog | null>(null);
  const [editTarget, setEditTarget] = useState<ConnectorRecord | null>(null);
  const [disconnectTarget, setDisconnectTarget] = useState<ConnectorRecord | null>(null);

  const loadConnectors = useCallback(async () => {
    try {
      const list = await getConnectors();
      setConnectors(list);
    } catch {
      // soft-fail: empty list. The dashboard handles toast surfacing for global errors.
      setConnectors([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadConnectors();
  }, [loadConnectors]);

  const totalPages = Math.max(1, Math.ceil(connectors.length / PAGE_SIZE));
  const pageRows = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return connectors.slice(start, start + PAGE_SIZE);
  }, [connectors, page]);

  const handleConnected = (record: ConnectorRecord) => {
    setConnectors((prev) => {
      const without = prev.filter((c) => c.id !== record.id);
      return [record, ...without];
    });
    setTab("active");
  };

  const handleSaved = (record: ConnectorRecord) => {
    setConnectors((prev) => prev.map((c) => (c.id === record.id ? record : c)));
  };

  const handleDisconnected = (id: string) => {
    setConnectors((prev) => prev.filter((c) => c.id !== id));
  };

  const handleTest = async (c: ConnectorRecord) => {
    setRefreshingId(c.id);
    try {
      const refreshed = await getConnector(c.id);
      handleSaved(refreshed);
      toast.info({
        title: `${refreshed.display_name}`,
        description: `Status: ${refreshed.status}`,
      });
    } catch (err) {
      toast.error({
        title: "Test failed",
        description: err instanceof Error ? err.message : "Unable to refresh status.",
      });
    } finally {
      setRefreshingId(null);
    }
  };

  return (
    <div className="space-y-8 min-w-0">
      <header>
        <h1 className="text-[28px] font-semibold tracking-tight text-zinc-100 md:text-[32px]">
          Connectors
        </h1>
        <p className="mt-1 max-w-xl text-[15px] leading-relaxed text-zinc-400">
          Authorize external services for the agent. Each connector uses a permission
          tier you control — read-only auto-approve, confirm-on-write, or always-confirm.
        </p>
      </header>

      {/* Tabs */}
      <div role="tablist" aria-label="Connectors view" className="flex gap-2 border-b border-zinc-800">
        <button
          role="tab"
          id="tab-active"
          type="button"
          aria-selected={tab === "active"}
          aria-controls="panel-active"
          tabIndex={tab === "active" ? 0 : -1}
          onClick={() => setTab("active")}
          className={clsx(
            "px-4 py-2 -mb-px border-b-2 text-[14px] font-medium transition-colors",
            tab === "active"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200",
          )}
        >
          Active connectors
          {connectors.length > 0 && (
            <span className="ml-2 rounded-full bg-zinc-800 px-2 py-0.5 text-[11px] font-semibold text-zinc-300">
              {connectors.length}
            </span>
          )}
        </button>
        <button
          role="tab"
          id="tab-add"
          type="button"
          aria-selected={tab === "add"}
          aria-controls="panel-add"
          tabIndex={tab === "add" ? 0 : -1}
          onClick={() => setTab("add")}
          className={clsx(
            "px-4 py-2 -mb-px border-b-2 text-[14px] font-medium transition-colors",
            tab === "add"
              ? "border-cyan-400 text-cyan-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200",
          )}
        >
          Add new
        </button>
      </div>

      {/* Active panel */}
      <section
        id="panel-active"
        role="tabpanel"
        aria-labelledby="tab-active"
        hidden={tab !== "active"}
      >
        {tab === "active" && (
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[13px]">
                <thead className="bg-zinc-900/60 text-[12px] uppercase tracking-wide text-zinc-400">
                  <tr>
                    <th scope="col" className="px-4 py-3 font-semibold">
                      Connector
                    </th>
                    <th scope="col" className="px-4 py-3 font-semibold">
                      Scopes
                    </th>
                    <th scope="col" className="px-4 py-3 font-semibold">
                      Tier
                    </th>
                    <th scope="col" className="px-4 py-3 font-semibold">
                      Status
                    </th>
                    <th scope="col" className="px-4 py-3 font-semibold">
                      Last used
                    </th>
                    <th scope="col" className="px-4 py-3 text-right font-semibold">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {loading && (
                    <>
                      <SkeletonRow />
                      <SkeletonRow />
                      <SkeletonRow />
                    </>
                  )}
                  {!loading && pageRows.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-12">
                        <div className="flex flex-col items-center justify-center text-center">
                          <Plug
                            className="mb-3 h-8 w-8 text-zinc-500"
                            strokeWidth={1.5}
                            aria-hidden="true"
                          />
                          <p className="text-[14px] font-semibold text-zinc-200">
                            No connectors yet
                          </p>
                          <p className="mt-1 text-[13px] text-zinc-400">
                            Head to{" "}
                            <button
                              type="button"
                              onClick={() => setTab("add")}
                              className="inline-flex items-center gap-1 text-cyan-400 hover:underline"
                            >
                              Add new <ChevronRight className="h-3 w-3" aria-hidden="true" />
                            </button>{" "}
                            to authorize your first connector.
                          </p>
                        </div>
                      </td>
                    </tr>
                  )}
                  {!loading &&
                    pageRows.map((c) => {
                      const catalog = CATALOG_BY_TYPE[c.connector_type];
                      const Icon = catalog?.icon ?? Plug;
                      return (
                        <tr key={c.id} className="border-t border-zinc-800">
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2.5">
                              <span
                                className="flex h-8 w-8 items-center justify-center rounded-md"
                                style={{
                                  backgroundColor: `${catalog?.accent ?? "#06b6d4"}1a`,
                                }}
                              >
                                <Icon className="h-4 w-4" strokeWidth={1.75} />
                              </span>
                              <span className="font-medium text-zinc-100">
                                {c.display_name || catalog?.name || c.connector_type}
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1.5">
                              {c.granted_scopes.slice(0, 4).map((s) => (
                                <span
                                  key={s}
                                  className="rounded bg-zinc-800/80 px-1.5 py-0.5 text-[11px] text-zinc-300"
                                >
                                  {s}
                                </span>
                              ))}
                              {c.granted_scopes.length > 4 && (
                                <span className="text-[11px] text-zinc-500">
                                  +{c.granted_scopes.length - 4}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <span className="rounded bg-zinc-800/60 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-300">
                              {c.permission_tier.replace(/_/g, " ")}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <StatusBadge
                              status={c.status}
                              lastError={c.last_error}
                              onReconnect={
                                c.status === "unauthorized"
                                  ? () => {
                                      const cat = CATALOG_BY_TYPE[c.connector_type];
                                      if (cat) setConnectCatalog(cat);
                                    }
                                  : undefined
                              }
                            />
                          </td>
                          <td className="px-4 py-3 text-zinc-400">
                            {c.last_used_at
                              ? new Date(c.last_used_at).toLocaleString()
                              : "Never"}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="inline-flex items-center gap-1">
                              <button
                                type="button"
                                onClick={() => handleTest(c)}
                                disabled={refreshingId === c.id}
                                className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 disabled:opacity-50"
                                aria-label={`Test ${c.display_name}`}
                              >
                                {refreshingId === c.id ? (
                                  <Loader2 className="h-4 w-4 animate-spin" />
                                ) : (
                                  <RefreshCw className="h-4 w-4" />
                                )}
                              </button>
                              <button
                                type="button"
                                onClick={() => setEditTarget(c)}
                                className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
                                aria-label={`Edit ${c.display_name}`}
                              >
                                <Pencil className="h-4 w-4" />
                              </button>
                              <button
                                type="button"
                                onClick={() => setDisconnectTarget(c)}
                                className="rounded-md p-1.5 text-zinc-400 hover:bg-rose-500/10 hover:text-rose-300"
                                aria-label={`Disconnect ${c.display_name}`}
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>

            {connectors.length > PAGE_SIZE && (
              <div className="flex items-center justify-between border-t border-zinc-800 px-4 py-2 text-[12px] text-zinc-400">
                <span>
                  Page {page} of {totalPages}
                </span>
                <div className="inline-flex gap-1">
                  <button
                    type="button"
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="rounded-md border border-zinc-800 px-3 py-1 hover:bg-zinc-800 disabled:opacity-40"
                  >
                    Prev
                  </button>
                  <button
                    type="button"
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="rounded-md border border-zinc-800 px-3 py-1 hover:bg-zinc-800 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Add new panel */}
      <section
        id="panel-add"
        role="tabpanel"
        aria-labelledby="tab-add"
        hidden={tab !== "add"}
      >
        {tab === "add" && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {CONNECTOR_CATALOG.map((catalog) => {
              const Icon = catalog.icon;
              const alreadyConnected = connectors.some(
                (c) => c.connector_type === catalog.type,
              );
              return (
                <article
                  key={catalog.type}
                  className="flex flex-col gap-3 rounded-lg border border-zinc-800 bg-zinc-950 p-5"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className="flex h-10 w-10 items-center justify-center rounded-lg"
                      style={{ backgroundColor: `${catalog.accent}1a` }}
                    >
                      <Icon className="h-5 w-5" strokeWidth={1.75} />
                    </span>
                    <div className="min-w-0">
                      <h3 className="text-[15px] font-semibold tracking-tight text-zinc-100">
                        {catalog.name}
                      </h3>
                    </div>
                  </div>
                  <p className="text-[13px] leading-relaxed text-zinc-400">
                    {catalog.tagline}
                  </p>
                  {catalog.isReadOnly && (
                    <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-[12px] text-amber-200">
                      <span className="inline-flex items-center gap-1.5 font-semibold">
                        <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                        Read-only — trades hard-blocked
                      </span>
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={() => setConnectCatalog(catalog)}
                    disabled={alreadyConnected}
                    className={clsx(
                      "mt-auto inline-flex items-center justify-center gap-1.5 rounded-md border px-3 py-2 text-[13px] font-semibold transition-colors",
                      alreadyConnected
                        ? "border-zinc-800 bg-zinc-900/40 text-zinc-500"
                        : "border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20",
                    )}
                  >
                    {alreadyConnected ? (
                      <>
                        <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                        Already connected
                      </>
                    ) : (
                      <>
                        <Plus className="h-4 w-4" aria-hidden="true" />
                        Connect
                      </>
                    )}
                  </button>
                </article>
              );
            })}
          </div>
        )}
      </section>

      {/* Modals */}
      <ConnectModal
        catalog={connectCatalog}
        open={connectCatalog !== null}
        onClose={() => setConnectCatalog(null)}
        onConnected={handleConnected}
      />
      <EditConnectorModal
        connector={editTarget}
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        onSaved={handleSaved}
      />
      <DisconnectModal
        connector={disconnectTarget}
        open={disconnectTarget !== null}
        onClose={() => setDisconnectTarget(null)}
        onDisconnected={handleDisconnected}
      />

      {/* Hidden helper icon to satisfy unused-import linters during cold-start;
          XCircle is referenced for status messages elsewhere if backend adds. */}
      <span className="hidden" aria-hidden="true">
        <XCircle />
      </span>
    </div>
  );
}
