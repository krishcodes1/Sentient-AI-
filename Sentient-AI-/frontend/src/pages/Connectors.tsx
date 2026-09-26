/**
 * Connectors page: the user's connectors (test, edit, reconnect, grant more access, remove, and
 * Slack DM linking) and a catalog of services to connect, rendered from GET /connectors/types,
 * with one connect flow per service: browser sign-in, device code, or pasted token.
 *
 * Why it exists: every service is described once, by the backend registry, so the page builds its
 * cards, credential forms and scope pickers from that data instead of a hand-kept list. Sign-ins
 * go through the OAuth broker (/api/oauth), which the page starts and then polls; Slack DM linking
 * goes through /api/connectors/{id}/slack/link. The pure rules live in ./connectorCatalog.ts and
 * the icon map in components/connectorIcons.ts.
 */

import { createElement, useEffect, useId, useMemo, useRef, useState, type CSSProperties } from "react";
import {
  Check,
  Copy,
  ExternalLink,
  KeyRound,
  Link2,
  Loader2,
  LogIn,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  ShieldCheck,
  ShieldPlus,
  Trash2,
  Unlink,
  X,
  XCircle,
  Zap,
} from "lucide-react";
import type {
  Connector,
  ConnectorAuthKind,
  ConnectorScopeInfo,
  ConnectorTypeInfo,
  OAuthDraftRequest,
  OAuthFlowStatus,
  PermissionTier,
  SlackLinkCode,
  SlackLinkStatus,
  UpdateConnectorRequest,
} from "@/types";
import {
  ApiError,
  createConnector,
  createSlackLink,
  deleteConnector,
  getConnectorTypes,
  getConnectors,
  getOAuthStatus,
  getSlackLinkStatus,
  startDeviceOAuth,
  startOAuth,
  testConnector,
  unlinkSlack,
  updateConnector,
} from "@/services/api";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
import { errorText, inputStyle, panelStyle } from "@/components/formStyles";
import { connectorIcon } from "@/components/connectorIcons";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import {
  DEFAULT_RATE_LIMIT,
  MAX_RATE_LIMIT,
  MCP_TYPE,
  MIN_RATE_LIMIT,
  SLACK_TYPE,
  STATUS_POLL_MS,
  anyFieldEntered,
  buildCredentials,
  catalogEntries,
  clampRateLimit,
  connectOptions,
  defaultScopes,
  externalUrl,
  findEntry,
  formatTime,
  grantableScopes,
  hasScopes,
  isFormComplete,
  isPastDeadline,
  methodLabel,
  orderedSelection,
  pollDelayMs,
  reconnectScopes,
  rowKind,
  scopeView,
  signInMethods,
  toggleScope,
  visibleFieldErrors,
  type FieldValues,
  type RowKind,
  type ScopeRisk,
  type ScopeView,
  type SignInKind,
} from "./connectorCatalog";

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

const tierLabels: Record<string, { label: string; color: string }> = {
  auto_approve: { label: "Auto Approve", color: "var(--accent-success)" },
  user_confirm: { label: "User Confirm", color: "var(--accent-warning)" },
  admin_only: { label: "Admin Only", color: "var(--accent-primary)" },
  hard_blocked: { label: "Hard Blocked", color: "var(--accent-danger)" },
};

const TIER_OPTIONS: { value: PermissionTier; label: string }[] = [
  { value: "user_confirm", label: "User Confirm (recommended)" },
  { value: "auto_approve", label: "Auto Approve" },
  { value: "admin_only", label: "Admin Only" },
];

const labelCls = "block mb-1.5 text-sm text-[var(--text-secondary)]";
const fieldCls =
  "w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none transition-colors";

// Each tint carries its own fill and border rather than deriving them by
// appending an alpha suffix to `text`: `var(--accent-success)1f` is not a
// color, so those chips were rendering untinted.
const riskColors: Record<ScopeRisk, { text: string; fill: string; border: string }> = {
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
  delete: {
    text: "var(--accent-danger)",
    fill: "var(--fill-danger)",
    border: "var(--border-danger)",
  },
  financial: {
    text: "var(--accent-danger)",
    fill: "var(--fill-danger)",
    border: "var(--border-danger)",
  },
};

const infoNoticeStyle: CSSProperties = {
  background: "var(--accent-glow)",
  color: "var(--accent-primary)",
  border: "1px solid var(--border-accent)",
};

const warningNoticeStyle: CSSProperties = {
  background: "var(--fill-warning)",
  color: "var(--accent-warning)",
  border: "1px solid var(--border-warning)",
};

const primaryButtonStyle: CSSProperties = {
  minHeight: 44,
  background: "var(--accent-primary)",
  color: "var(--text-on-accent)",
};

type Feedback = { ok: boolean; text: string } | null;

function EntryIcon({
  icon,
  className,
  style,
}: {
  icon: string | null | undefined;
  className?: string;
  style?: CSSProperties;
}) {
  // createElement rather than <Icon />: the lookup returns one of a fixed
  // set of module-level icon components, never a component made here, but
  // the compiler lint cannot tell a lookup from a factory call.
  return createElement(connectorIcon(icon), { className, style, "aria-hidden": true });
}

/** The icon name for a row: MCP rows are servers, others use their catalog entry. */
function rowIcon(connector: Connector, entry: ConnectorTypeInfo | undefined): string | undefined {
  if (connector.connector_type === MCP_TYPE) return "server";
  return entry?.icon;
}

/** An external link that opens in a new tab (the desktop app hands it to the
 * system browser). Renders nothing for a value that is not an http(s) URL. */
function ExternalAnchor({
  href,
  children,
  label,
}: {
  href: string | null | undefined;
  children: React.ReactNode;
  label?: string;
}) {
  const url = externalUrl(href);
  if (!url) return null;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={label}
      className="inline-flex items-center gap-1 text-xs font-medium underline underline-offset-2"
      style={{ color: "var(--accent-primary)" }}
    >
      {children}
      <ExternalLink className="w-3 h-3" aria-hidden />
    </a>
  );
}

function openExternal(url: string): void {
  const safe = externalUrl(url);
  // noopener: the provider page gets no handle on this window. The return
  // value is null either way (and the desktop app sends the URL to the
  // system browser), so nothing depends on it; a fallback link is shown.
  if (safe) window.open(safe, "_blank", "noopener,noreferrer");
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      if (!navigator.clipboard) throw new Error("no clipboard");
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
  };
  return (
    <span className="inline-flex items-center gap-2">
      <button
        type="button"
        onClick={() => void copy()}
        aria-label={label}
        className="inline-flex items-center gap-1.5 px-3 rounded-[8px] text-xs font-medium"
        style={{ ...inputStyle, minHeight: 36 }}
      >
        {state === "copied" ? (
          <Check className="w-3.5 h-3.5" aria-hidden />
        ) : (
          <Copy className="w-3.5 h-3.5" aria-hidden />
        )}
        {state === "copied" ? "Copied" : "Copy"}
      </button>
      <span role="status" className="text-xs" style={{ color: "var(--text-muted)" }}>
        {state === "failed" ? "Copy did not work here. Select the code and copy it by hand." : ""}
      </span>
    </span>
  );
}

/**
 * Poll until told to stop. `key` names the thing being waited on (null: not
 * waiting); a new key restarts the loop and unmounting ends it. One request
 * is in flight at a time: the next poll is scheduled after the last answer.
 * `onResult`/`onError` return true to stop.
 */
function usePolling<T>(
  key: string | null,
  delayMs: number,
  poll: () => Promise<T>,
  onResult: (result: T) => boolean,
  onError: (err: unknown) => boolean,
): void {
  const handlers = useRef({ poll, onResult, onError });
  useEffect(() => {
    handlers.current = { poll, onResult, onError };
  });
  useEffect(() => {
    if (key === null) return;
    let cancelled = false;
    let timer: number | undefined;
    const tick = async () => {
      let stop: boolean;
      try {
        const result = await handlers.current.poll();
        if (cancelled) return;
        stop = handlers.current.onResult(result);
      } catch (err) {
        if (cancelled) return;
        stop = handlers.current.onError(err);
      }
      if (!stop && !cancelled) timer = window.setTimeout(() => void tick(), delayMs);
    };
    timer = window.setTimeout(() => void tick(), delayMs);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [key, delayMs]);
}

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

function AlwaysAsksBadge() {
  return (
    <span
      className="text-[10px] px-1 rounded font-semibold"
      style={{ background: "var(--fill-warning)", color: "var(--accent-warning)" }}
    >
      always asks before running
    </span>
  );
}

/** A read-only chip on a connector card. */
function ScopeTag({ view }: { view: ScopeView }) {
  const c = riskColors[view.risk];
  return (
    <div
      className="mono-tag inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px]"
      style={{ backgroundColor: c.fill, border: `1px solid ${c.border}` }}
    >
      <Check className="w-3 h-3" style={{ color: c.text }} aria-hidden />
      <span style={{ color: c.text }}>{view.scope}</span>
      {view.alwaysConfirm && <AlwaysAsksBadge />}
      {view.risk === "financial" && (
        <span
          className="text-[10px] px-1 rounded font-bold"
          style={{ backgroundColor: "var(--fill-danger)", color: "var(--accent-danger)" }}
        >
          HIGH RISK
        </span>
      )}
    </div>
  );
}

function ScopeChip({
  view,
  selected,
  onToggle,
}: {
  view: ScopeView;
  selected: boolean;
  onToggle: () => void;
}) {
  const tint = riskColors[view.risk];
  return (
    <button
      type="button"
      onClick={onToggle}
      className="mono-tag inline-flex flex-wrap items-center gap-1.5 px-2.5 rounded-[8px] transition-all text-left"
      style={{
        minHeight: 36,
        backgroundColor: selected ? tint.fill : "var(--bg-input)",
        border: `1px solid ${selected ? tint.border : "var(--claw-border)"}`,
        color: selected ? tint.text : "var(--text-muted)",
      }}
      aria-pressed={selected}
    >
      {selected ? <Check className="w-3 h-3" aria-hidden /> : <Plus className="w-3 h-3" aria-hidden />}
      <span>{view.scope}</span>
      <span className="text-[10px] opacity-80">({view.category})</span>
      {view.alwaysConfirm && <AlwaysAsksBadge />}
    </button>
  );
}

/** Read and write scopes as toggle chips, grouped, with their category. */
function ScopePicker({
  entry,
  scopes,
  selected,
  onChange,
  legend,
  hint,
}: {
  entry: ConnectorTypeInfo;
  scopes: readonly ConnectorScopeInfo[];
  selected: readonly string[];
  onChange: (next: string[]) => void;
  legend: string;
  hint: string;
}) {
  const groups = [
    { title: "Read", items: scopes.filter((s) => s.category === "read") },
    { title: "Write", items: scopes.filter((s) => s.category !== "read") },
  ].filter((g) => g.items.length > 0);
  return (
    <fieldset>
      <legend className={labelCls}>{legend}</legend>
      <div className="flex flex-col gap-3">
        {groups.map((group) => (
          <div key={group.title} role="group" aria-label={`${group.title} permissions`}>
            <div className="eyebrow mb-1.5">{group.title}</div>
            <div className="flex flex-wrap gap-2">
              {group.items.map((s) => (
                <ScopeChip
                  key={s.scope}
                  view={scopeView(entry, s.scope)}
                  selected={selected.includes(s.scope)}
                  onToggle={() => onChange(toggleScope(selected, s.scope))}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
        {hint}
      </p>
    </fieldset>
  );
}

// ---------------------------------------------------------------------------
// Form pieces
// ---------------------------------------------------------------------------

function CredentialFields({
  fields,
  values,
  onChange,
  idPrefix,
  placeholderOverride,
}: {
  fields: ConnectorTypeInfo["auth"]["fields"];
  values: FieldValues;
  onChange: (key: string, value: string) => void;
  idPrefix: string;
  placeholderOverride?: string;
}) {
  const errors = visibleFieldErrors(fields, values);
  return (
    <>
      {fields.map((field) => {
        const id = `${idPrefix}-${field.key}`;
        const problem = errors[field.key];
        const describedBy =
          [problem ? `${id}-error` : "", field.hint ? `${id}-hint` : ""].filter(Boolean).join(" ") ||
          undefined;
        return (
          <div key={field.key}>
            <label htmlFor={id} className={labelCls}>
              {field.label}
              {!field.required && (
                <span style={{ color: "var(--text-muted)" }}> (optional)</span>
              )}
            </label>
            <input
              id={id}
              // "url" is validated here rather than by the browser, so a
              // bad value shows the same message everywhere.
              type={field.type === "password" ? "password" : "text"}
              inputMode={field.type === "url" ? "url" : undefined}
              value={values[field.key] ?? ""}
              onChange={(e) => onChange(field.key, e.target.value)}
              aria-invalid={problem ? true : undefined}
              aria-describedby={describedBy}
              className={fieldCls}
              style={inputStyle}
              placeholder={placeholderOverride ?? field.placeholder}
              autoComplete="off"
              spellCheck={false}
            />
            {problem && (
              <p id={`${id}-error`} className="text-xs mt-1.5" style={{ color: "var(--accent-danger)" }}>
                {problem}
              </p>
            )}
            {field.hint && (
              <p id={`${id}-hint`} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                {field.hint}
              </p>
            )}
          </div>
        );
      })}
    </>
  );
}

function TierAndRate({
  tier,
  onTier,
  rate,
  onRate,
  tierOptions = TIER_OPTIONS,
}: {
  tier: PermissionTier;
  onTier: (t: PermissionTier) => void;
  rate: number;
  onRate: (n: number) => void;
  tierOptions?: { value: PermissionTier; label: string }[];
}) {
  const tierId = useId();
  const rateId = useId();
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <div>
        <label htmlFor={tierId} className={labelCls}>
          Approval policy
        </label>
        <select
          id={tierId}
          value={tier}
          onChange={(e) => onTier(e.target.value as PermissionTier)}
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
        <label htmlFor={rateId} className={labelCls}>
          Rate limit (/min)
        </label>
        <input
          id={rateId}
          type="number"
          min={MIN_RATE_LIMIT}
          max={MAX_RATE_LIMIT}
          value={rate}
          onChange={(e) => onRate(clampRateLimit(Number(e.target.value)))}
          className={fieldCls}
          style={inputStyle}
        />
      </div>
    </div>
  );
}

function ModalShell({
  titleId,
  eyebrow,
  title,
  icon,
  onClose,
  children,
}: {
  titleId: string;
  eyebrow: string;
  title: string;
  icon: string | undefined;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  // Also supplies Escape, so the trap owns both and they never disagree.
  useFocusTrap(true, panelRef, onClose);
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
        aria-labelledby={titleId}
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
              style={{ background: "var(--accent-glow)", border: "1px solid var(--border-accent)" }}
            >
              <EntryIcon icon={icon} className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
            </div>
            <div className="min-w-0">
              <div className="eyebrow">{eyebrow}</div>
              <h2 id={titleId} className="h3" style={{ color: "var(--text-primary)" }}>
                {title}
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
        {children}
      </div>
    </div>
  );
}

function ModalFooter({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="flex items-center justify-end gap-2 px-4 sm:px-6 py-4"
      style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--claw-surface)" }}
    >
      {children}
    </div>
  );
}

function CancelButton({ onClick, label = "Cancel" }: { onClick: () => void; label?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="px-4 rounded-[10px] text-sm font-medium transition-colors"
      style={{ ...inputStyle, minHeight: 44 }}
    >
      {label}
    </button>
  );
}

function MethodChooser({
  entry,
  methods,
  value,
  onChange,
  disabled = false,
}: {
  entry: ConnectorTypeInfo;
  methods: readonly ConnectorAuthKind[];
  value: ConnectorAuthKind;
  onChange: (m: ConnectorAuthKind) => void;
  disabled?: boolean;
}) {
  const name = useId();
  if (methods.length < 2) return null;
  return (
    <fieldset disabled={disabled} className="disabled:opacity-50">
      <legend className={labelCls}>How to connect</legend>
      <div className="flex flex-wrap gap-2">
        {methods.map((m) => (
          <label
            key={m}
            className="inline-flex items-center gap-2 px-3 rounded-[10px] text-sm cursor-pointer"
            style={{
              minHeight: 40,
              ...inputStyle,
              border: `1px solid ${value === m ? "var(--border-accent-strong)" : "var(--claw-border)"}`,
            }}
          >
            <input
              type="radio"
              name={name}
              value={m}
              checked={value === m}
              onChange={() => onChange(m)}
            />
            {methodLabel(m, entry)}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function SignInNotSetUpNote({ entry, tokenFallback }: { entry: ConnectorTypeInfo; tokenFallback: boolean }) {
  return (
    <div className="px-3 py-2.5 rounded-[8px] text-xs leading-relaxed" style={warningNoticeStyle}>
      Sign-in with {entry.label} is not set up on this server: an administrator has to add its
      OAuth client ID to the server settings first.{" "}
      {tokenFallback
        ? "You can paste a token instead."
        : "Until then this service cannot be connected here."}
    </div>
  );
}

function SlackTokensNote() {
  return (
    <div className="px-3 py-2.5 rounded-[8px] text-xs leading-relaxed" style={infoNoticeStyle}>
      Create the Crawler app in Slack from the manifest link, install it to your workspace, then
      paste its tokens: the <strong>bot token</strong> (xoxb-) lets Crawler read channels and post
      with your approval; the <strong>app-level token</strong> (xapp-) is only needed to chat with
      Crawler in Slack direct messages; the <strong>user token</strong> (xoxp-) is only needed for
      search and setting your status.
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sign-in (OAuth broker)
// ---------------------------------------------------------------------------

/** A started sign-in. It carries its own provider, so polling always asks
 * about the provider the flow was started with. */
type StartedFlow = { provider: string; flowId: string; expiresAt: string } & (
  | { kind: "oauth"; authorizationUrl: string }
  | { kind: "device"; userCode: string; verificationUri: string; interval: number }
);

/** A sign-in whose dialog closed before it finished: the page keeps
 * watching it and shows `doneText` when it completes. */
type LeftRunning = { flow: StartedFlow; doneText: string };

/** Starts a sign-in through the broker and remembers the flow to poll.
 * `start` also returns the flow (null on failure), for a caller whose
 * dialog closed while the request was in flight. */
function useSignIn(provider: string | null) {
  const [flow, setFlow] = useState<StartedFlow | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = async (kind: SignInKind, draft: OAuthDraftRequest): Promise<StartedFlow | null> => {
    if (!provider || starting) return null;
    setStarting(true);
    setError(null);
    try {
      let started: StartedFlow;
      if (kind === "oauth") {
        const res = await startOAuth(provider, draft);
        openExternal(res.authorization_url);
        started = {
          kind: "oauth",
          provider,
          flowId: res.flow_id,
          authorizationUrl: res.authorization_url,
          expiresAt: res.expires_at,
        };
      } else {
        const res = await startDeviceOAuth(provider, draft);
        started = {
          kind: "device",
          provider,
          flowId: res.flow_id,
          userCode: res.user_code,
          verificationUri: res.verification_uri,
          expiresAt: res.expires_at,
          interval: res.interval,
        };
      }
      setFlow(started);
      return started;
    } catch (err) {
      setError(errorText(err, "Could not start the sign-in. Try again."));
      return null;
    } finally {
      setStarting(false);
    }
  };

  return {
    flow,
    starting,
    error,
    start,
    reset: () => setFlow(null),
    clearError: () => setError(null),
  };
}

const FLOW_EXPIRED = "The sign-in took too long and expired. Start again.";
const FLOW_GONE = "This sign-in is no longer available. Start again.";
const FLOW_FAILED = "The sign-in did not complete.";

/**
 * Polls the broker for a started sign-in until it completes or fails.
 * The server decides when a flow has expired; this device's clock only ends
 * the wait when the server cannot be reached and the flow is past its
 * expiry plus a clock-skew grace, so a fast local clock never cuts a
 * sign-in short.
 */
function useFlowStatus(
  flow: StartedFlow,
  active: boolean,
  onComplete: (connectorId: string | undefined) => void,
  onFailure: (message: string) => void,
): void {
  usePolling<OAuthFlowStatus>(
    active ? flow.flowId : null,
    flow.kind === "device" ? pollDelayMs(flow.interval) : STATUS_POLL_MS,
    () => getOAuthStatus(flow.provider, flow.flowId),
    (result) => {
      if (result.status === "complete") {
        onComplete(result.connector_id);
        return true;
      }
      if (result.status === "error" || result.status === "expired") {
        onFailure(result.error || (result.status === "expired" ? FLOW_EXPIRED : FLOW_FAILED));
        return true;
      }
      return false;
    },
    (err) => {
      if (err instanceof ApiError && err.status === 404) {
        onFailure(FLOW_GONE);
        return true;
      }
      if (isPastDeadline(flow.expiresAt)) {
        onFailure(FLOW_EXPIRED);
        return true;
      }
      return false; // a network blip: keep waiting until the flow expires
    },
  );
}

/** Keeps watching a sign-in whose dialog was closed (the consent page may
 * still be open in the browser), so the new or renewed row shows up
 * without a manual refresh. Renders nothing. */
function SignInWatcher({
  flow,
  onComplete,
  onEnd,
}: {
  flow: StartedFlow;
  onComplete: () => void;
  onEnd: () => void;
}) {
  useFlowStatus(flow, true, onComplete, onEnd);
  return null;
}

/** Waits for a started sign-in: shows the device code or a link back to the
 * consent page, polls the broker, and reports the outcome. */
function SignInProgress({
  entry,
  flow,
  onComplete,
  onRestart,
}: {
  entry: ConnectorTypeInfo;
  flow: StartedFlow;
  onComplete: (connectorId: string | undefined) => void;
  onRestart: () => void;
}) {
  const [failure, setFailure] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  // The form this replaces held focus; keep it inside the dialog.
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  useFlowStatus(flow, failure === null, onComplete, setFailure);

  return (
    <div className="px-4 sm:px-6 py-5 flex flex-col gap-4">
      <h3 ref={headingRef} tabIndex={-1} className="text-sm font-semibold outline-none" style={{ color: "var(--text-primary)" }}>
        {flow.kind === "device" ? `Enter this code at ${entry.label}` : `Finish signing in to ${entry.label}`}
      </h3>

      {flow.kind === "device" ? (
        <>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Open <ExternalAnchor href={flow.verificationUri}>{flow.verificationUri}</ExternalAnchor> and
            enter the code below. Expires at {formatTime(flow.expiresAt) || "soon"}.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <code
              aria-label="Sign-in code"
              className="text-2xl font-semibold tracking-widest px-3 py-2 rounded-[8px]"
              style={{ ...inputStyle, userSelect: "all" }}
            >
              {flow.userCode}
            </code>
            <CopyButton text={flow.userCode} label="Copy sign-in code" />
          </div>
        </>
      ) : (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          The sign-in page opened in your browser. Approve access there and come back: this page
          updates by itself. Nothing opened?{" "}
          <ExternalAnchor href={flow.authorizationUrl}>Open the sign-in page</ExternalAnchor>
        </p>
      )}

      {failure ? (
        <div className="flex flex-col gap-3">
          <ErrorAlert>{failure}</ErrorAlert>
          <div>
            <button type="button" onClick={onRestart} className="inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold" style={primaryButtonStyle}>
              <RefreshCw className="w-4 h-4" aria-hidden />
              Start again
            </button>
          </div>
        </div>
      ) : (
        <p role="status" className="inline-flex items-center gap-2 text-sm" style={{ color: "var(--text-muted)" }}>
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          Waiting for the sign-in to finish...
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Connect modal (new connector)
// ---------------------------------------------------------------------------

function ConnectModal({
  entries,
  initialKey,
  onClose,
  onCreated,
  onSignedIn,
  onLeftRunning,
}: {
  entries: ConnectorTypeInfo[];
  initialKey: string;
  onClose: () => void;
  onCreated: (c: Connector) => void;
  onSignedIn: (label: string) => void;
  onLeftRunning: (running: LeftRunning) => void;
}) {
  const initial = findEntry(entries, initialKey) ?? entries[0];
  const [entryKey, setEntryKey] = useState(initial.key);
  const [displayName, setDisplayName] = useState("");
  const [fieldValues, setFieldValues] = useState<FieldValues>({});
  const [selectedScopes, setSelectedScopes] = useState<string[]>(defaultScopes(initial));
  const [permissionTier, setPermissionTier] = useState<PermissionTier>("user_confirm");
  const [rateLimit, setRateLimit] = useState(DEFAULT_RATE_LIMIT);
  const [chosenMethod, setChosenMethod] = useState<ConnectorAuthKind | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ids = { title: useId(), service: useId(), displayName: useId(), field: useId() };

  const entry = findEntry(entries, entryKey) ?? initial;
  const options = connectOptions(entry);
  const method: ConnectorAuthKind | undefined =
    chosenMethod && options.methods.includes(chosenMethod) ? chosenMethod : options.methods[0];
  const signIn = useSignIn(entry.auth.provider);
  const closedRef = useRef(false);
  const doneText = `${entry.label} is connected.`;

  // Closing does not stop a sign-in the provider may still complete: hand
  // it to the page, which keeps watching and refreshes the list.
  const close = () => {
    closedRef.current = true;
    if (signIn.flow) onLeftRunning({ flow: signIn.flow, doneText });
    onClose();
  };

  const switchService = (key: string) => {
    const next = findEntry(entries, key) ?? entries[0];
    setEntryKey(next.key);
    setFieldValues({});
    setSelectedScopes(defaultScopes(next)); // least privilege: reads preselected
    setChosenMethod(null);
    setError(null);
    signIn.clearError();
  };

  const scopesOk = !hasScopes(entry) || selectedScopes.length > 0;
  const busy = submitting || signIn.starting;
  const canSubmit =
    method !== undefined &&
    scopesOk &&
    !busy &&
    (method !== "token" ||
      (displayName.trim() !== "" && isFormComplete(entry.auth.fields, fieldValues)));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit || method === undefined) return;
    const granted = orderedSelection(entry, selectedScopes);
    if (method !== "token") {
      setError(null);
      const started = await signIn.start(method, {
        display_name: displayName.trim() || undefined,
        granted_scopes: granted,
        permission_tier: permissionTier,
        rate_limit_per_minute: rateLimit,
      });
      // Closed while the start request was in flight: the consent page has
      // opened anyway, so the page watches the flow instead.
      if (started && closedRef.current) onLeftRunning({ flow: started, doneText });
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const created = await createConnector({
        connector_type: entry.key,
        display_name: displayName.trim(),
        auth_method: entry.auth.token_auth_method,
        credentials: buildCredentials(entry.auth.fields, fieldValues),
        granted_scopes: granted,
        permission_tier: permissionTier,
        rate_limit_per_minute: rateLimit,
      });
      onCreated(created);
    } catch (err) {
      setError(
        err instanceof SyntaxError
          ? "Headers must be valid JSON."
          : errorText(err, "Failed to create connector"),
      );
      setSubmitting(false);
    }
  };

  const submitLabel =
    method === "oauth"
      ? `Continue to ${entry.label}`
      : method === "device"
        ? "Get a sign-in code"
        : "Create connector";
  const SubmitIcon = method === "token" || method === undefined ? Plus : LogIn;
  const shownError = error ?? signIn.error;

  return (
    <ModalShell titleId={ids.title} eyebrow="New integration" title={`Connect ${entry.label}`} icon={entry.icon} onClose={close}>
      {signIn.flow ? (
        <>
          <SignInProgress
            entry={entry}
            flow={signIn.flow}
            onComplete={() => onSignedIn(entry.label)}
            onRestart={signIn.reset}
          />
          <ModalFooter>
            <CancelButton onClick={close} label="Close" />
          </ModalFooter>
        </>
      ) : (
        <form onSubmit={handleSubmit} noValidate>
          <div className="px-4 sm:px-6 py-5 flex flex-col gap-4">
            {shownError && <ErrorAlert>{shownError}</ErrorAlert>}

            <div>
              <label htmlFor={ids.service} className={labelCls}>
                Service
              </label>
              <select
                id={ids.service}
                value={entry.key}
                onChange={(e) => switchService(e.target.value)}
                // Locked while a request is out: a sign-in started for one
                // service must not land on another service's form.
                disabled={busy}
                className={`${fieldCls} disabled:opacity-50`}
                style={inputStyle}
              >
                {entries.map((s) => (
                  <option key={s.key} value={s.key}>
                    {s.label}
                  </option>
                ))}
              </select>
              {entry.description && (
                <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                  {entry.description}
                </p>
              )}
              {entry.docs_url && (
                <p className="mt-1.5">
                  <ExternalAnchor href={entry.docs_url}>
                    {entry.key === SLACK_TYPE ? "Create the Slack app from its manifest" : "Setup guide"}
                  </ExternalAnchor>
                </p>
              )}
            </div>

            {entry.key === SLACK_TYPE && <SlackTokensNote />}
            {options.signInUnavailable && (
              <SignInNotSetUpNote entry={entry} tokenFallback={options.methods.includes("token")} />
            )}
            {entry.auth.notes && method === "token" && (
              <div className="px-3 py-2.5 rounded-[8px] text-xs leading-relaxed" style={infoNoticeStyle}>
                {entry.auth.notes}
              </div>
            )}

            {method !== undefined && (
              <>
                <MethodChooser
                  entry={entry}
                  methods={options.methods}
                  value={method}
                  onChange={setChosenMethod}
                  disabled={busy}
                />

                <div>
                  <label htmlFor={ids.displayName} className={labelCls}>
                    Display name
                    {method !== "token" && <span style={{ color: "var(--text-muted)" }}> (optional)</span>}
                  </label>
                  <input
                    id={ids.displayName}
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className={fieldCls}
                    style={inputStyle}
                    placeholder={method === "token" ? `e.g. My ${entry.label}` : entry.label}
                    required={method === "token"}
                  />
                </div>

                {method === "token" ? (
                  <>
                    <CredentialFields
                      fields={entry.auth.fields}
                      values={fieldValues}
                      onChange={(key, value) => setFieldValues((prev) => ({ ...prev, [key]: value }))}
                      idPrefix={ids.field}
                    />
                    <p className="text-xs -mt-1" style={{ color: "var(--text-muted)" }}>
                      Credentials are encrypted (AES-256-GCM) before they touch the database and are
                      never displayed again after saving.
                    </p>
                  </>
                ) : (
                  <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                    {method === "oauth"
                      ? `${entry.label} opens in your browser to ask for the permissions below. Nothing is saved until you approve.`
                      : `You get a short code to enter on ${entry.label}'s site. Nothing is saved until you approve.`}
                  </p>
                )}

                {hasScopes(entry) && (
                  <ScopePicker
                    entry={entry}
                    scopes={[...entry.scopes.read, ...entry.scopes.write]}
                    selected={selectedScopes}
                    onChange={setSelectedScopes}
                    legend="Permissions to grant"
                    hint={
                      scopesOk
                        ? "Read access is preselected. Anything the agent is not granted here is refused at execution time, and write actions ask for your approval first."
                        : "Choose at least one permission."
                    }
                  />
                )}

                <TierAndRate
                  tier={permissionTier}
                  onTier={setPermissionTier}
                  rate={rateLimit}
                  onRate={setRateLimit}
                />
                <p className="text-xs -mt-2" style={{ color: "var(--text-muted)" }}>
                  Sensitive actions (sending messages, deleting anything, anything financial-adjacent)
                  require explicit approval regardless of the policy chosen here.
                </p>
              </>
            )}
          </div>

          <ModalFooter>
            <CancelButton onClick={close} />
            <button
              type="submit"
              disabled={!canSubmit}
              className="inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
              style={primaryButtonStyle}
            >
              {busy ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : <SubmitIcon className="w-4 h-4" aria-hidden />}
              {busy ? "Working..." : submitLabel}
            </button>
          </ModalFooter>
        </form>
      )}
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Reconnect / grant more access (existing OAuth connector)
// ---------------------------------------------------------------------------

function SignInActionModal({
  entry,
  connector,
  mode,
  onClose,
  onDone,
  onLeftRunning,
}: {
  entry: ConnectorTypeInfo;
  connector: Connector;
  mode: "reconnect" | "grant";
  onClose: () => void;
  onDone: (text: string) => void;
  onLeftRunning: (running: LeftRunning) => void;
}) {
  const methods = signInMethods(entry);
  const [chosen, setChosen] = useState<SignInKind | null>(null);
  const method: SignInKind | undefined = chosen && methods.includes(chosen) ? chosen : methods[0];
  const [extra, setExtra] = useState<string[]>([]);
  const titleId = useId();
  const signIn = useSignIn(entry.auth.provider);
  const closedRef = useRef(false);
  const grantable = grantableScopes(entry, connector.granted_scopes);
  const canSubmit =
    method !== undefined && !signIn.starting && (mode === "reconnect" || extra.length > 0);

  const title = mode === "reconnect" ? `Reconnect ${connector.display_name}` : `Grant more access`;
  const done =
    mode === "reconnect"
      ? `${connector.display_name} is reconnected.`
      : `${connector.display_name} has the new permissions.`;

  // As in ConnectModal: a sign-in left open in the browser can still
  // complete, so the page keeps watching it.
  const close = () => {
    closedRef.current = true;
    if (signIn.flow) onLeftRunning({ flow: signIn.flow, doneText: done });
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit || method === undefined) return;
    const keep = reconnectScopes(entry, connector.granted_scopes);
    const draft: OAuthDraftRequest = { connector_id: connector.id };
    if (mode === "grant") draft.granted_scopes = orderedSelection(entry, extra);
    else if (keep.length > 0) draft.granted_scopes = keep;
    const started = await signIn.start(method, draft);
    if (started && closedRef.current) onLeftRunning({ flow: started, doneText: done });
  };

  return (
    <ModalShell titleId={titleId} eyebrow={entry.label} title={title} icon={entry.icon} onClose={close}>
      {signIn.flow ? (
        <>
          <SignInProgress
            entry={entry}
            flow={signIn.flow}
            onComplete={() => onDone(done)}
            onRestart={signIn.reset}
          />
          <ModalFooter>
            <CancelButton onClick={close} label="Close" />
          </ModalFooter>
        </>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="px-4 sm:px-6 py-5 flex flex-col gap-4">
            {signIn.error && <ErrorAlert>{signIn.error}</ErrorAlert>}
            {mode === "reconnect" ? (
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Sign in to {entry.label} again to renew this connection. Its permissions, approval
                policy and rate limit stay as they are.
              </p>
            ) : grantable.length > 0 ? (
              <ScopePicker
                entry={entry}
                scopes={grantable}
                selected={extra}
                onChange={setExtra}
                legend="Permissions to add"
                hint={`${entry.label} asks you to approve the new permissions. The ones already granted are kept.`}
              />
            ) : (
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                This connector already has every permission {entry.label} offers.
              </p>
            )}
            {method !== undefined && (
              <MethodChooser
                entry={entry}
                methods={methods}
                value={method}
                onChange={(m) => setChosen(m === "token" ? null : m)}
                disabled={signIn.starting}
              />
            )}
          </div>
          <ModalFooter>
            <CancelButton onClick={close} />
            <button
              type="submit"
              disabled={!canSubmit}
              className="inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
              style={primaryButtonStyle}
            >
              {signIn.starting ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : <LogIn className="w-4 h-4" aria-hidden />}
              {method === "device" ? "Get a sign-in code" : `Continue to ${entry.label}`}
            </button>
          </ModalFooter>
        </form>
      )}
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Edit modal: activate/deactivate, scopes, policy, rate limit, and optional
// credential rotation (blank fields keep the stored set).
// ---------------------------------------------------------------------------

function EditConnectorModal({
  connector,
  entry,
  kind,
  onClose,
  onUpdated,
}: {
  connector: Connector;
  entry: ConnectorTypeInfo | undefined;
  kind: RowKind;
  onClose: () => void;
  onUpdated: (c: Connector) => void;
}) {
  // A signed-in row's credentials come from the broker; pasting over them
  // would drop the refresh token, so that row gets Reconnect instead.
  const credentialFields = kind === "oauth" ? [] : (entry?.auth.fields ?? []);
  const hasPresetScopes = hasScopes(entry);

  const [displayName, setDisplayName] = useState(connector.display_name);
  const [isActive, setIsActive] = useState(connector.is_active);
  const [selectedScopes, setSelectedScopes] = useState<string[]>(connector.granted_scopes);
  const [scopesText, setScopesText] = useState(connector.granted_scopes.join(", "));
  const [permissionTier, setPermissionTier] = useState<PermissionTier>(connector.permission_tier);
  const [rateLimit, setRateLimit] = useState(connector.rate_limit_per_minute);
  const [fieldValues, setFieldValues] = useState<FieldValues>({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ids = {
    title: useId(),
    status: useId(),
    displayName: useId(),
    scopes: useId(),
    scopesText: useId(),
    field: useId(),
  };

  // Chips: the catalog's scopes plus anything already granted (covers
  // retired names). A signed-in row can only drop scopes here: adding one
  // needs the provider's consent, which "Grant more access" asks for.
  const scopeOptions = Array.from(
    new Set<string>([
      ...(kind === "oauth" ? [] : [...(entry?.scopes.read ?? []), ...(entry?.scopes.write ?? [])].map((s) => s.scope)),
      ...connector.granted_scopes,
    ]),
  );

  // TIER_OPTIONS omits hard_blocked; keep the current tier selectable if it
  // is outside the normal choices.
  const tierOptions = TIER_OPTIONS.some((o) => o.value === connector.permission_tier)
    ? TIER_OPTIONS
    : [
        {
          value: connector.permission_tier,
          label: tierLabels[connector.permission_tier]?.label ?? connector.permission_tier,
        },
        ...TIER_OPTIONS,
      ];

  // Credentials replace the stored set wholesale on the server, so a partial
  // re-entry would silently drop the untouched fields. Require the same
  // fields as creation once any credential field is filled.
  const anyCredentialEntered = anyFieldEntered(credentialFields, fieldValues);
  const credentialsComplete = !anyCredentialEntered || isFormComplete(credentialFields, fieldValues);
  const canSubmit = displayName.trim() !== "" && credentialsComplete && !submitting;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const scopes = hasPresetScopes
        ? orderedSelection(entry, selectedScopes)
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
        payload.credentials = buildCredentials(credentialFields, fieldValues);
      }
      const updated = await updateConnector(connector.id, payload);
      onUpdated(updated);
    } catch (err) {
      setError(
        err instanceof SyntaxError
          ? "Headers must be valid JSON."
          : errorText(err, "Failed to update connector"),
      );
      setSubmitting(false);
    }
  };

  return (
    <ModalShell
      titleId={ids.title}
      eyebrow={entry?.label ?? connector.connector_type}
      title="Edit connector"
      icon={rowIcon(connector, entry)}
      onClose={onClose}
    >
      <form onSubmit={handleSubmit} noValidate>
        <div className="px-4 sm:px-6 py-5 flex flex-col gap-4">
          {error && <ErrorAlert>{error}</ErrorAlert>}

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
                background: isActive ? "var(--fill-success)" : "var(--fill-neutral)",
                border: isActive ? "1px solid var(--border-success)" : "1px solid var(--claw-border)",
                color: isActive ? "var(--accent-success)" : "var(--text-muted)",
              }}
            >
              <Power className="w-4 h-4" aria-hidden />
              {isActive ? "Active" : "Inactive"}
            </button>
            <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
              Inactive connectors keep their encrypted credentials, but the agent cannot use them
              until reactivated.
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

          {hasPresetScopes && entry ? (
            <fieldset>
              <legend id={ids.scopes} className={labelCls}>
                Permissions to grant
              </legend>
              <div className="flex flex-wrap gap-2">
                {scopeOptions.map((scope) => (
                  <ScopeChip
                    key={scope}
                    view={scopeView(entry, scope)}
                    selected={selectedScopes.includes(scope)}
                    onToggle={() => setSelectedScopes((prev) => toggleScope(prev, scope))}
                  />
                ))}
              </div>
              <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                {kind === "oauth"
                  ? "You can remove permissions here. To add one, use Grant more access on the card, which asks the provider for consent."
                  : "Anything the agent is not granted here is refused at execution time. Changes apply immediately."}
              </p>
            </fieldset>
          ) : (
            <div>
              <label htmlFor={ids.scopesText} className={labelCls}>
                Granted scopes <span style={{ color: "var(--text-muted)" }}>(comma-separated)</span>
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

          <TierAndRate
            tier={permissionTier}
            onTier={setPermissionTier}
            rate={rateLimit}
            onRate={setRateLimit}
            tierOptions={tierOptions}
          />

          {credentialFields.length > 0 && (
            <div>
              <div className="eyebrow mb-2">Replace credentials (optional)</div>
              <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
                Stored credentials are never displayed. Leave every field blank to keep them; filling
                any field replaces the whole stored set, so complete all required fields.
                {kind === "oauth_or_token" && entry
                  ? ` If you connected with Sign in with ${entry.label}, use Reconnect on the card instead: a pasted token replaces that sign-in.`
                  : ""}
              </p>
              <div className="flex flex-col gap-4">
                <CredentialFields
                  fields={credentialFields}
                  values={fieldValues}
                  onChange={(key, value) => setFieldValues((prev) => ({ ...prev, [key]: value }))}
                  idPrefix={ids.field}
                  placeholderOverride="Leave blank to keep existing"
                />
              </div>
              {anyCredentialEntered && !credentialsComplete && (
                <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-warning)" }}>
                  Re-entering credentials replaces the stored set: fill in all required fields with
                  valid values.
                </p>
              )}
            </div>
          )}
        </div>

        <ModalFooter>
          <CancelButton onClick={onClose} />
          <button
            type="submit"
            disabled={!canSubmit}
            className="inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
            style={primaryButtonStyle}
          >
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : <Check className="w-4 h-4" aria-hidden />}
            {submitting ? "Saving..." : "Save changes"}
          </button>
        </ModalFooter>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Slack DM linking
// ---------------------------------------------------------------------------

type SlackLoad = "loading" | "ready" | "unsupported" | "error";

function SlackDmLink({ connector }: { connector: Connector }) {
  const [load, setLoad] = useState<SlackLoad>("loading");
  const [status, setStatus] = useState<SlackLinkStatus | null>(null);
  const [pending, setPending] = useState<SlackLinkCode | null>(null);
  const [busy, setBusy] = useState<"link" | "unlink" | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    getSlackLinkStatus(connector.id)
      .then((s) => {
        if (cancelled) return;
        setStatus(s);
        setLoad("ready");
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        // An older server has no Slack linking at all: say nothing.
        if (err instanceof ApiError && err.status === 404) {
          setLoad("unsupported");
          return;
        }
        setLoad("error");
        setFeedback({ ok: false, text: errorText(err, "Could not check Slack DMs.") });
      });
    return () => {
      cancelled = true;
    };
  }, [connector.id, attempt]);

  const codeExpired = () => {
    setPending(null);
    setFeedback({ ok: false, text: "The code expired before it arrived. Get a new one." });
  };

  // The server decides when the code has expired: once it reports no
  // pending code (null) the wait ends. This device's clock only ends it
  // when the server cannot be reached, with a clock-skew grace.
  usePolling<SlackLinkStatus>(
    pending ? pending.code : null,
    STATUS_POLL_MS,
    () => getSlackLinkStatus(connector.id),
    (result) => {
      setStatus(result);
      if (result.linked) {
        setPending(null);
        setFeedback({ ok: true, text: "Slack DMs are linked. Message the Crawler bot to chat." });
        return true;
      }
      if (result.pending_code_expires_at === null) {
        codeExpired();
        return true;
      }
      return false;
    },
    () => {
      if (pending && isPastDeadline(pending.expires_at)) {
        codeExpired();
        return true;
      }
      return false;
    },
  );

  const link = async () => {
    setBusy("link");
    setFeedback(null);
    try {
      setPending(await createSlackLink(connector.id));
    } catch (err) {
      // 409: the connector has no app-level token; show the Edit hint.
      if (err instanceof ApiError && err.status === 409) {
        setStatus((prev) => (prev ? { ...prev, has_app_token: false } : prev));
      }
      setFeedback({ ok: false, text: errorText(err, "Could not create a link code.") });
    } finally {
      setBusy(null);
    }
  };

  const unlink = async () => {
    setBusy("unlink");
    setFeedback(null);
    try {
      await unlinkSlack(connector.id);
      setStatus((prev) => (prev ? { ...prev, linked: false, slack_user_id: null, team_id: null } : prev));
      setFeedback({ ok: true, text: "Slack DMs are unlinked." });
    } catch (err) {
      setFeedback({ ok: false, text: errorText(err, "Could not unlink Slack DMs.") });
    } finally {
      setBusy(null);
    }
  };

  if (load === "unsupported") return null;

  return (
    <section
      aria-label={`Slack DMs for ${connector.display_name}`}
      className="px-5 py-3 flex flex-col gap-2"
      style={{ borderTop: "1px solid var(--border-subtle)" }}
    >
      <div className="eyebrow">Slack DMs</div>
      {load === "loading" && (
        <p role="status" className="inline-flex items-center gap-2 text-xs" style={{ color: "var(--text-muted)" }}>
          <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
          Checking Slack DMs...
        </p>
      )}
      {load === "error" && (
        <button
          type="button"
          onClick={() => {
            setLoad("loading");
            setFeedback(null);
            setAttempt((n) => n + 1);
          }}
          className="self-start inline-flex items-center gap-1.5 text-xs font-medium"
          style={{ minHeight: 36, color: "var(--accent-primary)" }}
        >
          <RefreshCw className="w-3.5 h-3.5" aria-hidden />
          Check again
        </button>
      )}

      {load === "ready" && status?.linked && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Linked{status.slack_user_id ? ` to Slack user ${status.slack_user_id}` : ""}. Chat with
            Crawler and approve actions from Slack direct messages.
            {!status.channel_running &&
              " The DM channel is not connected right now: check this connector's app-level token."}
          </p>
          <button
            type="button"
            onClick={() => void unlink()}
            disabled={busy !== null}
            className="inline-flex items-center gap-1.5 text-xs font-medium disabled:opacity-50"
            style={{ minHeight: 44, color: "var(--accent-danger)" }}
          >
            {busy === "unlink" ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden /> : <Unlink className="w-3.5 h-3.5" aria-hidden />}
            Unlink
          </button>
        </div>
      )}

      {load === "ready" && !status?.linked && pending && (
        <div className="flex flex-col gap-2">
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            Send this code as a direct message to the Crawler bot in Slack. It expires at{" "}
            {formatTime(pending.expires_at) || "soon"}.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <code
              aria-label="Slack link code"
              className="text-sm font-semibold px-2.5 py-1.5 rounded-[8px] break-all"
              style={{ ...inputStyle, userSelect: "all" }}
            >
              {pending.code}
            </code>
            <CopyButton text={pending.code} label="Copy Slack link code" />
          </div>
          <p role="status" className="inline-flex items-center gap-2 text-xs" style={{ color: "var(--text-muted)" }}>
            <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
            Waiting for your message...
          </p>
        </div>
      )}

      {/* Linking needs the app-level token; a server that predates
          has_app_token leaves it undefined, and the link request says so. */}
      {load === "ready" && !status?.linked && !pending && status?.has_app_token === false && (
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          Add an app-level token (xapp-) in Edit to chat with Crawler and approve actions in Slack
          direct messages.
        </p>
      )}

      {load === "ready" && !status?.linked && !pending && status?.has_app_token !== false && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            Chat with Crawler and approve actions in Slack direct messages. Needs this connector's
            app-level token (xapp-).
            {status && !status.channel_running && " The DM channel is not running for this connector."}
          </p>
          <button
            type="button"
            onClick={() => void link()}
            disabled={busy !== null}
            className="inline-flex items-center gap-1.5 text-xs font-medium disabled:opacity-50"
            style={{ minHeight: 44, color: "var(--accent-primary)" }}
          >
            {busy === "link" ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden /> : <Link2 className="w-3.5 h-3.5" aria-hidden />}
            Link Slack DMs
          </button>
        </div>
      )}

      {feedback && (
        <div className="text-xs">
          <ResultLine ok={feedback.ok}>{feedback.text}</ResultLine>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Connector card (an existing row)
// ---------------------------------------------------------------------------

function CardAction({
  onClick,
  label,
  icon: Icon,
  text,
  color = "var(--text-secondary)",
  disabled,
  spinning,
}: {
  onClick: () => void;
  label: string;
  icon: typeof Zap;
  text: string;
  color?: string;
  disabled?: boolean;
  spinning?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className="inline-flex items-center gap-1.5 text-xs font-medium disabled:opacity-50"
      style={{ minHeight: 44, color }}
    >
      {spinning ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden /> : <Icon className="w-3.5 h-3.5" aria-hidden />}
      {text}
    </button>
  );
}

function ConnectorCard({
  connector,
  entry,
  onDelete,
  onEdit,
  onSignIn,
  onTested,
}: {
  connector: Connector;
  entry: ConnectorTypeInfo | undefined;
  onDelete: () => Promise<void>;
  onEdit: () => void;
  onSignIn: (mode: "reconnect" | "grant") => void;
  /** Called after a test of a signed-in row: the test may have refreshed
   * the sign-in, or found it dead and flagged the row "needs reconnect". */
  onTested?: () => void;
}) {
  const [deleting, setDeleting] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null);
  const kind = rowKind(connector, entry);
  const unavailable = kind === "unavailable";
  const signedIn = kind === "oauth" || kind === "oauth_or_token";
  const canSignIn = signedIn && entry !== undefined && signInMethods(entry).length > 0;
  const canGrantMore = canSignIn && entry !== undefined && grantableScopes(entry, connector.granted_scopes).length > 0;
  const lit = connector.is_active && !unavailable;
  const needsReconnect = !unavailable && connector.is_active && connector.needs_reconnect === true;
  const tier = tierLabels[connector.permission_tier] || {
    label: connector.permission_tier,
    color: "var(--text-muted)",
  };

  const handleTest = async () => {
    if (testing) return;
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await testConnector(connector.id));
    } catch (err) {
      setTestResult({ ok: false, detail: errorText(err, "The test failed.") });
    } finally {
      setTesting(false);
      if (signedIn) onTested?.();
    }
  };

  const badge = unavailable
    ? { text: "unavailable", bg: "var(--fill-danger)", fg: "var(--accent-danger)", border: "var(--border-danger)" }
    : needsReconnect
      ? { text: "needs reconnect", bg: "var(--fill-warning)", fg: "var(--accent-warning)", border: "var(--border-warning)" }
      : connector.is_active
        ? { text: "active", bg: "var(--fill-success)", fg: "var(--accent-success)", border: "var(--border-success)" }
        : { text: "inactive", bg: "var(--fill-neutral)", fg: "var(--text-muted)", border: "var(--claw-border)" };

  return (
    <article
      aria-label={connector.display_name}
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
      {/* Inactive and unavailable connectors are dimmed so the state is
          obvious at a glance; the footer actions keep full contrast. */}
      <div className="p-5" style={{ opacity: lit ? 1 : 0.55 }}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-10 h-10 rounded-[10px] flex items-center justify-center shrink-0"
              style={{
                background: lit ? "var(--accent-glow)" : "var(--fill-neutral)",
                border: lit ? "1px solid var(--border-accent)" : "1px solid var(--claw-border)",
              }}
            >
              <EntryIcon
                icon={rowIcon(connector, entry)}
                className="w-5 h-5"
                style={{ color: lit ? "var(--accent-primary)" : "var(--text-muted)" }}
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
            style={{ background: badge.bg, color: badge.fg, border: `1px solid ${badge.border}` }}
          >
            {badge.text}
          </span>
        </div>

        {unavailable && (
          <p className="text-xs mb-4" style={{ color: "var(--text-secondary)" }}>
            This connector type is no longer available on this server, so the agent cannot use it.
            Remove it, or restore the version that provides it.
          </p>
        )}

        {needsReconnect && (
          <p role="status" className="text-xs mb-4 px-3 py-2 rounded-[8px]" style={warningNoticeStyle}>
            {canSignIn
              ? `${connector.display_name} stopped accepting this sign-in, so the agent cannot use it. Press Reconnect to sign in again.`
              : `${connector.display_name} stopped accepting this sign-in, so the agent cannot use it. Sign-in is not set up on this server; ask the administrator, or paste a new token in Edit if this connector accepts one.`}
          </p>
        )}

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
              No scopes granted, treated as read-only
            </span>
          ) : (
            connector.granted_scopes.map((s) => <ScopeTag key={s} view={scopeView(entry, s)} />)
          )}
        </div>

        {signedIn && !canSignIn && (
          <p className="text-xs mt-3" style={{ color: "var(--text-muted)" }}>
            {kind === "oauth"
              ? "Sign-in is not set up on this server, so this connection cannot be renewed from here."
              : "Sign-in is not set up on this server. Renew this connection by pasting a new token in Edit."}
          </p>
        )}

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
              <ShieldCheck className="w-3.5 h-3.5 mt-px shrink-0" aria-hidden />
            ) : (
              <XCircle className="w-3.5 h-3.5 mt-px shrink-0" aria-hidden />
            )}
            <span>{testResult.detail}</span>
          </div>
        )}
      </div>

      {!unavailable && connector.connector_type === SLACK_TYPE && <SlackDmLink connector={connector} />}

      <div
        className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-5 py-2"
        style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--claw-surface)" }}
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
        <div className="flex flex-wrap items-center gap-x-4">
          {!unavailable && (
            <CardAction
              onClick={() => void handleTest()}
              label={`Test ${connector.display_name}`}
              icon={Zap}
              text="Test"
              color="var(--accent-primary)"
              disabled={testing}
              spinning={testing}
            />
          )}
          {canSignIn && (
            <CardAction
              onClick={() => onSignIn("reconnect")}
              label={`Reconnect ${connector.display_name}`}
              icon={KeyRound}
              text="Reconnect"
              color={needsReconnect ? "var(--accent-warning)" : undefined}
            />
          )}
          {canGrantMore && (
            <CardAction
              onClick={() => onSignIn("grant")}
              label={`Grant more access to ${connector.display_name}`}
              icon={ShieldPlus}
              text="Grant more access"
            />
          )}
          {!unavailable && (
            <CardAction onClick={onEdit} label={`Edit ${connector.display_name}`} icon={Pencil} text="Edit" />
          )}
          <CardAction
            onClick={() => setConfirmOpen(true)}
            label={`Remove ${connector.display_name}`}
            icon={Trash2}
            text="Remove"
            color="var(--accent-danger)"
            disabled={deleting}
            spinning={deleting}
          />
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
            setError(errorText(err, "Could not remove the connector."));
            return;
          }
          setConfirmOpen(false);
        }}
      />
    </article>
  );
}

// ---------------------------------------------------------------------------
// Catalog card (a service to connect)
// ---------------------------------------------------------------------------

function CatalogCard({
  entry,
  connectedCount,
  onConnect,
}: {
  entry: ConnectorTypeInfo;
  connectedCount: number;
  onConnect: () => void;
}) {
  const titleId = useId();
  const options = connectOptions(entry);
  const blocked = options.methods.length === 0;
  return (
    <article
      aria-labelledby={titleId}
      className="rounded-[14px] p-5 flex flex-col gap-3"
      style={panelStyle}
    >
      <div className="flex items-start gap-3">
        <div
          className="w-10 h-10 rounded-[10px] flex items-center justify-center shrink-0"
          style={{ background: "var(--accent-glow)", border: "1px solid var(--border-accent)" }}
        >
          <EntryIcon icon={entry.icon} className="w-5 h-5" style={{ color: "var(--accent-primary)" }} />
        </div>
        <div className="min-w-0">
          <h3 id={titleId} style={{ color: "var(--text-primary)" }}>
            {entry.label}
          </h3>
          {connectedCount > 0 && (
            <p className="mono-tag mt-0.5" style={{ color: "var(--accent-success)" }}>
              {connectedCount} connected
            </p>
          )}
        </div>
      </div>
      {entry.description && (
        <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
          {entry.description}
        </p>
      )}
      {blocked && options.signInUnavailable && (
        <p className="text-xs" style={{ color: "var(--accent-warning)" }}>
          Sign-in is not set up on this server yet.
        </p>
      )}
      <div className="mt-auto flex flex-wrap items-center justify-between gap-2">
        {entry.docs_url ? (
          <ExternalAnchor
            href={entry.docs_url}
            label={`${entry.label} ${entry.key === SLACK_TYPE ? "app manifest" : "setup guide"} (opens in a new tab)`}
          >
            {entry.key === SLACK_TYPE ? "App manifest" : "Setup guide"}
          </ExternalAnchor>
        ) : (
          <span />
        )}
        <button
          type="button"
          onClick={onConnect}
          disabled={blocked}
          aria-label={`Connect ${entry.label}`}
          className="inline-flex items-center gap-1.5 px-3.5 rounded-[10px] text-sm font-semibold disabled:opacity-50"
          style={primaryButtonStyle}
        >
          <Plus className="w-4 h-4" aria-hidden />
          Connect
        </button>
      </div>
    </article>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type SignInTarget = { connector: Connector; entry: ConnectorTypeInfo; mode: "reconnect" | "grant" };

export default function Connectors() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [types, setTypes] = useState<ConnectorTypeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [typesError, setTypesError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [connectKey, setConnectKey] = useState<string | null>(null);
  const [editTarget, setEditTarget] = useState<Connector | null>(null);
  const [signInTarget, setSignInTarget] = useState<SignInTarget | null>(null);
  const [notice, setNotice] = useState<Feedback>(null);
  // Sign-ins whose dialog closed before they finished, keyed by flow id.
  const [leftRunning, setLeftRunning] = useState<LeftRunning[]>([]);

  // The only way to re-run the fetch below after mount, so the loading state
  // flips here, in the click, rather than in an extra render from the effect.
  const refresh = () => {
    setLoading(true);
    setError(null);
    setTypesError(null);
    setRefreshKey((k) => k + 1);
  };

  useEffect(() => {
    let cancelled = false;
    // Settled separately: a catalog failure must not hide the user's rows,
    // and the rows failing must not hide the catalog.
    void Promise.allSettled([getConnectors(), getConnectorTypes()]).then(([rows, catalog]) => {
      if (cancelled) return;
      if (rows.status === "fulfilled") setConnectors(rows.value);
      else setError(errorText(rows.reason, "Could not load your connectors."));
      if (catalog.status === "fulfilled") setTypes(catalog.value);
      else setTypesError(errorText(catalog.reason, "Could not load the list of services."));
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  // A sign-in creates or updates the row on the server; fetch the list
  // quietly instead of flashing the whole page into its loading state.
  const reloadConnectors = () => {
    getConnectors()
      .then(setConnectors)
      .catch((err: unknown) =>
        setNotice({ ok: false, text: errorText(err, "Could not refresh your connectors.") }),
      );
  };

  const watchSignIn = (running: LeftRunning) => {
    setLeftRunning((prev) => [
      ...prev.filter((r) => r.flow.flowId !== running.flow.flowId),
      running,
    ]);
  };

  const stopWatching = (flowId: string) => {
    setLeftRunning((prev) => prev.filter((r) => r.flow.flowId !== flowId));
  };

  const entries = useMemo(() => catalogEntries(types), [types]);
  const entryFor = (type: string) => findEntry(entries, type);

  const counts = useMemo(() => {
    let active = 0;
    let inactive = 0;
    const byType: Record<string, number> = {};
    for (const c of connectors) {
      if (c.is_active) active += 1;
      else inactive += 1;
      byType[c.connector_type] = (byType[c.connector_type] ?? 0) + 1;
    }
    return { active, inactive, byType };
  }, [connectors]);

  const handleDelete = async (id: string) => {
    await deleteConnector(id);
    setConnectors((prev) => prev.filter((c) => c.id !== id));
  };

  const openConnect = (key?: string) => {
    setNotice(null);
    setConnectKey(key ?? entries[0].key);
  };

  const editEntry = editTarget ? entryFor(editTarget.connector_type) : undefined;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="eyebrow mb-2">Integrations</div>
          <h1 style={{ color: "var(--text-primary)" }}>Connectors</h1>
          <p className="text-sm mt-1.5 max-w-2xl" style={{ color: "var(--text-secondary)" }}>
            Manage third-party integrations and their security policies.
            {!loading && !error && (
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
            onClick={() => openConnect()}
            disabled={loading}
            className="flex items-center justify-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
            style={primaryButtonStyle}
          >
            <Plus className="w-4 h-4" aria-hidden /> Add Connector
          </button>
        </div>
      </div>

      {notice && <ResultLine ok={notice.ok}>{notice.text}</ResultLine>}

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

      {!loading && (
        <section aria-labelledby="connectors-yours" className="space-y-3">
          <h2 id="connectors-yours" className="h3" style={{ color: "var(--text-primary)" }}>
            Your connectors
          </h2>

          {error && (
            <div className="rounded-[14px] p-6 flex flex-col items-center gap-3 text-center" style={panelStyle}>
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

          {!error && connectors.length === 0 && (
            <div
              className="rounded-[14px] border-2 border-dashed p-10 flex flex-col items-center justify-center gap-3 text-center"
              style={{ borderColor: "var(--claw-border)", color: "var(--text-muted)" }}
            >
              <EntryIcon icon="plug" className="w-10 h-10" />
              <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                No connectors yet
              </p>
              <p className="text-xs max-w-sm">
                Connect {entries.length > 1 ? "one of the services below" : "an MCP server"} so the
                agent can act on your behalf. Every action stays governed by your granted scopes and
                approval policy.
              </p>
            </div>
          )}

          {!error && connectors.length > 0 && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {connectors.map((c) => {
                const entry = entryFor(c.connector_type);
                return (
                  <ConnectorCard
                    key={c.id}
                    connector={c}
                    entry={entry}
                    onDelete={() => handleDelete(c.id)}
                    onEdit={() => setEditTarget(c)}
                    onSignIn={(mode) => {
                      if (!entry) return;
                      setNotice(null);
                      setSignInTarget({ connector: c, entry, mode });
                    }}
                    onTested={reloadConnectors}
                  />
                );
              })}
            </div>
          )}
        </section>
      )}

      {!loading && (
        <section aria-labelledby="connectors-catalog" className="space-y-3">
          <h2 id="connectors-catalog" className="h3" style={{ color: "var(--text-primary)" }}>
            Add a service
          </h2>
          {typesError && (
            <div className="flex flex-wrap items-center gap-3">
              <ResultLine ok={false}>{typesError}</ResultLine>
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
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {entries.map((entry) => (
              <CatalogCard
                key={entry.key}
                entry={entry}
                connectedCount={counts.byType[entry.key] ?? 0}
                onConnect={() => openConnect(entry.key)}
              />
            ))}
          </div>
        </section>
      )}

      {connectKey !== null && (
        <ConnectModal
          entries={entries}
          initialKey={connectKey}
          onClose={() => setConnectKey(null)}
          onCreated={(c) => {
            setConnectors((prev) => [c, ...prev]);
            setConnectKey(null);
            setNotice({ ok: true, text: `${c.display_name} is connected.` });
          }}
          onSignedIn={(label) => {
            setConnectKey(null);
            setNotice({ ok: true, text: `${label} is connected.` });
            reloadConnectors();
          }}
          onLeftRunning={watchSignIn}
        />
      )}

      {signInTarget && (
        <SignInActionModal
          entry={signInTarget.entry}
          connector={signInTarget.connector}
          mode={signInTarget.mode}
          onClose={() => setSignInTarget(null)}
          onDone={(text) => {
            setSignInTarget(null);
            setNotice({ ok: true, text });
            reloadConnectors();
          }}
          onLeftRunning={watchSignIn}
        />
      )}

      {leftRunning.map((running) => (
        <SignInWatcher
          key={running.flow.flowId}
          flow={running.flow}
          onComplete={() => {
            stopWatching(running.flow.flowId);
            setNotice({ ok: true, text: running.doneText });
            reloadConnectors();
          }}
          // A closed sign-in that fails or expires ends quietly: the user
          // already walked away from it.
          onEnd={() => stopWatching(running.flow.flowId)}
        />
      ))}

      {editTarget && (
        <EditConnectorModal
          connector={editTarget}
          entry={editEntry}
          kind={rowKind(editTarget, editEntry)}
          onClose={() => setEditTarget(null)}
          onUpdated={(updated) => {
            setConnectors((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
            setEditTarget(null);
          }}
        />
      )}
    </div>
  );
}
