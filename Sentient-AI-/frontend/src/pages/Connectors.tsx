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

import {
  Fragment,
  createElement,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import {
  AlertTriangle,
  Check,
  ChevronRight,
  Copy,
  KeyRound,
  Link2,
  Loader2,
  LogIn,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldPlus,
  Trash2,
  Unlink,
  X,
  XCircle,
  Zap,
} from "lucide-react";
import type {
  CanvasSchool,
  Connector,
  ConnectorAuthKind,
  ConnectorScopeInfo,
  ConnectorTestResult,
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
  getMe,
  getOAuthStatus,
  getSlackLinkStatus,
  searchCanvasSchools,
  startDeviceOAuth,
  startOAuth,
  testConnector,
  unlinkSlack,
  updateConnector,
} from "@/services/api";
import ConfirmDialog from "@/components/ConfirmDialog";
import ExternalAnchor from "@/components/ExternalAnchor";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
import { errorText, inputStyle, panelStyle } from "@/components/formStyles";
import { connectorIcon } from "@/components/connectorIcons";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import {
  DEFAULT_RATE_LIMIT,
  MAX_RATE_LIMIT,
  MCP_TYPE,
  MIN_RATE_LIMIT,
  ROBINHOOD_TYPE,
  SLACK_TYPE,
  STATUS_POLL_MS,
  anyFieldEntered,
  buildCredentials,
  catalogEntries,
  clampRateLimit,
  connectOptions,
  defaultScopes,
  externalUrl,
  fieldError,
  findEntry,
  formatTime,
  grantableScopes,
  hasScopes,
  isFormComplete,
  isPastDeadline,
  lowRiskNotes,
  methodLabel,
  orderedSelection,
  pollDelayMs,
  reconnectScopes,
  rowKind,
  scopeView,
  signInMethods,
  toggleScope,
  tokenLink,
  tokenLinkLabel,
  tokenLinkWaitsFor,
  visibleFieldErrors,
  type FieldValues,
  type RowKind,
  type ScopeRisk,
  type ScopeView,
  type SignInKind,
} from "./connectorCatalog";
import {
  CANVAS_TYPE,
  KEYPAIR_FIELD,
  checkFailureText,
  connectGuide,
  connectedText,
  defaultDisplayName,
  plainFields,
  recognizeCode,
  schoolAddress,
  schoolFieldKey,
  serviceName,
  splitPastedCodes,
  stepFields,
  type ConnectGuide,
  type GuideStep,
  type Recognition,
} from "./connectGuides";
import { KEY_PAIR_UNSUPPORTED, generateRobinhoodKeyPair, type RobinhoodKeyPair } from "./robinhoodKeys";

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

const tierLabels: Record<string, { label: string; color: string }> = {
  auto_approve: { label: "Auto Approve", color: "var(--accent-success)" },
  low_risk: { label: "Allow low-risk changes", color: "var(--accent-success)" },
  user_confirm: { label: "User Confirm", color: "var(--accent-warning)" },
  admin_only: { label: "Admin Only", color: "var(--accent-primary)" },
  hard_blocked: { label: "Hard Blocked", color: "var(--accent-danger)" },
};

const TIER_OPTIONS: { value: PermissionTier; label: string }[] = [
  { value: "user_confirm", label: "User Confirm (recommended)" },
  { value: "low_risk", label: "Allow low-risk changes" },
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

const successBoxStyle: CSSProperties = {
  background: "var(--fill-success)",
  color: "var(--accent-success)",
  border: "1px solid var(--border-success)",
};

const dangerBoxStyle: CSSProperties = {
  background: "var(--fill-danger)",
  color: "var(--accent-danger)",
  border: "1px solid var(--border-danger)",
};

const primaryBtnCls =
  "inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50";

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
  after,
  recognize,
}: {
  fields: ConnectorTypeInfo["auth"]["fields"];
  values: FieldValues;
  onChange: (key: string, value: string) => void;
  idPrefix: string;
  placeholderOverride?: string;
  /** Rendered right after the field with this key (the token link under the Canvas URL). */
  after?: { key: string; node: React.ReactNode };
  /** A one-line read of what was pasted into a field (connectGuides.recognizeCode). */
  recognize?: (key: string, value: string) => Recognition | null;
}) {
  const errors = visibleFieldErrors(fields, values);
  return (
    <>
      {fields.map((field) => {
        const id = `${idPrefix}-${field.key}`;
        const problem = errors[field.key];
        const seen = problem ? null : (recognize?.(field.key, values[field.key] ?? "") ?? null);
        const describedBy =
          [problem ? `${id}-error` : "", seen ? `${id}-seen` : "", field.hint ? `${id}-hint` : ""]
            .filter(Boolean)
            .join(" ") || undefined;
        return (
          <Fragment key={field.key}>
            <div>
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
              {seen && (
                <p
                  id={`${id}-seen`}
                  className="flex items-start gap-1.5 text-xs mt-1.5"
                  style={{ color: seen.ok ? "var(--accent-success)" : "var(--accent-warning)" }}
                >
                  {seen.ok ? (
                    <Check className="w-3.5 h-3.5 mt-px shrink-0" aria-hidden />
                  ) : (
                    <AlertTriangle className="w-3.5 h-3.5 mt-px shrink-0" aria-hidden />
                  )}
                  {seen.text}
                </p>
              )}
              {field.hint && (
                <p id={`${id}-hint`} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                  {field.hint}
                </p>
              )}
            </div>
            {after?.key === field.key && after.node}
          </Fragment>
        );
      })}
    </>
  );
}

/**
 * The token form's main call to action: the page where the user creates the token, in a new tab.
 * A template link (Canvas) appears once its field holds a valid address; until then, with
 * `waitingHint`, a muted line says what to fill in. `variant="inline"` is a plain small link, for
 * where pasting a token is not the recommended path.
 */
function TokenLinkCta({
  entry,
  values,
  waitingHint = false,
  variant = "action",
  linkLabel,
}: {
  entry: ConnectorTypeInfo;
  values: FieldValues;
  waitingHint?: boolean;
  variant?: "action" | "inline";
  /** The guide's words for the link ("Open my Canvas settings"), over the catalog's label. */
  linkLabel?: string;
}) {
  const href = tokenLink(entry, values);
  if (!href) {
    const waitsFor = tokenLinkWaitsFor(entry);
    // A template link always waits for a web address field (registry rule).
    if (!waitingHint || !waitsFor) return null;
    return (
      <p className="text-xs -mt-1" style={{ color: "var(--text-muted)" }}>
        Fill in the address above to get a direct link.
      </p>
    );
  }
  const label = linkLabel ?? tokenLinkLabel(entry);
  if (variant === "inline") {
    return (
      <p>
        <ExternalAnchor href={href}>{label}</ExternalAnchor>
      </p>
    );
  }
  // The steps differ per service (Slack installs an app, Robinhood registers a key), so the
  // line stays neutral. The new-tab cue is on the link itself.
  return (
    <div className="flex flex-col items-start gap-1.5">
      <ExternalAnchor href={href} variant="action">
        {label}
      </ExternalAnchor>
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        Follow the steps there, then fill in the rest of this form.
      </p>
    </div>
  );
}

/** The token form's fields with its token link: right under the field a template link is built
 * from (Canvas URL), otherwise above the fields. */
function TokenFields({
  entry,
  fields,
  values,
  onChange,
  idPrefix,
  placeholderOverride,
  waitingHint = false,
  linkVariant = "action",
  linkLabel,
  recognize,
}: {
  entry: ConnectorTypeInfo | undefined;
  fields: ConnectorTypeInfo["auth"]["fields"];
  values: FieldValues;
  onChange: (key: string, value: string) => void;
  idPrefix: string;
  placeholderOverride?: string;
  waitingHint?: boolean;
  linkVariant?: "action" | "inline";
  linkLabel?: string;
  recognize?: (key: string, value: string) => Recognition | null;
}) {
  const waitsFor = entry ? tokenLinkWaitsFor(entry) : null;
  const link = entry ? (
    <TokenLinkCta
      entry={entry}
      values={values}
      waitingHint={waitingHint}
      variant={linkVariant}
      linkLabel={linkLabel}
    />
  ) : null;
  const after =
    waitsFor && fields.some((f) => f.key === waitsFor.key)
      ? { key: waitsFor.key, node: link }
      : undefined;
  return (
    <>
      {!after && link}
      <CredentialFields
        fields={fields}
        values={values}
        onChange={onChange}
        idPrefix={idPrefix}
        placeholderOverride={placeholderOverride}
        after={after}
        recognize={recognize}
      />
    </>
  );
}

/** A folded section: a button that shows or hides `children` (the extras most people skip). */
function Disclosure({
  label,
  children,
  small = false,
}: {
  label: string;
  children: React.ReactNode;
  small?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        className={`inline-flex items-center gap-1.5 font-medium ${small ? "text-xs" : "text-sm"}`}
        style={{ minHeight: small ? 36 : 44, color: small ? "var(--accent-primary)" : "var(--text-secondary)" }}
      >
        <ChevronRight
          className={`w-4 h-4 transition-transform duration-200 ${open ? "rotate-90" : ""}`}
          aria-hidden
        />
        {label}
      </button>
      {open && (
        <div id={panelId} className="flex flex-col gap-4 pt-2">
          {children}
        </div>
      )}
    </div>
  );
}

/** One numbered step of a guided connect flow; a step that is complete shows a check. */
function GuideStepItem({
  n,
  title,
  done,
  children,
}: {
  n: number;
  title: string;
  done: boolean;
  children: React.ReactNode;
}) {
  return (
    <li className="flex gap-3">
      <span
        aria-hidden
        className="w-6 h-6 rounded-full flex items-center justify-center shrink-0 text-xs font-semibold"
        style={
          done
            ? { background: "var(--fill-success)", border: "1px solid var(--border-success)", color: "var(--accent-success)" }
            : { background: "var(--accent-glow)", border: "1px solid var(--border-accent)", color: "var(--accent-primary)" }
        }
      >
        {done ? <Check className="w-3.5 h-3.5" /> : n}
      </span>
      <div className="min-w-0 flex-1 flex flex-col gap-2">
        <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
          {title}
          {done && <span className="sr-only"> (done)</span>}
        </p>
        {children}
      </div>
    </li>
  );
}

const stepTextCls = "text-xs leading-relaxed";
const stepTextStyle: CSSProperties = { color: "var(--text-secondary)" };

/** Wait after the last keystroke before searching, so typing a name sends one search. */
const SCHOOL_SEARCH_DEBOUNCE_MS = 300;
const SCHOOL_SEARCH_MIN = 2;

type SchoolSearch =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "done"; results: CanvasSchool[] }
  | { status: "error"; message: string };

/**
 * Canvas step 1: search for the school by name (through the backend, which asks Instructure's
 * public school list) and pick it, which fills the Canvas address. "My school uses its own
 * address" swaps the search for the address field, for schools the list does not have.
 */
function SchoolPicker({
  entry,
  guide,
  values,
  onChange,
  school,
  onSchool,
  idPrefix,
}: {
  entry: ConnectorTypeInfo;
  guide: ConnectGuide;
  values: FieldValues;
  onChange: (key: string, value: string) => void;
  school: CanvasSchool | null;
  onSchool: (school: CanvasSchool | null) => void;
  idPrefix: string;
}) {
  const fieldKey = schoolFieldKey(entry);
  const address = values[fieldKey] ?? "";
  const picked = school && schoolAddress(school) === address ? school : null;
  // Typed by hand earlier (the form came back after a failed check): keep showing that field.
  const [manual, setManual] = useState(() => address !== "" && picked === null);
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState<SchoolSearch>({ status: "idle" });
  const searchId = useId();
  const statusId = useId();
  const searchRef = useRef<HTMLInputElement>(null);
  const changeRef = useRef<HTMLButtonElement>(null);

  // Each view replaces the control that switched to it (a result, "Change school", the address
  // toggles), so move focus to the new view's control rather than let it fall out of the dialog.
  const mode = picked ? "picked" : manual ? "manual" : "search";
  const shownMode = useRef(mode);
  useEffect(() => {
    if (shownMode.current === mode) return;
    shownMode.current = mode;
    if (mode === "picked") changeRef.current?.focus();
    else if (mode === "search") searchRef.current?.focus();
    else document.getElementById(`${idPrefix}-${fieldKey}`)?.focus();
  }, [mode, idPrefix, fieldKey]);

  useEffect(() => {
    const q = query.trim();
    if (q.length < SCHOOL_SEARCH_MIN) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      setSearch({ status: "loading" });
      searchCanvasSchools(q)
        .then((results) => {
          if (!cancelled) setSearch({ status: "done", results });
        })
        .catch((err: unknown) => {
          if (!cancelled) {
            setSearch({
              status: "error",
              message: errorText(err, "School search is not working right now. Type your school's Canvas address instead."),
            });
          }
        });
    }, SCHOOL_SEARCH_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [query]);

  const type = (next: string) => {
    setQuery(next);
    if (next.trim().length < SCHOOL_SEARCH_MIN) setSearch({ status: "idle" });
  };

  const pick = (choice: CanvasSchool) => {
    const href = schoolAddress(choice);
    if (!href) return;
    onSchool(choice);
    onChange(fieldKey, href);
  };

  const change = () => {
    onSchool(null);
    onChange(fieldKey, "");
    setQuery("");
    setSearch({ status: "idle" });
  };

  if (picked) {
    return (
      <div
        className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-[10px]"
        style={{ background: "var(--accent-glow)", border: "1px solid var(--border-accent)" }}
      >
        <div className="min-w-0">
          <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
            {picked.name}
          </p>
          <p className="text-xs break-all" style={{ color: "var(--text-muted)" }}>
            {picked.domain}
          </p>
        </div>
        <button
          ref={changeRef}
          type="button"
          onClick={change}
          className="text-xs font-medium"
          style={{ minHeight: 36, color: "var(--accent-primary)" }}
        >
          Change school
        </button>
      </div>
    );
  }

  const switchButton = (label: string, onClick: () => void) => (
    <button
      type="button"
      onClick={onClick}
      className="self-start text-xs font-medium underline underline-offset-2"
      style={{ minHeight: 36, color: "var(--accent-primary)" }}
    >
      {label}
    </button>
  );

  if (manual) {
    return (
      <div className="flex flex-col gap-1">
        <CredentialFields
          fields={plainFields(entry, guide, [fieldKey])}
          values={values}
          onChange={onChange}
          idPrefix={idPrefix}
        />
        {switchButton("Search for my school instead", () => {
          setManual(false);
          onChange(fieldKey, "");
        })}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={searchId} className="sr-only">
        School name
      </label>
      <div className="relative">
        <Search
          className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
          style={{ color: "var(--text-muted)" }}
          aria-hidden
        />
        {/* type="text": "search" adds a second clear button in some browsers. */}
        <input
          ref={searchRef}
          id={searchId}
          type="text"
          value={query}
          onChange={(e) => type(e.target.value)}
          aria-describedby={statusId}
          className="w-full pl-9 pr-9 py-2.5 rounded-[10px] text-sm outline-none"
          style={inputStyle}
          placeholder="Type your school's name"
          autoComplete="off"
          spellCheck={false}
        />
        {search.status === "loading" && (
          <Loader2
            className="w-3.5 h-3.5 absolute right-3 top-1/2 -translate-y-1/2 animate-spin"
            style={{ color: "var(--text-muted)" }}
            aria-hidden
          />
        )}
      </div>
      {search.status === "done" && search.results.length > 0 && (
        <ul aria-label="Schools found" className="flex flex-col gap-1.5 max-h-60 overflow-y-auto">
          {search.results.map((result) =>
            schoolAddress(result) ? (
              <li key={result.domain}>
                <button
                  type="button"
                  onClick={() => pick(result)}
                  className="w-full text-left px-3 py-2 rounded-[8px] transition-colors"
                  style={{ minHeight: 44, background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
                >
                  <span className="block text-sm" style={{ color: "var(--text-primary)" }}>
                    {result.name}
                  </span>
                  <span className="block text-xs break-all" style={{ color: "var(--text-muted)" }}>
                    {result.domain}
                  </span>
                </button>
              </li>
            ) : null,
          )}
        </ul>
      )}
      <p
        id={statusId}
        role="status"
        className="text-xs"
        style={{ color: search.status === "error" ? "var(--accent-warning)" : "var(--text-muted)" }}
      >
        {search.status === "loading" && "Searching..."}
        {search.status === "done" &&
          search.results.length > 0 &&
          `${search.results.length} ${search.results.length === 1 ? "school" : "schools"} found. Pick yours.`}
        {search.status === "done" &&
          search.results.length === 0 &&
          "No schools found. Try another spelling, or use your school's own address."}
        {search.status === "error" && search.message}
      </p>
      {switchButton("My school uses its own address", () => {
        setManual(true);
        onSchool(null);
      })}
    </div>
  );
}

/** One password box that takes several codes at once (Slack) and sorts them into their fields
 *  by prefix, with a chip per code saying what was found and what an optional one adds. */
function PasteBox({
  service,
  spec,
  values,
  onChange,
  idPrefix,
}: {
  service: string;
  spec: NonNullable<ConnectGuide["pasteBox"]>;
  values: FieldValues;
  onChange: (key: string, value: string) => void;
  idPrefix: string;
}) {
  // Starts from the fields, so the box is filled again when the form comes back after a check.
  const [text, setText] = useState(() =>
    spec.codes
      .map((code) => values[code.key] ?? "")
      .filter(Boolean)
      .join(" "),
  );
  const id = `${idPrefix}-paste`;
  const split = splitPastedCodes(text, spec.codes);
  const update = (next: string) => {
    setText(next);
    const found = splitPastedCodes(next, spec.codes).values;
    for (const code of spec.codes) onChange(code.key, found[code.key] ?? "");
  };
  const prefixes = spec.codes.map((code) => code.prefix).join(", ");
  return (
    <div>
      <label htmlFor={id} className={labelCls}>
        {spec.label}
      </label>
      <input
        id={id}
        type="password"
        value={text}
        onChange={(e) => update(e.target.value)}
        aria-describedby={`${id}-found`}
        className={fieldCls}
        style={inputStyle}
        placeholder={spec.codes.map((code) => `${code.prefix}...`).join(" ")}
        autoComplete="off"
        spellCheck={false}
      />
      <ul id={`${id}-found`} aria-label="Codes found" className="flex flex-wrap gap-1.5 mt-2">
        {spec.codes.map((code) => {
          const found = Boolean(split.values[code.key]);
          const chip = found
            ? `${code.name} added${code.adds ? `: ${code.adds}` : ""}`
            : code.adds
              ? `${code.name} (optional): ${code.adds}`
              : `${code.name} needed (${code.prefix})`;
          return (
            <li
              key={code.key}
              className="inline-flex items-center gap-1 px-2 py-1 rounded-[6px] text-xs"
              style={
                found
                  ? { background: "var(--fill-success)", border: "1px solid var(--border-success)", color: "var(--accent-success)" }
                  : { background: "var(--fill-neutral)", border: "1px solid var(--claw-border)", color: "var(--text-secondary)" }
              }
            >
              {found && <Check className="w-3 h-3" aria-hidden />}
              {chip}
            </li>
          );
        })}
      </ul>
      {(split.unknown > 0 || split.duplicates > 0) && (
        <p role="status" className="text-xs mt-1.5" style={{ color: "var(--accent-warning)" }}>
          {split.unknown > 0 && `Part of what you pasted is not a ${service} code. Those start with ${prefixes}. `}
          {split.duplicates > 0 && "Two codes of the same kind were pasted; the first one is used."}
        </p>
      )}
    </div>
  );
}

/** The guided flow's numbered steps for a pasted-code service: the page to open for each code,
 *  the fields to paste it into (with what was recognized), and anything to do afterwards. */
function GuidedSteps({
  entry,
  guide,
  values,
  onChange,
  idPrefix,
  school,
  onSchool,
}: {
  entry: ConnectorTypeInfo;
  guide: ConnectGuide;
  values: FieldValues;
  onChange: (key: string, value: string) => void;
  idPrefix: string;
  school: CanvasSchool | null;
  onSchool: (school: CanvasSchool | null) => void;
}) {
  const recognize = (key: string, value: string) => recognizeCode(entry, key, value);

  const content = (step: GuideStep, keys: string[]): { done: boolean; body: React.ReactNode } => {
    const fields = plainFields(entry, guide, keys);
    switch (step.kind) {
      case "school": {
        const field = fields[0];
        const done = field !== undefined && Boolean(values[field.key]?.trim()) && fieldError(field, values[field.key]) === null;
        return {
          done,
          body: (
            <SchoolPicker
              entry={entry}
              guide={guide}
              values={values}
              onChange={onChange}
              school={school}
              onSchool={onSchool}
              idPrefix={idPrefix}
            />
          ),
        };
      }
      case "keypair":
        return {
          done: Boolean(values[KEYPAIR_FIELD]?.trim()),
          body: (
            <>
              <p className={stepTextCls} style={stepTextStyle}>
                {step.body}
              </p>
              <RobinhoodKeyPairHelper
                privateKey={values[KEYPAIR_FIELD]}
                onPrivateKey={(value) => onChange(KEYPAIR_FIELD, value)}
                guided
              />
              {fields.length > 0 && (
                <Disclosure label="I already have a key pair" small>
                  <CredentialFields fields={fields} values={values} onChange={onChange} idPrefix={idPrefix} />
                </Disclosure>
              )}
            </>
          ),
        };
      case "open": {
        const href = tokenLink(entry, values);
        return {
          done: false,
          body: (
            <>
              <p className={stepTextCls} style={stepTextStyle}>
                {step.body}
              </p>
              {href ? (
                <div>
                  <ExternalAnchor href={href} variant="action">
                    {step.button}
                  </ExternalAnchor>
                </div>
              ) : tokenLinkWaitsFor(entry) ? (
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  {entry.key === CANVAS_TYPE
                    ? "Find your school in step 1 first. The button appears here."
                    : "Fill in the address above first. The button appears here."}
                </p>
              ) : null}
            </>
          ),
        };
      }
      case "paste":
        return {
          done: fields.length > 0 && isFormComplete(fields, values),
          body: (
            <>
              {step.body && (
                <p className={stepTextCls} style={stepTextStyle}>
                  {step.body}
                </p>
              )}
              {guide.pasteBox ? (
                <PasteBox
                  service={guide.service}
                  // Only the codes this server's catalog has fields for.
                  spec={{ ...guide.pasteBox, codes: guide.pasteBox.codes.filter((code) => keys.includes(code.key)) }}
                  values={values}
                  onChange={onChange}
                  idPrefix={idPrefix}
                />
              ) : (
                <CredentialFields
                  fields={fields}
                  values={values}
                  onChange={onChange}
                  idPrefix={idPrefix}
                  recognize={recognize}
                />
              )}
            </>
          ),
        };
      case "note":
        return {
          done: false,
          body: (
            <p className={stepTextCls} style={stepTextStyle}>
              {step.body}
            </p>
          ),
        };
    }
  };

  return (
    <ol aria-label={`Steps to connect ${guide.service}`} className="flex flex-col gap-5">
      {guide.steps.map((step, i) => {
        const { done, body } = content(step, stepFields(entry, guide, step));
        return (
          <GuideStepItem key={`${step.kind}-${i}`} n={i + 1} title={step.title} done={done}>
            {body}
          </GuideStepItem>
        );
      })}
    </ol>
  );
}

/** A guide's optional extras (Canvas developer key, Google renewal), folded away. */
function AdvancedFields({
  entry,
  guide,
  values,
  onChange,
  idPrefix,
  placeholderOverride,
}: {
  entry: ConnectorTypeInfo;
  guide: ConnectGuide;
  values: FieldValues;
  onChange: (key: string, value: string) => void;
  idPrefix: string;
  placeholderOverride?: string;
}) {
  const fields = plainFields(entry, guide, guide.advanced);
  if (fields.length === 0) return null;
  return (
    <Disclosure label="Advanced (optional)">
      {guide.advancedNote && (
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          {guide.advancedNote}
        </p>
      )}
      <CredentialFields
        fields={fields}
        values={values}
        onChange={onChange}
        idPrefix={idPrefix}
        placeholderOverride={placeholderOverride}
        recognize={(key, value) => recognizeCode(entry, key, value)}
      />
    </Disclosure>
  );
}

// The stricter of a connection's tier and the account default wins (backend
// tool_registry._TIER_STRICTNESS), so a looser connection tier is capped.
const TIER_STRICTNESS: Record<string, number> = {
  auto_approve: 0,
  low_risk: 1,
  user_confirm: 2,
  admin_only: 3,
  hard_blocked: 4,
};

/** The signed-in account's default tier (Settings), or null until known. */
function useAccountTier(): PermissionTier | null {
  const [tier, setTier] = useState<PermissionTier | null>(null);
  useEffect(() => {
    let cancelled = false;
    Promise.resolve()
      .then(() => getMe())
      .then((me) => {
        if (!cancelled && me?.default_permission_tier) setTier(me.default_permission_tier);
      })
      .catch(() => {
        // Without it the "capped" line is left out; nothing else depends on it.
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return tier;
}

/** Under the tier select: what "Allow low-risk changes" covers for this connector, and when the
 *  account default caps the chosen tier. */
function TierHelp({ tier, lowRisk }: { tier: PermissionTier; lowRisk: string[] }) {
  const accountTier = useAccountTier();
  const capped =
    accountTier !== null &&
    (TIER_STRICTNESS[accountTier] ?? 2) > (TIER_STRICTNESS[tier] ?? 2);
  if (tier !== "low_risk" && !capped) return null;
  return (
    <div className="sm:col-span-2 -mt-2 space-y-1">
      {tier === "low_risk" && (
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          {lowRisk.length > 0
            ? `Low-risk here: ${lowRisk.join("; ")}. Sends, deletes, sharing and anything other people see still ask.`
            : "This connector has no low-risk actions: every change still asks."}
        </p>
      )}
      {capped && accountTier && (
        <p className="text-xs" style={{ color: "var(--accent-warning)" }}>
          Capped by your account setting ({tierLabels[accountTier]?.label ?? accountTier}) in Settings.
        </p>
      )}
    </div>
  );
}

function TierAndRate({
  tier,
  onTier,
  rate,
  onRate,
  tierOptions = TIER_OPTIONS,
  lowRisk = [],
}: {
  tier: PermissionTier;
  onTier: (t: PermissionTier) => void;
  rate: number;
  onRate: (n: number) => void;
  tierOptions?: { value: PermissionTier; label: string }[];
  lowRisk?: string[];
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
          Most actions per minute
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
      <TierHelp tier={tier} lowRisk={lowRisk} />
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

/**
 * What the server owner does to turn sign-in on: register the sign-in app (linked when the
 * definition has client_setup_url), put its client ID (and secret) in backend/.env under the
 * setting names the catalog sends, and restart the backend. Shared by the card and the modal.
 */
function SignInSetupSteps({ entry }: { entry: ConnectorTypeInfo }) {
  const { client_setup_url: setupUrl, client_id_setting: idName, client_secret_setting: secretName } =
    entry.auth;
  const what = secretName ? "client ID and secret" : "client ID";
  return (
    <ol className="list-decimal pl-5 space-y-1 text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
      <li>
        {setupUrl ? (
          <ExternalAnchor href={setupUrl} label={`Register a sign-in app for ${entry.label}`}>
            Register a sign-in app for Crawler
          </ExternalAnchor>
        ) : (
          <>Register a sign-in app for Crawler with {entry.label}</>
        )}
        .
      </li>
      <li>
        Add its {what} to <code>backend/.env</code>
        {idName && (
          <>
            {" "}
            as <code>{idName}</code>
            {secretName && (
              <>
                {" "}
                and <code>{secretName}</code>
              </>
            )}
          </>
        )}
        .
      </li>
      <li>Restart the backend.</li>
    </ol>
  );
}

/** Sign-in needs the server owner to register an app first; say so plainly, with the owner's
 *  steps folded behind "How to set it up". */
function SignInNotSetUpNote({ entry, tokenFallback }: { entry: ConnectorTypeInfo; tokenFallback: boolean }) {
  return (
    <div className="px-3 py-2.5 rounded-[8px] text-xs leading-relaxed" style={warningNoticeStyle}>
      <p>
        Sign-in with {serviceName(entry)} needs a one-time setup by whoever runs this Crawler.{" "}
        {tokenFallback
          ? `Until then, connect with a code from ${serviceName(entry)} below.`
          : "Until then it cannot be connected here."}
      </p>
      <Disclosure label="How to set it up" small>
        <SignInSetupSteps entry={entry} />
      </Disclosure>
    </div>
  );
}

/** Makes the Ed25519 key pair that signs requests to Robinhood: fills the
 * private key field and shows the public key to register at Robinhood. The
 * public key shows only while the field still holds its private key, so an
 * edited field never sits beside a public key it does not match. `guided`
 * drops the framing the guided steps already give. */
function RobinhoodKeyPairHelper({
  privateKey,
  onPrivateKey,
  guided = false,
}: {
  privateKey: string | undefined;
  onPrivateKey: (value: string) => void;
  guided?: boolean;
}) {
  const [pair, setPair] = useState<RobinhoodKeyPair | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const publicKeyId = useId();
  const shown = pair && pair.privateKey === privateKey ? pair : null;

  const generate = async () => {
    setBusy(true);
    setError(null);
    try {
      const next = await generateRobinhoodKeyPair();
      setPair(next);
      onPrivateKey(next.privateKey);
    } catch (err) {
      setError(err instanceof Error ? err.message : KEY_PAIR_UNSUPPORTED);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className={`text-xs leading-relaxed flex flex-col gap-2 ${guided ? "" : "px-3 py-2.5 rounded-[8px]"}`}
      style={guided ? { color: "var(--text-secondary)" } : infoNoticeStyle}
    >
      {!guided && (
        <p>
          No key pair yet? Generate one here. The private key fills its field and is saved only with
          the connector; it never goes to Robinhood.
        </p>
      )}
      <div>
        <button
          type="button"
          onClick={() => void generate()}
          disabled={busy}
          className="inline-flex items-center gap-1.5 px-3 rounded-[8px] text-xs font-medium disabled:opacity-50"
          style={{ ...inputStyle, minHeight: 36 }}
        >
          <KeyRound className="w-3.5 h-3.5" aria-hidden />
          {shown ? "Generate a new key pair" : "Generate a key pair"}
        </button>
      </div>
      {shown && (
        <div>
          <label htmlFor={publicKeyId} className="block mb-1.5 font-medium">
            Public key for Robinhood
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <input
              id={publicKeyId}
              readOnly
              value={shown.publicKey}
              onFocus={(e) => e.currentTarget.select()}
              className={`${fieldCls} font-mono`}
              style={{ ...inputStyle, flex: "1 1 16rem" }}
              spellCheck={false}
            />
            <CopyButton key={shown.publicKey} text={shown.publicKey} label="Copy public key" />
          </div>
          {!guided && (
            <p className="mt-1.5">
              Add it as a new API credential at{" "}
              <ExternalAnchor href="https://robinhood.com/account/crypto">robinhood.com/account/crypto</ExternalAnchor>,
              then paste the API key Robinhood gives you into the API key field.
            </p>
          )}
        </div>
      )}
      {error && (
        <p role="alert" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
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

/** What the check right after saving found. */
type CheckState =
  | { phase: "checking" }
  | { phase: "ok"; text: string }
  | { phase: "failed"; text: string; detail: string };

/** Runs the connector's test once it is saved; a test that cannot run counts as failed. */
async function runCheck(id: string): Promise<ConnectorTestResult> {
  try {
    const result = await testConnector(id);
    if (result && typeof result.ok === "boolean") return result;
    return { ok: false, detail: "The check gave no answer." };
  } catch (err) {
    return { ok: false, detail: errorText(err, "The check could not run.") };
  }
}

/** After saving: the check in progress, then "Connected to X as Y", or what went wrong with the
 *  fix in plain words and the service's own answer underneath. */
function CheckView({ entry, check }: { entry: ConnectorTypeInfo; check: CheckState }) {
  const ref = useRef<HTMLDivElement>(null);
  // The form this replaces held focus; keep it inside the dialog, on the news.
  useEffect(() => {
    ref.current?.focus();
  }, [check.phase]);
  const service = serviceName(entry);
  return (
    <div ref={ref} tabIndex={-1} className="px-4 sm:px-6 py-5 flex flex-col gap-3 outline-none">
      {check.phase === "checking" && (
        <p role="status" className="inline-flex items-center gap-2 text-sm" style={{ color: "var(--text-secondary)" }}>
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          Saved. Checking with {service}...
        </p>
      )}
      {check.phase === "ok" && (
        <div role="status" className="flex items-start gap-2 px-3 py-3 rounded-[10px] text-sm font-medium" style={successBoxStyle}>
          <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" aria-hidden />
          <span>{check.text}</span>
        </div>
      )}
      {check.phase === "failed" && (
        <>
          <div role="alert" className="flex items-start gap-2 px-3 py-3 rounded-[10px] text-sm" style={dangerBoxStyle}>
            <XCircle className="w-4 h-4 mt-0.5 shrink-0" aria-hidden />
            <span>{check.text}</span>
          </div>
          {check.detail && (
            <p className="text-xs break-words" style={{ color: "var(--text-muted)" }}>
              What {service} said: {check.detail}
            </p>
          )}
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            The connection is saved, so you can also fix it later with Edit on its card.
          </p>
        </>
      )}
    </div>
  );
}

function ConnectModal({
  entries,
  initialKey,
  onClose,
  onSaved,
  onNotice,
  onSignedIn,
  onLeftRunning,
}: {
  entries: ConnectorTypeInfo[];
  initialKey: string;
  /** `notice` is what the page says once the dialog is gone, if anything. */
  onClose: (notice?: Feedback) => void;
  /** How a save or check that was still running when the dialog closed turned out. */
  onNotice: (notice: Feedback) => void;
  /** A connector was created or updated here; the dialog stays open for the check. */
  onSaved: (c: Connector) => void;
  onSignedIn: (label: string) => void;
  onLeftRunning: (running: LeftRunning) => void;
}) {
  const initial = findEntry(entries, initialKey) ?? entries[0];
  const [entryKey, setEntryKey] = useState(initial.key);
  const [displayName, setDisplayName] = useState("");
  const [fieldValues, setFieldValues] = useState<FieldValues>({});
  const [school, setSchool] = useState<CanvasSchool | null>(null);
  const [selectedScopes, setSelectedScopes] = useState<string[]>(defaultScopes(initial));
  const [permissionTier, setPermissionTier] = useState<PermissionTier>("user_confirm");
  const [rateLimit, setRateLimit] = useState(DEFAULT_RATE_LIMIT);
  const [chosenMethod, setChosenMethod] = useState<ConnectorAuthKind | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The row this dialog saved: trying again after a failed check updates it rather than adding
  // a second one.
  const [saved, setSaved] = useState<Connector | null>(null);
  const [check, setCheck] = useState<CheckState | null>(null);
  // Back on the form after a failed check, to change what was entered.
  const [fixing, setFixing] = useState(false);
  const fixNoticeRef = useRef<HTMLParagraphElement>(null);
  const ids = { title: useId(), service: useId(), displayName: useId(), field: useId() };

  // "Change what I entered" removes itself; keep focus in the dialog, on what went wrong.
  useEffect(() => {
    if (fixing) fixNoticeRef.current?.focus();
  }, [fixing]);

  const entry = findEntry(entries, entryKey) ?? initial;
  const options = connectOptions(entry);
  const method: ConnectorAuthKind | undefined =
    chosenMethod && options.methods.includes(chosenMethod) ? chosenMethod : options.methods[0];
  const signIn = useSignIn(entry.auth.provider);
  const closedRef = useRef(false);
  const doneText = `${entry.label} is connected.`;
  const guide = method === "token" ? connectGuide(entry) : null;
  const pickedSchool =
    school && schoolAddress(school) === fieldValues[schoolFieldKey(entry)] ? school : null;
  const fallbackName = defaultDisplayName(entry, pickedSchool);
  // A device sign-in that is not set up (GitHub) is not worth a warning: pasting is the way in.
  const showSetupNote = options.signInUnavailable && entry.auth.methods.includes("oauth");

  const setField = (key: string, value: string) => setFieldValues((prev) => ({ ...prev, [key]: value }));

  // Closing does not stop a sign-in the provider may still complete: hand
  // it to the page, which keeps watching and refreshes the list.
  const notPassedYet = (row: Connector) =>
    `${row.display_name} is saved, but the check with ${serviceName(entry)} did not pass. Use Edit on its card to fix it.`;

  const close = () => {
    closedRef.current = true;
    if (signIn.flow) onLeftRunning({ flow: signIn.flow, doneText });
    // A save or check still running reports its own outcome when it lands (handleSubmit).
    if (!saved || submitting) onClose();
    else if (check?.phase === "ok") onClose({ ok: true, text: check.text });
    else if (check?.phase === "failed") onClose({ ok: false, text: notPassedYet(saved) });
    else onClose({ ok: true, text: `${saved.display_name} is saved.` });
  };

  const switchService = (key: string) => {
    const next = findEntry(entries, key) ?? entries[0];
    setEntryKey(next.key);
    setFieldValues({});
    setSchool(null);
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
    (method !== "token" || isFormComplete(entry.auth.fields, fieldValues));

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
    let credentials: Record<string, unknown>;
    try {
      credentials = buildCredentials(entry.auth.fields, fieldValues);
    } catch {
      setError("Headers must be valid JSON.");
      return;
    }
    setSubmitting(true);
    setError(null);
    const settings = {
      display_name: displayName.trim() || fallbackName,
      credentials,
      granted_scopes: granted,
      permission_tier: permissionTier,
      rate_limit_per_minute: rateLimit,
    };
    let row: Connector;
    try {
      row = saved
        ? await updateConnector(saved.id, settings)
        : await createConnector({
            connector_type: entry.key,
            auth_method: entry.auth.token_auth_method,
            ...settings,
          });
    } catch (err) {
      const text = errorText(err, saved ? "Could not save the changes." : "Could not save the connection.");
      if (closedRef.current) {
        onNotice({ ok: false, text });
      } else {
        setError(text);
        setSubmitting(false);
      }
      return;
    }
    setSaved(row);
    onSaved(row);
    setFixing(false);
    setCheck({ phase: "checking" });
    const result = await runCheck(row.id);
    const outcome: CheckState = result.ok
      ? { phase: "ok", text: connectedText(entry, result, pickedSchool?.name) }
      : { phase: "failed", text: checkFailureText(entry, result.detail), detail: result.detail };
    // Closed while saving or checking: the page says how it went instead.
    if (closedRef.current) {
      onNotice(outcome.phase === "ok" ? { ok: true, text: outcome.text } : { ok: false, text: notPassedYet(row) });
      return;
    }
    setSubmitting(false);
    setCheck(outcome);
  };

  const submitLabel =
    method === "oauth"
      ? `Continue to ${entry.label}`
      : method === "device"
        ? "Get a sign-in code"
        : saved
          ? "Save and check again"
          : "Connect";
  const SubmitIcon = method === "token" || method === undefined ? (saved ? RefreshCw : Plus) : LogIn;
  const shownError = error ?? signIn.error;

  return (
    <ModalShell titleId={ids.title} eyebrow="New connection" title={`Connect ${entry.label}`} icon={entry.icon} onClose={close}>
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
        <>
          {/* The form stays mounted (hidden) under the check, so going back to it keeps
              everything as it was: the school picked, the key pair made, the codes pasted. */}
          {check && !fixing && (
            <>
              <CheckView entry={entry} check={check} />
              <ModalFooter>
                {check.phase === "ok" ? (
                  <button type="button" onClick={close} className={primaryBtnCls} style={primaryButtonStyle}>
                    <Check className="w-4 h-4" aria-hidden />
                    Done
                  </button>
                ) : check.phase === "failed" ? (
                  <>
                    <CancelButton onClick={close} label="Close for now" />
                    <button type="button" onClick={() => setFixing(true)} className={primaryBtnCls} style={primaryButtonStyle}>
                      <Pencil className="w-4 h-4" aria-hidden />
                      Change what I entered
                    </button>
                  </>
                ) : (
                  <CancelButton onClick={close} label="Close" />
                )}
              </ModalFooter>
            </>
          )}
          <form onSubmit={handleSubmit} noValidate hidden={check !== null && !fixing}>
            <div className="px-4 sm:px-6 py-5 flex flex-col gap-4">
              {shownError && <ErrorAlert>{shownError}</ErrorAlert>}
              {fixing && check?.phase === "failed" && (
                <p
                  ref={fixNoticeRef}
                  tabIndex={-1}
                  className="px-3 py-2.5 rounded-[8px] text-xs leading-relaxed outline-none"
                  style={warningNoticeStyle}
                >
                  {check.text}
                </p>
              )}

              <div>
                <label htmlFor={ids.service} className={labelCls}>
                  Service
                </label>
                <select
                  id={ids.service}
                  value={entry.key}
                  onChange={(e) => switchService(e.target.value)}
                  // Locked while a request is out, and once a connector is saved here: a
                  // sign-in or a retry must not land on another service's form.
                  disabled={busy || saved !== null}
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
              </div>

              {showSetupNote && (
                <SignInNotSetUpNote entry={entry} tokenFallback={options.methods.includes("token")} />
              )}
              {/* A guide's steps say what the catalog's notes say, in plainer words. */}
              {!guide && entry.auth.notes && method === "token" && (
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
                    // Once a pasted code is saved, a retry fixes that connector: a sign-in
                    // would add a second one beside it.
                    disabled={busy || saved !== null}
                  />

                  {method === "token" ? (
                    <>
                      {guide ? (
                        <>
                          <GuidedSteps
                            entry={entry}
                            guide={guide}
                            values={fieldValues}
                            onChange={setField}
                            idPrefix={ids.field}
                            school={school}
                            onSchool={setSchool}
                          />
                          <AdvancedFields
                            entry={entry}
                            guide={guide}
                            values={fieldValues}
                            onChange={setField}
                            idPrefix={ids.field}
                          />
                        </>
                      ) : (
                        <TokenFields
                          entry={entry}
                          fields={entry.auth.fields}
                          values={fieldValues}
                          onChange={setField}
                          idPrefix={ids.field}
                          waitingHint
                        />
                      )}
                      <p className="text-xs -mt-1" style={{ color: "var(--text-muted)" }}>
                        What you enter is stored encrypted and never shown again.
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
                      legend="What Crawler may do"
                      hint={
                        scopesOk
                          ? "Reading is on to start. Anything you leave off is refused, and changes ask you first."
                          : "Choose at least one."
                      }
                    />
                  )}

                  <Disclosure label="More settings">
                    <div>
                      <label htmlFor={ids.displayName} className={labelCls}>
                        Name in Crawler <span style={{ color: "var(--text-muted)" }}>(optional)</span>
                      </label>
                      <input
                        id={ids.displayName}
                        type="text"
                        value={displayName}
                        onChange={(e) => setDisplayName(e.target.value)}
                        className={fieldCls}
                        style={inputStyle}
                        placeholder={fallbackName}
                      />
                    </div>
                    <TierAndRate
                      tier={permissionTier}
                      onTier={setPermissionTier}
                      rate={rateLimit}
                      onRate={setRateLimit}
                      lowRisk={lowRiskNotes(entry)}
                    />
                    <p className="text-xs -mt-2" style={{ color: "var(--text-muted)" }}>
                      Sending messages, deleting anything and anything to do with money always ask you
                      first, whatever you choose here.
                    </p>
                    {entry.docs_url && (
                      <p>
                        <ExternalAnchor href={entry.docs_url} label={`Technical guide for ${entry.label}`}>
                          Technical guide
                        </ExternalAnchor>
                      </p>
                    )}
                  </Disclosure>
                </>
              )}
            </div>

            <ModalFooter>
              <CancelButton onClick={close} />
              <button type="submit" disabled={!canSubmit} className={primaryBtnCls} style={primaryButtonStyle}>
                {busy ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : <SubmitIcon className="w-4 h-4" aria-hidden />}
                {busy ? "Working..." : submitLabel}
              </button>
            </ModalFooter>
          </form>
        </>
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
  const guide = connectGuide(entry);
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
  const setField = (key: string, value: string) => setFieldValues((prev) => ({ ...prev, [key]: value }));
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
              An inactive connector keeps its saved codes, but Crawler cannot use it until you turn
              it back on.
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
                  : "Anything you leave off here is refused. Changes apply right away."}
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
            lowRisk={lowRiskNotes(entry)}
          />

          {credentialFields.length > 0 && (
            <div>
              <div className="eyebrow mb-2">Replace saved codes (optional)</div>
              <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
                Saved codes are never shown. Leave these blank to keep them. Entering any of them
                replaces all of them, so fill in every one that is needed.
                {kind === "oauth_or_token" && entry
                  ? ` If you connected with Sign in with ${entry.label}, use Reconnect on the card instead: a pasted code replaces that sign-in.`
                  : ""}
              </p>
              <div className="flex flex-col gap-4">
                <TokenFields
                  entry={entry}
                  fields={
                    entry && guide
                      ? plainFields(entry, guide, credentialFields.map((f) => f.key).filter((k) => !guide.advanced.includes(k)))
                      : credentialFields
                  }
                  values={fieldValues}
                  onChange={setField}
                  idPrefix={ids.field}
                  placeholderOverride="Leave blank to keep the saved one"
                  // Reconnect is the advice for a sign-in row, so the token link stays small.
                  linkVariant={kind === "oauth_or_token" ? "inline" : "action"}
                  linkLabel={guide?.steps.find((s) => s.kind === "open")?.button}
                  recognize={entry ? (key, value) => recognizeCode(entry, key, value) : undefined}
                />
                {connector.connector_type === ROBINHOOD_TYPE && (
                  <RobinhoodKeyPairHelper
                    privateKey={fieldValues.api_secret}
                    onPrivateKey={(value) => setField("api_secret", value)}
                  />
                )}
                {entry && guide && (
                  <AdvancedFields
                    entry={entry}
                    guide={guide}
                    values={fieldValues}
                    onChange={setField}
                    idPrefix={ids.field}
                    placeholderOverride="Leave blank to keep the saved one"
                  />
                )}
              </div>
              {anyCredentialEntered && !credentialsComplete && (
                <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-warning)" }}>
                  A new code replaces all the saved ones: fill in every field that is needed, with
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
              " Slack DMs are not connected right now: check this connector's app code (xapp-) in Edit."}
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
          Add Slack&apos;s app code (it starts with xapp-) in Edit to chat with Crawler and approve
          actions in Slack direct messages.
        </p>
      )}

      {load === "ready" && !status?.linked && !pending && status?.has_app_token !== false && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            Chat with Crawler and approve actions in Slack direct messages. Needs Slack&apos;s app
            code (xapp-).
            {status && !status.channel_running && " Slack DMs are not running for this connector."}
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
  const [testResult, setTestResult] = useState<ConnectorTestResult | null>(null);
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
                {entry?.label ?? connector.connector_type}
                {kind === "oauth" ? " · signed in" : kind === "token" && entry ? " · pasted code" : ""}
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
            This kind of connector is no longer available on this server, so Crawler cannot use it.
            Remove it, or restore the version that provides it.
          </p>
        )}

        {needsReconnect && (
          <p role="status" className="text-xs mb-4 px-3 py-2 rounded-[8px]" style={warningNoticeStyle}>
            {canSignIn
              ? `${connector.display_name} stopped accepting this sign-in, so Crawler cannot use it. Press Reconnect to sign in again.`
              : `${connector.display_name} stopped accepting this sign-in, so Crawler cannot use it. Sign-in needs a one-time setup by whoever runs this Crawler; ask them, or enter a new code in Edit if this connector takes one.`}
          </p>
        )}

        <div className="flex flex-wrap gap-x-6 gap-y-3 mb-4">
          <div>
            <div className="eyebrow mb-1">Approval</div>
            <p className="text-sm font-medium" style={{ color: tier.color }}>
              {tier.label}
            </p>
          </div>
          <div>
            <div className="eyebrow mb-1">Limit</div>
            <p className="text-sm font-medium mono-num" style={{ color: "var(--text-primary)" }}>
              {connector.rate_limit_per_minute} actions/min
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
              No permissions chosen, so it can only read
            </span>
          ) : (
            connector.granted_scopes.map((s) => <ScopeTag key={s} view={scopeView(entry, s)} />)
          )}
        </div>

        {signedIn && !canSignIn && (
          <p className="text-xs mt-3" style={{ color: "var(--text-muted)" }}>
            {kind === "oauth"
              ? "Sign-in needs a one-time setup by whoever runs this Crawler, so this connection cannot be renewed from here."
              : "Sign-in needs a one-time setup by whoever runs this Crawler. Renew this connection by entering a new code in Edit."}
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
            <span>
              {testResult.ok && entry && (testResult.account || testResult.user)
                ? connectedText(entry, testResult)
                : testResult.detail}
            </span>
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
  // A guided service walks through its steps, with a button per page, in the connect dialog, so
  // its card stays plain; any other service keeps the link to its setup guide here.
  const guided = connectGuide(entry) !== null;
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
        // Connect is disabled here, so say why, with the owner's steps one click away.
        <div className="text-xs leading-relaxed" style={{ color: "var(--accent-warning)" }}>
          <p>Needs a one-time setup by whoever runs this Crawler.</p>
          <Disclosure label="How to set it up" small>
            <SignInSetupSteps entry={entry} />
          </Disclosure>
        </div>
      )}
      <div className="mt-auto flex flex-wrap items-center justify-between gap-2">
        {!guided && entry.docs_url ? (
          <ExternalAnchor href={entry.docs_url} label={`Setup guide for ${entry.label}`}>
            Setup guide
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
            Connect the apps you use so Crawler can help with them. You choose what it may do, and it
            asks before anything risky.
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
                Connect {entries.length > 1 ? "one of the services below" : "an MCP server"} so
                Crawler can help with it. It only does what you allow, and asks before anything
                risky.
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
          onClose={(closingNotice) => {
            setConnectKey(null);
            if (closingNotice) setNotice(closingNotice);
          }}
          // Saved (or saved again after a failed check): show the row now, the dialog stays
          // open for the check.
          onSaved={(c) => setConnectors((prev) => [c, ...prev.filter((r) => r.id !== c.id)])}
          onNotice={setNotice}
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
