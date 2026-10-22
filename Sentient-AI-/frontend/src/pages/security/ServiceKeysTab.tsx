/**
 * ServiceKeysTab: Security ▸ Service keys (owner only). One row per outside security service a key
 * can be saved for (Google Safe Browsing, Google Web Risk, Have I Been Pwned, VirusTotal), each with
 * what it is used for, where to get a key, whether one is saved, and Test / Save / Remove; under the
 * two Google rows, one line on how link checks with Google are going (the switch, the service in
 * use, lookups against the owner's limit and the last problem).
 *
 * Why it exists: nothing is sent to an outside service until the owner adds their own key
 * (decisions 2), and this tab is the one place a key is added, proved and removed. The rows are
 * drawn from GET /api/security/keys as the server lists them, so the breach monitor and file
 * reputation need no key screen of their own. A key travels one way only: it is typed into a
 * password field, sent once in a request body through services/api (same origin; the browser never
 * calls a service itself), and never prefilled, echoed or shown again. The server answers with
 * booleans, and the server's sentences are shown as they come.
 */

import { Fragment, useCallback, useEffect, useId, useState, type CSSProperties, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import ExternalAnchor from "@/components/ExternalAnchor";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
import {
  errorText,
  inputCls,
  inputStyle,
  panelStyle,
  primaryCls,
  primaryStyle,
  secondaryCls,
  secondaryStyle,
} from "@/components/formStyles";
import {
  ApiError,
  getLinkReputationStatus,
  getSecurityKeys,
  removeSecurityKey,
  saveSecurityKey,
  testSecurityKey,
} from "@/services/api";
import type {
  LinkReputationProblem,
  LinkReputationStatus,
  SecurityServiceKey,
  SecurityServiceKeys,
  SecurityServiceName,
} from "@/types";

const INTRO =
  "Crawler sends nothing to these services until you add your own key here. Keys are stored " +
  "encrypted and are never shown again.";
const OWNER_ONLY = "Only the owner of this install can manage service keys.";
const UNREADABLE =
  "Saved service keys can't be read with this server's current ENCRYPTION_KEY. Restore the old " +
  "key, or clear stored secrets in Settings, then add the keys again.";
const ENV_MANAGED = "Provided by server configuration (.env); remove it there to manage it here.";
const STORED_PLACEHOLDER = "A key is saved — paste a new one to replace it";
const LINK_CHECKS_OFF =
  "Link checks with Google are turned off in Settings → Permissions. Links are still checked on " +
  "this computer.";

// The rows a Google lookup can use; the link-check line sits under the last of them.
const GOOGLE_ROWS: ReadonlySet<SecurityServiceName> = new Set(["safe_browsing", "web_risk"]);
const GOOGLE_LABELS: Record<"safe_browsing" | "web_risk", string> = {
  safe_browsing: "Google Safe Browsing",
  web_risk: "Google Web Risk",
};

// Fixed locale, as usageFormat does: the counts are read beside Settings' own limits.
const counts = new Intl.NumberFormat("en-US");

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; data: SecurityServiceKeys }
  | { kind: "forbidden" }
  | { kind: "error"; message: string };

type Busy = "idle" | "testing" | "saving" | "removing";
type Outcome = { ok: boolean; text: string } | null;

/** A short local time ("12:04 PM"), or "" when the value is not a date. */
function clock(iso: string | null | undefined): string {
  if (!iso) return "";
  const at = Date.parse(iso);
  if (!Number.isFinite(at)) return "";
  return new Date(at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

/** A server sentence with the typed key cut out. The key routes never quote a key; this is the
 *  second line, so a key can never reach the page text through a message. */
function withoutKey(text: string, key: string): string {
  return key.length >= 4 ? text.split(key).join("[hidden]") : text;
}

function problemText(problem: LinkReputationProblem | null): string {
  if (!problem) return "none";
  const at = clock(problem.at);
  const when = at ? ` at ${at}` : "";
  const http = problem.http_status != null ? ` (HTTP ${problem.http_status})` : "";
  switch (problem.kind) {
    case "key_rejected":
      return `Google refused the key${http}${when}`;
    case "rate_limited":
      return `lookup limit reached${when}`;
    case "timeout":
      return `Google did not answer in time${when}`;
    default:
      return problem.http_status != null
        ? `Google answered with an error${http}${when}`
        : `Google could not be reached${when}`;
  }
}

/** The link-check line(s) under the Google rows, from the status route. Never calls a link safe:
 *  it only counts lookups and dangerous finds. */
function linkCheckLines(status: LinkReputationStatus): string[] {
  if (status.capability === "blocked") {
    return [status.reason || "Link checks with Google are not available yet."];
  }
  if (status.capability === "off") return [LINK_CHECKS_OFF];
  const found = status.dangerous_found_last_day;
  const parts = ["Link checks: on"];
  if (status.service) parts.push(`using ${GOOGLE_LABELS[status.service]}`);
  parts.push(
    `${counts.format(status.lookups_last_day)} of ${counts.format(status.lookups_per_day)} lookups ` +
      "in the last 24 hours",
  );
  parts.push(`${counts.format(found)} dangerous ${found === 1 ? "link" : "links"} found`);
  parts.push(`last problem: ${problemText(status.last_problem)}`);
  const lines = [parts.join(" · ")];
  if (status.both_keys) lines.push("Both Google keys are saved; Web Risk is used.");
  const until = clock(status.cooling_down_until);
  if (until) {
    lines.push(
      status.last_problem?.kind === "key_rejected"
        ? `Paused until ${until} after Google refused the key.`
        : `Paused until ${until} after Google asked to slow down.`,
    );
  }
  return lines;
}

/** What removing a row's key changes, for the confirmation. */
function removeConsequence(row: SecurityServiceKey, services: SecurityServiceKey[]): string {
  if (row.key_from_env) {
    return "Only the saved copy is removed; the key in the server's .env file is still used.";
  }
  if (GOOGLE_ROWS.has(row.name)) {
    const other = services.find(
      (s) => GOOGLE_ROWS.has(s.name) && s.name !== row.name && (s.key_stored || s.key_from_env),
    );
    return other
      ? `Link checks with Google continue with ${other.label}; links are still checked on this computer.`
      : "Link checks with Google stop until you add a key again; links are still checked on this computer.";
  }
  if (row.name === "hibp") {
    return (
      "Breach monitoring with Have I Been Pwned stops until you add a key again; the password " +
      "check still works without one."
    );
  }
  if (row.name === "virustotal") {
    return "File checks with VirusTotal stop until you add a key again.";
  }
  return `${row.label} is not used until you add a key again.`;
}

function badgeFor(row: SecurityServiceKey): { text: string; style: CSSProperties } {
  if (row.key_from_env) {
    return {
      text: "From server configuration",
      style: {
        background: "var(--fill-neutral)",
        border: "1px solid var(--claw-border)",
        color: "var(--text-secondary)",
      },
    };
  }
  if (row.key_stored) {
    return {
      text: "Saved",
      style: {
        background: "var(--fill-success)",
        border: "1px solid var(--border-success)",
        color: "var(--accent-success)",
      },
    };
  }
  return {
    text: "Not set",
    style: {
      background: "var(--fill-neutral)",
      border: "1px solid var(--claw-border)",
      color: "var(--text-muted)",
    },
  };
}

function KeyRow({
  row,
  removeMessage,
  onChanged,
}: {
  row: SecurityServiceKey;
  removeMessage: string;
  onChanged: (row: SecurityServiceKey) => void;
}) {
  const ids = useId();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState<Busy>("idle");
  const [outcome, setOutcome] = useState<Outcome>(null);
  const [confirming, setConfirming] = useState(false);

  const key = typed.trim();
  const configured = row.key_stored || row.key_from_env;
  // With nothing typed, Test checks the configured key (the server picks the .env one first).
  const canTest = busy === "idle" && (key !== "" || configured);
  const canSave = busy === "idle" && key !== "" && !row.key_from_env;
  const badge = badgeFor(row);

  const test = async () => {
    setBusy("testing");
    setOutcome(null);
    try {
      const result = key ? await testSecurityKey(row.name, key) : await testSecurityKey(row.name);
      setOutcome(
        result.ok
          ? { ok: true, text: withoutKey(result.detail || "The key works.", key) }
          : { ok: false, text: withoutKey(result.error || "The key did not pass its test.", key) },
      );
    } catch (err) {
      const text = errorText(err, "The key could not be tested. Try again.");
      setOutcome({ ok: false, text: withoutKey(text, key) });
    } finally {
      setBusy("idle");
    }
  };

  const save = async () => {
    setBusy("saving");
    setOutcome(null);
    try {
      // The server tests the key first and stores it only when the service accepted it.
      const result = await saveSecurityKey(row.name, key);
      setTyped("");
      onChanged(result.service ?? { ...row, key_stored: true });
      // The tester's own sentence when the server sends one ("Google answered: the key works.").
      const said = result.detail ? withoutKey(result.detail, key) : `${row.label} accepted the key.`;
      setOutcome({ ok: true, text: `Saved. ${said}` });
    } catch (err) {
      // The server's sentence as is (400 the test's reason, 409, 422 the format, 429 the wait).
      const text = errorText(err, "The key could not be saved. Try again.");
      setOutcome({ ok: false, text: withoutKey(text, key) });
    } finally {
      setBusy("idle");
    }
  };

  const remove = async () => {
    setBusy("removing");
    setOutcome(null);
    try {
      await removeSecurityKey(row.name);
      onChanged({ ...row, key_stored: false });
      setOutcome({ ok: true, text: "Removed." });
    } catch (err) {
      // Shown on the row like every other outcome; the dialog closes either way.
      setOutcome({ ok: false, text: errorText(err, "The key could not be removed. Try again.") });
    } finally {
      setBusy("idle");
      setConfirming(false);
    }
  };

  return (
    <section aria-labelledby={`${ids}-title`} className="rounded-[10px] p-4" style={rowStyle}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <h3 id={`${ids}-title`} className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
          {row.label}
        </h3>
        <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full" style={badge.style}>
          {badge.text}
        </span>
      </div>
      <p className="text-xs mt-1.5 break-words" style={{ color: "var(--text-secondary)" }}>
        <span className="font-medium">Used for:</span> {row.used_for}
      </p>
      {row.note && (
        <p className="text-xs mt-1 break-words" style={{ color: "var(--text-muted)" }}>
          {row.note}
        </p>
      )}

      {row.key_from_env ? (
        // The environment always wins, so a key typed here would never be used (the server
        // answers 409); the sentence replaces the field, as Settings does for the bot token.
        <p className="text-sm mt-3" style={{ color: "var(--text-secondary)" }}>
          {ENV_MANAGED}
        </p>
      ) : (
        <div className="mt-3">
          <div className="flex items-center justify-between gap-3 flex-wrap mb-1.5">
            <label className="block text-sm font-medium text-[var(--text-secondary)]" htmlFor={`${ids}-key`}>
              <span className="sr-only">{row.label} </span>API key
            </label>
            <ExternalAnchor href={row.console_url} label={`Get a key for ${row.label}`}>
              Get a key
            </ExternalAnchor>
          </div>
          <input
            id={`${ids}-key`}
            type="password"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            disabled={busy !== "idle"}
            placeholder={row.key_stored ? STORED_PLACEHOLDER : row.key_hint}
            className={inputCls}
            style={inputStyle}
          />
        </div>
      )}

      <div className="flex items-center gap-3 flex-wrap mt-3">
        <button
          type="button"
          onClick={() => void test()}
          disabled={!canTest}
          aria-label={`Test the ${row.label} key`}
          className={secondaryCls}
          style={secondaryStyle}
        >
          {busy === "testing" && <Loader2 className="w-4 h-4 animate-spin" aria-hidden />}
          Test
        </button>
        {!row.key_from_env && (
          <button
            type="button"
            onClick={() => void save()}
            disabled={!canSave}
            aria-label={`Save the ${row.label} key`}
            className={primaryCls}
            style={primaryStyle}
          >
            {busy === "saving" && <Loader2 className="w-4 h-4 animate-spin" aria-hidden />}
            Save
          </button>
        )}
        {row.key_stored && (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            disabled={busy !== "idle"}
            aria-label={`Remove the ${row.label} key`}
            className="inline-flex items-center gap-1.5 px-2 text-sm font-medium underline disabled:opacity-50"
            style={{ minHeight: 44, color: "var(--accent-danger)" }}
          >
            {busy === "removing" && <Loader2 className="w-4 h-4 animate-spin" aria-hidden />}
            Remove
          </button>
        )}
        {outcome && <ResultLine ok={outcome.ok}>{outcome.text}</ResultLine>}
      </div>

      <ConfirmDialog
        open={confirming}
        title={`Remove the ${row.label} key?`}
        message={removeMessage}
        confirmLabel="Remove"
        danger
        onConfirm={remove}
        onCancel={() => setConfirming(false)}
      />
    </section>
  );
}

function LinkCheckStatus({ status }: { status: LinkReputationStatus }) {
  return (
    <section
      aria-label="Link checks with Google"
      className="rounded-[10px] px-4 py-3 space-y-1"
      style={{ background: "var(--bg-input)", border: "1px solid var(--claw-border)" }}
    >
      {linkCheckLines(status).map((line) => (
        <p key={line} className="text-xs break-words" style={{ color: "var(--text-secondary)" }}>
          {line}
        </p>
      ))}
    </section>
  );
}

export default function ServiceKeysTab() {
  const headingId = useId();
  const [load, setLoad] = useState<LoadState>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);
  const [status, setStatus] = useState<LinkReputationStatus | null>(null);
  const [statusRound, setStatusRound] = useState(0);

  useEffect(() => {
    let cancelled = false;
    getSecurityKeys()
      .then((data) => {
        if (!cancelled) setLoad({ kind: "ready", data });
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 403) setLoad({ kind: "forbidden" });
        else setLoad({ kind: "error", message: errorText(err, "The service keys could not be loaded.") });
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  // Loaded with the keys and again after every save or remove (the service in use and the
  // switch's blocked reason follow the keys). A failure only hides the line: keys stay usable.
  useEffect(() => {
    let cancelled = false;
    getLinkReputationStatus()
      .then((next) => {
        if (!cancelled) setStatus(next);
      })
      .catch(() => {
        if (!cancelled) setStatus(null);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt, statusRound]);

  const replaceRow = useCallback((row: SecurityServiceKey) => {
    setLoad((prev) =>
      prev.kind === "ready"
        ? {
            kind: "ready",
            data: {
              ...prev.data,
              services: prev.data.services.map((s) => (s.name === row.name ? row : s)),
            },
          }
        : prev,
    );
    setStatusRound((n) => n + 1);
  }, []);

  const retry = () => {
    setLoad({ kind: "loading" });
    setAttempt((n) => n + 1);
  };

  let body: ReactNode;
  if (load.kind === "loading") {
    body = (
      <p className="text-sm" style={{ color: "var(--text-muted)" }}>
        Loading service keys…
      </p>
    );
  } else if (load.kind === "forbidden") {
    body = (
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        {OWNER_ONLY}
      </p>
    );
  } else if (load.kind === "error") {
    body = (
      <ErrorAlert>
        {load.message}{" "}
        <button type="button" className="underline font-medium" onClick={retry}>
          Retry
        </button>
      </ErrorAlert>
    );
  } else {
    const services = load.data.services;
    const lastGoogle = services.reduce((last, s, i) => (GOOGLE_ROWS.has(s.name) ? i : last), -1);
    body = (
      <>
        {load.data.secrets_unreadable && <ErrorAlert>{UNREADABLE}</ErrorAlert>}
        <div className="space-y-3">
          {services.map((row, i) => (
            <Fragment key={row.name}>
              <KeyRow row={row} removeMessage={removeConsequence(row, services)} onChanged={replaceRow} />
              {i === lastGoogle && status && <LinkCheckStatus status={status} />}
            </Fragment>
          ))}
        </div>
      </>
    );
  }

  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-6" style={panelStyle}>
      <h2 id={headingId} className="mb-1">
        Service keys
      </h2>
      <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
        {INTRO}
      </p>
      {body}
    </section>
  );
}
