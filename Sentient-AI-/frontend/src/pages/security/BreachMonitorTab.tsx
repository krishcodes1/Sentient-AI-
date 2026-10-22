/**
 * BreachMonitorTab: Security ▸ "Breach monitor". The owner sees whether breach checks run (on,
 * turned off in Settings, or waiting for their own Have I Been Pwned key), the addresses Crawler
 * watches with each one's last check (Check now, Pause or Resume, Remove), a form to add an address
 * they own, and the breaches found, newest unhandled first, each with "Mark as handled". Everyone
 * signed in can check a password against Pwned Passwords at the bottom.
 *
 * Why it exists: a breach lookup sends the owner's address to a third party, so the owner has to
 * be able to see what is watched, what was found and why nothing is being sent (no key, switch off,
 * a failed lookup). A failed lookup is always shown as "not checked" with its reason, never as "no
 * breaches", and nothing here ever calls an address or a password safe. The password check hashes
 * in this browser (pages/security/pwnedPasswords.ts) and sends only a 5-character prefix through
 * the backend; the password is never stored, logged or shown back. Every call goes through
 * services/api.ts to Crawler's own backend (the page's CSP allows nothing else). Standard users
 * never request the overview (it is owner only); they see only the password check.
 */

import { useEffect, useId, useState, type FormEvent } from "react";
import { Loader2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import ExternalAnchor from "@/components/ExternalAnchor";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
import { errorText, inputCls, inputStyle, labelCls, panelStyle } from "@/components/formStyles";
import { checkPassword } from "@/pages/security/pwnedPasswords";
import {
  ApiError,
  acknowledgeAllBreachFindings,
  acknowledgeBreachFinding,
  addBreachAddress,
  checkBreachAddress,
  getBreachMonitor,
  removeBreachAddress,
  setBreachAddressPaused,
} from "@/services/api";
import type { BreachAddress, BreachFinding, BreachOverview } from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const sectionStyle = { borderTop: "1px solid var(--claw-border)" };
const smallButtonCls =
  "inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[10px] text-xs font-semibold disabled:opacity-50";
const neutralButtonStyle = {
  minHeight: 36,
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};
const dangerButtonStyle = {
  minHeight: 36,
  background: "var(--claw-panel)",
  border: "1px solid var(--border-danger)",
  color: "var(--accent-danger)",
};
const primaryButtonStyle = { minHeight: 40, background: "var(--accent-primary)", color: "var(--text-on-accent)" };

const MEMBER_NOTE = "Breach monitoring of email addresses is set up by the owner of this Crawler.";
const NO_KEY_NOTE =
  "Breach checks use your own Have I Been Pwned key, and none is saved yet. Nothing is sent until you add one.";
const OFF_NOTE = "Breach monitoring is turned off in Settings → Permissions. Nothing is sent.";
const UNREADABLE_NOTE =
  "This address can no longer be read (the server's encryption key changed). Remove it and add it again.";
const PAUSED_NOTE = "Paused: Crawler does not check this address until you resume it.";
const NEW_ADVICE = "Change the password you used there, and anywhere you reused it.";
const BASELINE_NOTE = "Known before monitoring started";
const SENSITIVE_TITLE = "A breach marked sensitive";
const PASSWORD_NOTE =
  "Your password never leaves this browser. Crawler works out its SHA-1 fingerprint here and sends " +
  "only the first 5 characters of it; the match is made in this browser.";
const PASSWORD_NOT_FOUND =
  "Not found in Have I Been Pwned's list of leaked passwords. That doesn't make it strong: a long " +
  "password used nowhere else is still best.";
const PASSWORD_UNREACHABLE = "the Pwned Passwords service could not be reached. Try again later.";
// Only if a not_checked answer ever came back without its note: Check now is an HIBP lookup.
const CHECK_UNREACHABLE = "Not checked: Have I Been Pwned could not be reached.";

type RowAction = "check" | "pause";
type RowNote = { ok: boolean; text: string };
type PasswordState =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "found"; count: number }
  | { kind: "not_found" }
  | { kind: "not_checked"; message: string };

/** "1 address", "3 addresses". */
function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** A copy of `record` without `key`. */
function without<T>(record: Record<string, T>, key: string): Record<string, T> {
  const next = { ...record };
  delete next[key];
  return next;
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * A day in the viewer's locale ("Oct 10, 2026" or "10 Oct 2026"). A breach date ("2026-08-30") is a
 * calendar day, so it is read in UTC and never slips to the day before west of Greenwich. A value
 * that is not a date comes back as it was, rather than as "Invalid Date".
 */
function formatDay(value: string): string {
  const dateOnly = DATE_ONLY.test(value);
  const when = new Date(dateOnly ? `${value}T00:00:00Z` : value);
  if (Number.isNaN(when.getTime())) return value;
  return when.toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
    ...(dateOnly ? { timeZone: "UTC" } : {}),
  });
}

/** When Crawler tries again: "in 40 minutes", "in 2 hours", "on Oct 17, 2026", or "shortly". */
function retryWhen(iso: string): string {
  const when = Date.parse(iso);
  if (Number.isNaN(when)) return "later";
  const minutes = Math.round((when - Date.now()) / 60_000);
  if (minutes <= 1) return "shortly";
  if (minutes < 60) return `in ${minutes} minutes`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `in ${plural(hours, "hour", "hours")}`;
  return `on ${formatDay(iso)}`;
}

/** "every week", "every day", "every 3 days". */
function cadence(days: number): string {
  if (days === 7) return "every week";
  if (days === 1) return "every day";
  return `every ${days} days`;
}

/** What a watched address is called on its row and in its buttons' names. */
function addressName(row: BreachAddress): string {
  if (row.readable && row.address) return row.address;
  return row.hint || "An address that can no longer be read";
}

function breachCountText(n: number): string {
  if (n === 0) return "in no known breaches";
  return `in ${plural(n, "known breach", "known breaches")}`;
}

/** What a breach is called: its title, or the fixed words for a sensitive one (never named). */
function breachName(finding: BreachFinding): string {
  return finding.sensitive ? SENSITIVE_TITLE : finding.title || finding.name;
}

/** The finding's headline: its title, site and date; a sensitive breach is never named. */
function breachHeadline(finding: BreachFinding): string {
  if (finding.sensitive) return SENSITIVE_TITLE;
  const parts = [breachName(finding), finding.domain];
  if (finding.breach_date) parts.push(`breached ${formatDay(finding.breach_date)}`);
  return parts.filter(Boolean).join(" · ");
}

/** Have I Been Pwned's own qualifiers on a breach, in words. */
function breachQualifiers(finding: BreachFinding): string {
  const notes: string[] = [];
  if (!finding.verified) notes.push("Have I Been Pwned has not verified this breach.");
  if (finding.fabricated) notes.push("Have I Been Pwned thinks it may be made up.");
  if (finding.spam_list) notes.push("It is a spam list, not a break-in at the site.");
  return notes.join(" ");
}

/** New findings first (each one once), then the rest; a finding seen again is replaced. */
function mergeFindings(existing: BreachFinding[], fresh: BreachFinding[]): BreachFinding[] {
  const freshIds = new Set(fresh.map((finding) => finding.id));
  return [...fresh, ...existing.filter((finding) => !freshIds.has(finding.id))];
}

/** The status line: checks on, waiting for a key, or turned off. */
function StatusLine({ overview, onOpenKeys }: { overview: BreachOverview; onOpenKeys?: () => void }) {
  if (overview.state === "on") {
    const watched = overview.addresses.filter((row) => row.status === "active" && row.readable).length;
    return (
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        {watched === 0
          ? "Breach checks are on, but no address is being checked right now."
          : `Crawler checks ${plural(watched, "address", "addresses")} ${cadence(overview.check_every_days)} with your Have I Been Pwned key.`}
      </p>
    );
  }
  if (overview.state === "off") {
    return (
      <p role="status" className="text-sm" style={{ color: "var(--accent-warning, var(--text-secondary))" }}>
        {OFF_NOTE}
      </p>
    );
  }
  if (overview.key_configured) {
    // Blocked although a key is saved: the server's own reason says why.
    return (
      <p role="status" className="text-sm" style={{ color: "var(--accent-warning, var(--text-secondary))" }}>
        {overview.reason || "Breach checks are not running right now. Nothing is sent."}
      </p>
    );
  }
  return (
    <div className="flex items-center gap-3 flex-wrap">
      <p role="status" className="text-sm" style={{ color: "var(--accent-warning, var(--text-secondary))" }}>
        {NO_KEY_NOTE}
        {!onOpenKeys && " Add one in Security → Service keys."}
      </p>
      {onOpenKeys && (
        <button type="button" onClick={onOpenKeys} className={smallButtonCls} style={neutralButtonStyle}>
          Open Service keys
        </button>
      )}
    </div>
  );
}

/** The detail lines under one watched address. `canCheck` is false while breach checks are off or
 *  have no key: then there is no Check now button and nothing retries, so neither is promised. */
function AddressDetails({ row, canCheck }: { row: BreachAddress; canCheck: boolean }) {
  const muted = { color: "var(--text-muted)" };
  if (!row.readable) {
    return (
      <p className="text-xs mt-0.5" style={{ color: "var(--accent-danger)" }}>
        {UNREADABLE_NOTE}
      </p>
    );
  }
  const lines: { key: string; text: string; danger?: boolean }[] = [];
  if (row.status === "paused") lines.push({ key: "paused", text: PAUSED_NOTE });
  if (row.last_checked_at) {
    const parts = [`Last checked ${formatDay(row.last_checked_at)}`, breachCountText(row.breach_count)];
    if (row.new_count > 0) parts.push(`${row.new_count.toLocaleString()} new`);
    lines.push({ key: "checked", text: parts.join(" · ") });
  }
  if (row.status === "error") {
    const why = row.last_error ? `: ${row.last_error}` : " after repeated failures.";
    const next = canCheck ? " Press Check now to try again." : "";
    lines.push({ key: "error", text: `Checks stopped${why}${next}`, danger: true });
  } else if (row.last_error) {
    // A failure the server will retry on its own; its sentence may already say when.
    const retry =
      canCheck && row.status === "active" && !/tries again/i.test(row.last_error)
        ? ` Crawler tries again ${retryWhen(row.next_check_at)}.`
        : "";
    lines.push({ key: "failed", text: `Last check failed: ${row.last_error}${retry}`, danger: true });
  } else if (!row.last_checked_at && row.status !== "paused") {
    lines.push({ key: "never", text: "Not checked yet" });
  }
  return (
    <>
      {lines.map((line) => (
        <p
          key={line.key}
          className="text-xs mt-0.5 break-words"
          style={line.danger ? { color: "var(--accent-danger)" } : muted}
        >
          {line.text}
        </p>
      ))}
    </>
  );
}

/** Parts A to C: the owner's status line, watched addresses and breaches. */
function OwnerMonitor({ onOpenKeys }: { onOpenKeys?: () => void }) {
  const addressesHeadingId = useId();
  const findingsHeadingId = useId();
  const formId = useId();
  const [overview, setOverview] = useState<BreachOverview | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState<Record<string, RowAction>>({});
  const [notes, setNotes] = useState<Record<string, RowNote>>({});
  const [removing, setRemoving] = useState<BreachAddress | null>(null);
  const [newAddress, setNewAddress] = useState("");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");
  const [acking, setAcking] = useState<Record<string, true>>({});
  const [ackingAll, setAckingAll] = useState(false);
  const [findingsError, setFindingsError] = useState("");

  useEffect(() => {
    let cancelled = false;
    getBreachMonitor()
      .then((data) => {
        if (cancelled) return;
        setOverview(data);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "The breach monitor could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const replaceAddress = (row: BreachAddress) =>
    setOverview((prev) => prev && { ...prev, addresses: prev.addresses.map((a) => (a.id === row.id ? row : a)) });

  const runCheck = async (id: string) => {
    setBusy((prev) => ({ ...prev, [id]: "check" }));
    setNotes((prev) => without(prev, id));
    try {
      const result = await checkBreachAddress(id);
      setOverview(
        (prev) =>
          prev && {
            ...prev,
            addresses: prev.addresses.map((a) => (a.id === id ? result.address : a)),
            findings: mergeFindings(prev.findings, result.new_findings),
          },
      );
      const checked = result.outcome === "checked";
      const fallback = checked ? "Checked." : CHECK_UNREACHABLE;
      setNotes((prev) => ({ ...prev, [id]: { ok: checked, text: result.note || fallback } }));
    } catch (err) {
      // A 409 (paused, no key, switch off) or a 429 (checked moments ago) says why, as sent; the
      // row stays as it was.
      setNotes((prev) => ({ ...prev, [id]: { ok: false, text: errorText(err, "The check could not be run. Try again.") } }));
    } finally {
      setBusy((prev) => without(prev, id));
    }
  };

  const togglePause = async (row: BreachAddress) => {
    const pause = row.status !== "paused";
    setBusy((prev) => ({ ...prev, [row.id]: "pause" }));
    setNotes((prev) => without(prev, row.id));
    try {
      replaceAddress(await setBreachAddressPaused(row.id, pause));
    } catch (err) {
      const fallback = pause ? "The address could not be paused. Try again." : "The address could not be resumed. Try again.";
      setNotes((prev) => ({ ...prev, [row.id]: { ok: false, text: errorText(err, fallback) } }));
    } finally {
      setBusy((prev) => without(prev, row.id));
    }
  };

  const remove = async (target: BreachAddress) => {
    // ConfirmDialog shows a failure inline and stays open.
    await removeBreachAddress(target.id);
    setOverview(
      (prev) =>
        prev && {
          ...prev,
          addresses: prev.addresses.filter((a) => a.id !== target.id),
          findings: prev.findings.filter((f) => f.address_id !== target.id),
        },
    );
    setNotes((prev) => without(prev, target.id));
    setRemoving(null);
  };

  const add = async (event: FormEvent) => {
    event.preventDefault();
    const address = newAddress.trim();
    if (!address || saving) return;
    setFormError("");
    setSaving(true);
    let created: BreachAddress;
    try {
      created = await addBreachAddress(address);
    } catch (err) {
      setFormError(errorText(err, "The address could not be added. Try again."));
      setSaving(false);
      return;
    }
    setSaving(false);
    setOverview(
      (prev) => prev && { ...prev, addresses: [...prev.addresses.filter((a) => a.id !== created.id), created] },
    );
    setNewAddress("");
    // The first answer shows inline at once. Without a key or with the switch off the server would
    // only refuse (the status line already says why), so the row waits for the first sweep.
    if (overview?.state === "on") void runCheck(created.id);
  };

  const acknowledge = async (finding: BreachFinding) => {
    setAcking((prev) => ({ ...prev, [finding.id]: true }));
    setFindingsError("");
    try {
      const updated = await acknowledgeBreachFinding(finding.id);
      const handledNow = finding.acknowledged_at === null && updated.acknowledged_at !== null;
      setOverview(
        (prev) =>
          prev && {
            ...prev,
            findings: prev.findings.map((f) => (f.id === finding.id ? updated : f)),
            addresses: handledNow
              ? prev.addresses.map((a) =>
                  a.id === finding.address_id ? { ...a, new_count: Math.max(0, a.new_count - 1) } : a,
                )
              : prev.addresses,
          },
      );
    } catch (err) {
      setFindingsError(errorText(err, "The breach could not be marked as handled. Try again."));
    } finally {
      setAcking((prev) => without(prev, finding.id));
    }
  };

  const acknowledgeAll = async () => {
    setAckingAll(true);
    setFindingsError("");
    try {
      await acknowledgeAllBreachFindings();
      const now = new Date().toISOString();
      setOverview(
        (prev) =>
          prev && {
            ...prev,
            findings: prev.findings.map((f) => (f.acknowledged_at === null ? { ...f, acknowledged_at: now } : f)),
            addresses: prev.addresses.map((a) => ({ ...a, new_count: 0 })),
          },
      );
    } catch (err) {
      setFindingsError(errorText(err, "The breaches could not be marked as handled. Try again."));
    } finally {
      setAckingAll(false);
    }
  };

  if (loadError) {
    return (
      <ErrorAlert>
        {loadError}{" "}
        <button
          type="button"
          className="underline font-medium"
          onClick={() => {
            setLoadError("");
            setOverview(null);
            setAttempt((n) => n + 1);
          }}
        >
          Try again
        </button>
      </ErrorAlert>
    );
  }
  if (overview === null) {
    return (
      <p role="status" className="inline-flex items-center gap-2 text-sm" style={{ color: "var(--text-muted)" }}>
        <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
        Loading the breach monitor…
      </p>
    );
  }

  const nameOf = new Map(overview.addresses.map((row) => [row.id, addressName(row)]));
  const fresh = overview.findings.filter((f) => f.acknowledged_at === null);
  const handled = overview.findings.filter((f) => f.acknowledged_at !== null);
  const anyChecked = overview.addresses.some((row) => row.last_checked_at !== null);
  const canCheck = overview.state === "on";

  return (
    <>
      <StatusLine overview={overview} onOpenKeys={onOpenKeys} />
      {overview.account_note && (
        <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
          {overview.account_note}
        </p>
      )}

      <section aria-labelledby={addressesHeadingId} className="mt-6 pt-5" style={sectionStyle}>
        <h3 id={addressesHeadingId} className="text-sm font-semibold mb-3" style={{ color: "var(--text-primary)" }}>
          Watched addresses
        </h3>
        {overview.addresses.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            No address is watched yet.
          </p>
        ) : (
          <ul className="space-y-2" aria-label="Watched addresses">
            {overview.addresses.map((row) => {
              const name = addressName(row);
              const action = busy[row.id];
              const note = notes[row.id];
              const paused = row.status === "paused";
              return (
                <li key={row.id} className="rounded-[10px] p-3" style={rowStyle}>
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold break-all" style={{ color: "var(--text-primary)" }}>
                        {name}
                        {row.source === "account" && (
                          <span className="ml-2 text-xs font-normal" style={{ color: "var(--text-muted)" }}>
                            Your sign-in address
                          </span>
                        )}
                      </p>
                      <AddressDetails row={row} canCheck={canCheck} />
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      {row.readable && canCheck && !paused && (
                        <button
                          type="button"
                          disabled={action !== undefined}
                          onClick={() => void runCheck(row.id)}
                          aria-label={`Check now: ${name}`}
                          className={smallButtonCls}
                          style={neutralButtonStyle}
                        >
                          {action === "check" && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
                          Check now
                        </button>
                      )}
                      {row.readable && (
                        <button
                          type="button"
                          disabled={action !== undefined}
                          onClick={() => void togglePause(row)}
                          aria-label={paused ? `Resume checks of ${name}` : `Pause checks of ${name}`}
                          className={smallButtonCls}
                          style={neutralButtonStyle}
                        >
                          {action === "pause" && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
                          {paused ? "Resume" : "Pause"}
                        </button>
                      )}
                      {row.source === "added" && (
                        <button
                          type="button"
                          disabled={action !== undefined}
                          onClick={() => setRemoving(row)}
                          aria-label={`Remove ${name}`}
                          className={smallButtonCls}
                          style={dangerButtonStyle}
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  </div>
                  {note && (
                    <div className="mt-2">
                      <ResultLine ok={note.ok}>{note.text}</ResultLine>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}

        <form onSubmit={(e) => void add(e)} className="mt-4" aria-label="Add an address to watch">
          <label className={labelCls} htmlFor={`${formId}-address`}>
            Add an address you own
          </label>
          <div className="flex items-start gap-2 flex-wrap">
            <input
              id={`${formId}-address`}
              type="email"
              className={`${inputCls} flex-1 min-w-[12rem]`}
              style={inputStyle}
              value={newAddress}
              placeholder="name@example.com"
              autoComplete="off"
              spellCheck={false}
              aria-describedby={`${formId}-hint`}
              onChange={(e) => setNewAddress(e.target.value)}
            />
            <button
              type="submit"
              disabled={saving || newAddress.trim() === ""}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
              style={primaryButtonStyle}
            >
              {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
              Watch this address
            </button>
          </div>
          <p id={`${formId}-hint`} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
            Add only addresses you own. Crawler sends each one to Have I Been Pwned{" "}
            {overview.check_every_days === 7 ? "once a week" : cadence(overview.check_every_days)}. Up to{" "}
            {overview.max_addresses}.
          </p>
          {formError && (
            <p role="alert" className="text-sm mt-2" style={{ color: "var(--accent-danger)" }}>
              {formError}
            </p>
          )}
        </form>
      </section>

      <section aria-labelledby={findingsHeadingId} className="mt-6 pt-5" style={sectionStyle}>
        <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
          <h3 id={findingsHeadingId} className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
            Breaches
          </h3>
          {fresh.length > 0 && (
            <button
              type="button"
              disabled={ackingAll}
              onClick={() => void acknowledgeAll()}
              className={smallButtonCls}
              style={neutralButtonStyle}
            >
              {ackingAll && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
              Mark all as handled
            </button>
          )}
        </div>
        {findingsError && (
          <p role="alert" className="text-sm mb-2" style={{ color: "var(--accent-danger)" }}>
            {findingsError}
          </p>
        )}
        {overview.findings.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            {anyChecked ? "No breaches are recorded for the addresses checked so far." : "No address has been checked yet."}
          </p>
        ) : (
          <>
            <ul className="space-y-2" aria-label="Breaches found">
              {[...fresh, ...handled].map((finding) => {
                const isNew = finding.acknowledged_at === null;
                const headline = breachHeadline(finding);
                const owner = nameOf.get(finding.address_id);
                const exposed = finding.data_classes.map((c) => c.toLowerCase()).join(", ");
                const detail = [owner, exposed && `exposed: ${exposed}`].filter(Boolean).join(" · ");
                const qualifiers = breachQualifiers(finding);
                return (
                  <li key={finding.id} className="rounded-[10px] p-3" style={rowStyle}>
                    <div className="flex items-start justify-between gap-3 flex-wrap">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
                          {isNew && (
                            <span
                              className="mr-2 px-1.5 py-0.5 rounded-[6px] text-[10px] font-bold tracking-wide align-middle"
                              style={{
                                background: "var(--fill-danger)",
                                color: "var(--accent-danger)",
                                border: "1px solid var(--border-danger)",
                              }}
                            >
                              NEW
                            </span>
                          )}
                          {headline}
                        </p>
                        {detail && (
                          <p className="text-xs mt-0.5 break-words" style={{ color: "var(--text-muted)" }}>
                            {detail}
                          </p>
                        )}
                        {qualifiers && (
                          <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                            {qualifiers}
                          </p>
                        )}
                        {isNew && (
                          <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
                            {NEW_ADVICE}
                          </p>
                        )}
                        {finding.baseline && (
                          <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                            {BASELINE_NOTE}
                          </p>
                        )}
                      </div>
                      {isNew ? (
                        <button
                          type="button"
                          disabled={ackingAll || acking[finding.id] === true}
                          onClick={() => void acknowledge(finding)}
                          aria-label={`Mark as handled: ${breachName(finding)}${owner ? ` (${owner})` : ""}`}
                          className={smallButtonCls}
                          style={neutralButtonStyle}
                        >
                          {acking[finding.id] && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
                          Mark as handled
                        </button>
                      ) : (
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                          Handled
                        </span>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
            <p className="mt-3">
              <ExternalAnchor href={overview.attribution.url}>
                {overview.attribution.text || "Breach data: Have I Been Pwned"}
              </ExternalAnchor>
            </p>
          </>
        )}
      </section>

      <ConfirmDialog
        open={removing !== null}
        title={removing ? `Stop watching ${addressName(removing)}?` : ""}
        message="Crawler stops checking this address and forgets the breaches found for it."
        confirmLabel="Remove"
        danger
        onConfirm={() => (removing ? remove(removing) : undefined)}
        onCancel={() => setRemoving(null)}
      />
    </>
  );
}

/** What a failed password check says after "Not checked:". */
function notCheckedText(err: unknown): string {
  // The switch being off (403) or the per-user limit (429) has the server's own sentence; anything
  // else (the service down, an unreadable answer) is the plain "could not be reached".
  if (err instanceof ApiError && (err.status === 403 || err.status === 429) && err.message) {
    return err.message.replace(/^Not checked:\s*/i, "");
  }
  return PASSWORD_UNREACHABLE;
}

/** Part D: the in-browser Pwned Passwords check, for everyone signed in. */
function PasswordCheck() {
  const headingId = useId();
  const fieldId = useId();
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<PasswordState>({ kind: "idle" });
  const checking = result.kind === "checking";

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!password || checking) return;
    // Exactly as typed (no trim); the field is emptied before anything is sent, whatever the outcome.
    const typed = password;
    setPassword("");
    setResult({ kind: "checking" });
    try {
      const outcome = await checkPassword(typed);
      setResult(outcome.found ? { kind: "found", count: outcome.count } : { kind: "not_found" });
    } catch (err) {
      setResult({ kind: "not_checked", message: notCheckedText(err) });
    }
  };

  return (
    <section aria-labelledby={headingId} className="mt-6 pt-5" style={sectionStyle}>
      <h3 id={headingId} className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
        Check a password
      </h3>
      <p id={`${fieldId}-note`} className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
        {PASSWORD_NOTE}
      </p>
      <form onSubmit={(e) => void submit(e)} aria-label="Check a password">
        <label className={labelCls} htmlFor={fieldId}>
          Password to check
        </label>
        <div className="flex items-start gap-2 flex-wrap">
          <input
            id={fieldId}
            type="password"
            className={`${inputCls} flex-1 min-w-[12rem]`}
            style={inputStyle}
            value={password}
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            aria-describedby={`${fieldId}-note`}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button
            type="submit"
            disabled={checking || password === ""}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
            style={primaryButtonStyle}
          >
            {checking && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
            Check
          </button>
        </div>
      </form>
      {result.kind === "found" && (
        <p role="alert" className="text-sm mt-3" style={{ color: "var(--accent-danger)" }}>
          This password has appeared in {plural(result.count, "data breach", "data breaches")}. Don't use it;
          change it wherever you use it.
        </p>
      )}
      {result.kind === "not_found" && (
        <p role="status" className="text-sm mt-3" style={{ color: "var(--text-secondary)" }}>
          {PASSWORD_NOT_FOUND}
        </p>
      )}
      {result.kind === "not_checked" && (
        <p role="alert" className="text-sm mt-3" style={{ color: "var(--accent-danger)" }}>
          <span className="font-semibold">Not checked:</span> {result.message}
        </p>
      )}
    </section>
  );
}

export default function BreachMonitorTab({ isOwner, onOpenKeys }: { isOwner: boolean; onOpenKeys?: () => void }) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-6" style={panelStyle}>
      <h2 id={headingId} className="mb-1">
        Breach monitor
      </h2>
      {isOwner ? (
        <OwnerMonitor onOpenKeys={onOpenKeys} />
      ) : (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          {MEMBER_NOTE}
        </p>
      )}
      <PasswordCheck />
    </section>
  );
}
