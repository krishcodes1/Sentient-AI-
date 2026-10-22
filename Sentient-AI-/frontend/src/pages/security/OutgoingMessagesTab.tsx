/**
 * OutgoingMessagesTab: Security ▸ "Outgoing messages" (every user) — whether Crawler checks what
 * it sends, how many addresses and domains it remembers sending mail to for you (counts only), with
 * a way to forget that history, and the organisation's domains: the sign-in domain plus the owner's
 * list, which only the owner can add to or remove from.
 *
 * Why it exists: before an email, post or comment leaves an account, Crawler notes on the approval
 * card who it goes to (first time, outside your organisation, a look-alike address) and what it
 * carries. "First time" rests on a sent-to history the person should be able to see and wipe, and
 * "outside your organisation" rests on a domain list the owner has to be able to keep right. The
 * history is one-way fingerprints, so this tab can only ever show counts, never an address. The
 * server checks every domain (a real domain, not a public mail service, at most the limit) and its
 * reason is shown beside the form as is.
 */

import { useEffect, useId, useState, type FormEvent } from "react";
import { Loader2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, inputCls, inputStyle, panelStyle } from "@/components/formStyles";
import {
  ApiError,
  addOrganisationDomain,
  forgetKnownRecipients,
  getOutboundSettings,
  removeOrganisationDomain,
} from "@/services/api";
import type { OrganisationDomain, OutboundSettings } from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const dangerButtonStyle = {
  minHeight: 36,
  background: "var(--claw-panel)",
  border: "1px solid var(--border-danger)",
  color: "var(--accent-danger)",
};

const ON_NOTE =
  "Checks are on. Before Crawler sends an email, posts or comments, it checks who it goes to and " +
  "what it carries, and puts what it finds on the approval card.";
const OFF_NOTE =
  "Checks are off (Settings → Permissions). Hidden characters are still removed from everything " +
  "Crawler sends.";
const FINGERPRINT_NOTE =
  "It keeps one-way fingerprints, never the addresses, so it can tell you when a message goes to " +
  "someone new.";

/** "1 address", "37 addresses". */
function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * A day in the viewer's locale ("14 Oct 2026" or "Oct 14, 2026"). A value that is not a date comes
 * back as it was, rather than as "Invalid Date".
 */
function formatDay(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

/** What the history block says Crawler remembers, from the counts alone. */
function knownSentence(known: OutboundSettings["known"]): string {
  if (known.addresses === 0) return "Crawler has not sent mail for you yet.";
  const since = known.since ? ` since ${formatDay(known.since)}` : "";
  return (
    `Crawler has sent mail to ${count(known.addresses, "address", "addresses")} at ` +
    `${count(known.domains, "domain", "domains")} for you${since}.`
  );
}

export default function OutgoingMessagesTab({ isOwner }: { isOwner: boolean }) {
  const headingId = useId();
  const historyHeadingId = useId();
  const orgHeadingId = useId();
  const domainInputId = useId();

  const [settings, setSettings] = useState<OutboundSettings | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);

  const [confirmingForget, setConfirmingForget] = useState(false);
  const [forgotText, setForgotText] = useState("");
  const [forgetError, setForgetError] = useState("");

  const [newDomain, setNewDomain] = useState("");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");
  const [removing, setRemoving] = useState<OrganisationDomain | null>(null);

  useEffect(() => {
    let cancelled = false;
    getOutboundSettings()
      .then((data) => {
        if (cancelled) return;
        setSettings(data);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) {
          setLoadError(errorText(err, "The outgoing message settings could not be loaded."));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const forget = async () => {
    setForgotText("");
    setForgetError("");
    try {
      const { removed } = await forgetKnownRecipients();
      setSettings(
        (prev) => prev && { ...prev, known: { addresses: 0, domains: 0, since: null } },
      );
      setForgotText(`Forgot ${count(removed, "entry", "entries")}.`);
    } catch (err) {
      // Shown next to the Forget button (the counts stay as they were), not inside the dialog:
      // the history is unchanged, so there is nothing left to confirm.
      setForgetError(errorText(err, "The sent-to history could not be forgotten. Try again."));
    } finally {
      setConfirmingForget(false);
    }
  };

  const addDomain = async (event: FormEvent) => {
    event.preventDefault();
    const domain = newDomain.trim().toLowerCase();
    if (!domain) return;
    setFormError("");
    setSaving(true);
    try {
      const created = await addOrganisationDomain(domain);
      setSettings(
        (prev) => prev && { ...prev, organisation_domains: [...prev.organisation_domains, created] },
      );
      setNewDomain("");
    } catch (err) {
      // A 409 (already listed) or 422 (not a domain, a public mail service, the limit) arrives as
      // the server's own sentence; it is shown as is and what was typed stays in the box.
      setFormError(errorText(err, "The domain could not be added. Try again."));
    } finally {
      setSaving(false);
    }
  };

  const removeDomain = async (target: OrganisationDomain) => {
    // ConfirmDialog shows a failure inline and stays open; the row stays too. A 404 means the
    // domain is already gone (removed in another tab), so the row goes as if this remove worked.
    try {
      await removeOrganisationDomain(target.id);
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 404)) throw err;
    }
    setSettings(
      (prev) =>
        prev && {
          ...prev,
          organisation_domains: prev.organisation_domains.filter((row) => row.id !== target.id),
        },
    );
    setRemoving(null);
  };

  const retry = () => {
    setLoadError("");
    setSettings(null);
    setAttempt((n) => n + 1);
  };

  // The owner edits the list only when the server agrees (`can_edit_domains`); the server checks
  // again on every change, so this only decides what is shown.
  const canEdit = isOwner && settings?.can_edit_domains === true;
  const atLimit = settings !== null && settings.organisation_domains.length >= settings.domain_limit;
  const listEmpty =
    settings !== null && settings.own_domains.length === 0 && settings.organisation_domains.length === 0;

  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-6" style={panelStyle}>
      <h2 id={headingId} className="mb-1">
        Outgoing messages
      </h2>

      {loadError ? (
        <ErrorAlert>
          {loadError}{" "}
          <button type="button" className="underline font-medium" onClick={retry}>
            Retry
          </button>
        </ErrorAlert>
      ) : settings === null ? (
        <p role="status" className="inline-flex items-center gap-2 text-sm" style={{ color: "var(--text-muted)" }}>
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          Loading outgoing message checks…
        </p>
      ) : (
        <>
          {settings.enabled ? (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              {ON_NOTE}
            </p>
          ) : (
            <p role="status" className="text-sm" style={{ color: "var(--accent-warning, var(--text-secondary))" }}>
              {OFF_NOTE}
            </p>
          )}

          <section
            aria-labelledby={historyHeadingId}
            className="mt-6 pt-5"
            style={{ borderTop: "1px solid var(--claw-border)" }}
          >
            <h3 id={historyHeadingId} className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
              Who you have sent to
            </h3>
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              {knownSentence(settings.known)}
            </p>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              {FINGERPRINT_NOTE}
            </p>
            {settings.known.addresses > 0 && (
              <div className="mt-3 flex items-center gap-3 flex-wrap">
                <button
                  type="button"
                  onClick={() => {
                    setForgetError("");
                    setConfirmingForget(true);
                  }}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[10px] text-xs font-semibold"
                  style={dangerButtonStyle}
                >
                  Forget this history
                </button>
                {forgetError && (
                  <p role="alert" className="text-xs" style={{ color: "var(--accent-danger)" }}>
                    {forgetError}
                  </p>
                )}
              </div>
            )}
            {forgotText && (
              <p role="status" className="text-sm mt-2" style={{ color: "var(--accent-success)" }}>
                {forgotText}
              </p>
            )}
          </section>

          <section
            aria-labelledby={orgHeadingId}
            className="mt-6 pt-5"
            style={{ borderTop: "1px solid var(--claw-border)" }}
          >
            <h3 id={orgHeadingId} className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
              Your organisation
            </h3>
            <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
              Mail to these domains is not marked “outside your organisation”. Public mail services
              such as gmail.com never count.
            </p>

            {listEmpty ? (
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                No domains are listed, so no message is marked as going outside your organisation.
              </p>
            ) : (
              <ul className="space-y-2" aria-label="Organisation domains">
                {settings.own_domains.map((domain) => (
                  <li key={`own:${domain}`} className="rounded-[10px] p-3" style={rowStyle}>
                    <p className="text-sm font-semibold break-all" style={{ color: "var(--text-primary)" }}>
                      {domain}
                    </p>
                    <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                      from your sign-in email
                    </p>
                  </li>
                ))}
                {settings.organisation_domains.map((row) => (
                  <li key={row.id} className="rounded-[10px] p-3" style={rowStyle}>
                    <div className="flex items-center justify-between gap-3 flex-wrap">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold break-all" style={{ color: "var(--text-primary)" }}>
                          {row.domain}
                        </p>
                        <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                          added {formatDay(row.added_at)}
                        </p>
                      </div>
                      {canEdit && (
                        <button
                          type="button"
                          onClick={() => setRemoving(row)}
                          aria-label={`Remove ${row.domain}`}
                          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[10px] text-xs font-semibold"
                          style={dangerButtonStyle}
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}

            {!canEdit ? (
              <p className="text-sm mt-3" style={{ color: "var(--text-muted)" }}>
                Only the owner can change this list.
              </p>
            ) : atLimit ? (
              <p className="text-sm mt-3" style={{ color: "var(--text-secondary)" }}>
                You can list at most {settings.domain_limit} domains.
              </p>
            ) : (
              <form onSubmit={(e) => void addDomain(e)} className="mt-4" aria-label="Add an organisation domain">
                <label htmlFor={domainInputId} className="sr-only">
                  Domain to add
                </label>
                <div className="flex items-center gap-2 flex-wrap">
                  <input
                    id={domainInputId}
                    className={`${inputCls} flex-1 min-w-[12rem]`}
                    style={inputStyle}
                    value={newDomain}
                    maxLength={253}
                    placeholder="example.org"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    onChange={(e) => setNewDomain(e.target.value)}
                  />
                  <button
                    type="submit"
                    disabled={saving || !newDomain.trim()}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
                    style={{ minHeight: 40, background: "var(--accent-primary)", color: "var(--text-on-accent)" }}
                  >
                    {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
                    Add
                  </button>
                </div>
                {formError && (
                  <p role="alert" className="text-sm mt-2" style={{ color: "var(--accent-danger)" }}>
                    {formError}
                  </p>
                )}
              </form>
            )}
          </section>
        </>
      )}

      <ConfirmDialog
        open={confirmingForget}
        title="Forget the sent-to history?"
        message="Every address will count as new again."
        confirmLabel="Forget"
        danger
        onConfirm={forget}
        onCancel={() => setConfirmingForget(false)}
      />
      <ConfirmDialog
        open={removing !== null}
        title={removing ? `Remove ${removing.domain}?` : ""}
        message="Mail there will count as outside your organisation."
        confirmLabel="Remove"
        danger
        onConfirm={() => (removing ? removeDomain(removing) : undefined)}
        onCancel={() => setRemoving(null)}
      />
    </section>
  );
}
