/**
 * MailAlertsTab: Security ▸ "Mail alerts". The automatic scam check's switch and today's AI
 * reviews, which outside checks are on, this account's checked mailboxes (each with Pause or
 * Resume), and the flagged emails: verdict, sender, subject, Crawler's own reasons, the AI review
 * or why there was none, and the Move to Spam/Junk approval card, decided right on the row.
 *
 * Why it exists: every few minutes Crawler checks new Gmail and Outlook mail for scams and pushes
 * the worrying ones to Telegram or Slack. This tab is where a person sees all of them, including
 * the ones that were held back or never reached a chat, and acts on them. Nothing touches the
 * mailbox without an approved card, and the tab never calls an email safe. The owner also sees
 * install-wide counts (numbers only, never anyone else's mail). Block sender is not offered: the
 * owner deferred it (decisions.md 8a).
 */

import { useEffect, useId, useRef, useState, useSyncExternalStore } from "react";
import { Link } from "react-router-dom";
import { Loader2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText } from "@/components/formStyles";
import { useCountdown } from "@/pages/approvalCountdown";
import {
  EMPTY_OPEN_VIEW,
  NO_FURTHER_SIGNS,
  QUIET_SENTENCE,
  accountResumes,
  accountStatusText,
  actionLabel,
  actionOffered,
  alertNoteText,
  cardIsWaiting,
  cardStatusLine,
  fileChecksText,
  formatReceived,
  lastCheckText,
  linkChecksText,
  reviewHeading,
  verdictBadge,
  type MailTone,
} from "@/pages/security/mailAlertFormat";
import {
  decideApproval,
  dismissMailAlert,
  getMailScanStatus,
  listMailAlerts,
  requestMailAlertAction,
  setMailScanPaused,
} from "@/services/api";
import type { MailAlert, MailAlertCard, MailScanAccount, MailScanStatus } from "@/types";

type View = "open" | "all";

/** The only action this tab offers (Block sender is deferred by the owner). */
const MOVE_TO_SPAM = "move_to_spam";
/** The server's default page; a reload asks for more only when more are on screen. */
const PAGE_SIZE = 20;
const MAX_PAGE = 50;
const OFF_FALLBACK = "Automatic scam checks on new email are turned off.";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const smallButtonCls =
  "inline-flex items-center gap-1.5 px-3 rounded-[8px] text-xs font-semibold disabled:opacity-50";
const quietButtonStyle = {
  minHeight: 36,
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

const TONE_STYLES: Record<MailTone, { color: string; background: string; border: string }> = {
  danger: { color: "var(--accent-danger)", background: "var(--fill-danger)", border: "1px solid var(--border-danger)" },
  warning: { color: "var(--accent-warning)", background: "var(--fill-warning)", border: "1px solid var(--border-warning)" },
  neutral: { color: "var(--text-secondary)", background: "var(--fill-neutral)", border: "1px solid var(--claw-border)" },
  muted: { color: "var(--text-muted)", background: "transparent", border: "1px solid var(--claw-border)" },
};

// A coarse clock for "last check 2 min ago" and for hiding a button while its card still waits.
// It is read through useSyncExternalStore (as approvalCountdown does), and its value only changes
// every few seconds, so a render never reads the time directly and rows re-render only on a tick.
const CLOCK_STEP_MS = 5000;
function clockNow(): number {
  return Math.floor(Date.now() / CLOCK_STEP_MS) * CLOCK_STEP_MS;
}
function subscribeClock(onTick: () => void): () => void {
  const id = window.setInterval(onTick, CLOCK_STEP_MS);
  return () => window.clearInterval(id);
}
function useClock(): number {
  return useSyncExternalStore(subscribeClock, clockNow);
}

export default function MailAlertsTab({ isOwner }: { isOwner: boolean }) {
  const headingId = useId();
  const [view, setView] = useState<View>("open");
  const [status, setStatus] = useState<MailScanStatus | null>(null);
  const [alerts, setAlerts] = useState<MailAlert[] | null>(null);
  const [nextBefore, setNextBefore] = useState<string | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [olderBusy, setOlderBusy] = useState(false);
  const [olderError, setOlderError] = useState("");
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});
  const [busyRows, setBusyRows] = useState<Record<string, boolean>>({});
  const [accountErrors, setAccountErrors] = useState<Record<string, string>>({});
  const [busyAccount, setBusyAccount] = useState<string | null>(null);
  const [dismissing, setDismissing] = useState<MailAlert | null>(null);
  // The view on screen now, so a slow reload or older page of the view just left is dropped.
  const viewRef = useRef<View>("open");
  const now = useClock();

  useEffect(() => {
    let cancelled = false;
    // The switch and mailboxes, and the alerts of the chosen view, load together.
    Promise.all([getMailScanStatus(), listMailAlerts({ view })])
      .then(([loadedStatus, list]) => {
        if (cancelled) return;
        setStatus(loadedStatus);
        setAlerts(list.alerts);
        setNextBefore(list.next_before);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "Mail alerts could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [view, attempt]);

  const setRowError = (id: string, message: string) =>
    setRowErrors((prev) => {
      const next = { ...prev };
      if (message) next[id] = message;
      else delete next[id];
      return next;
    });

  const chooseView = (next: View) => {
    if (next === view) return;
    viewRef.current = next;
    setView(next);
    setAlerts(null);
    setNextBefore(null);
    setRowErrors({});
    setOlderError("");
  };

  const retry = () => {
    setLoadError("");
    setStatus(null);
    setAlerts(null);
    setAttempt((n) => n + 1);
  };

  /** After a card is decided its status changes on the server, so the alerts on screen reload. */
  const reloadAlerts = async () => {
    const shown = alerts?.length ?? 0;
    const list = await listMailAlerts(
      shown > PAGE_SIZE ? { view, limit: Math.min(MAX_PAGE, shown) } : { view },
    );
    if (viewRef.current !== view) return;
    setAlerts(list.alerts);
    setNextBefore(list.next_before);
  };

  const decide = async (alert: MailAlert, card: MailAlertCard, approved: boolean) => {
    setRowError(alert.id, "");
    try {
      await decideApproval(card.action_id, approved);
    } catch (err) {
      setRowError(alert.id, errorText(err, "The decision could not be sent. Try again."));
      return;
    }
    try {
      await reloadAlerts();
    } catch (err) {
      setRowError(alert.id, errorText(err, "The alerts could not be reloaded. Reload the page to see the card's state."));
    }
  };

  const requestAction = async (alert: MailAlert) => {
    setRowError(alert.id, "");
    setBusyRows((prev) => ({ ...prev, [alert.id]: true }));
    try {
      const { card } = await requestMailAlertAction(alert.id, MOVE_TO_SPAM);
      setAlerts(
        (prev) =>
          prev &&
          prev.map((row) =>
            row.id === alert.id
              ? { ...row, cards: [...row.cards.filter((c) => c.action_id !== card.action_id), card] }
              : row,
          ),
      );
    } catch (err) {
      // 409 (a card is already waiting), 422 (not offered, and why) and 404 say so as is; the
      // alert stays where it is.
      setRowError(alert.id, errorText(err, "The card could not be made. Try again."));
    } finally {
      setBusyRows((prev) => ({ ...prev, [alert.id]: false }));
    }
  };

  const dismiss = async (target: MailAlert) => {
    // ConfirmDialog shows a failure inline and stays open.
    await dismissMailAlert(target.id);
    setAlerts(
      (prev) =>
        prev &&
        (view === "open"
          ? prev.filter((row) => row.id !== target.id)
          : prev.map((row) => (row.id === target.id ? { ...row, status: "dismissed" as const } : row))),
    );
    setRowError(target.id, "");
    setDismissing(null);
  };

  const togglePaused = async (account: MailScanAccount) => {
    const paused = !accountResumes(account.status);
    setBusyAccount(account.connector_id);
    setAccountErrors((prev) => ({ ...prev, [account.connector_id]: "" }));
    try {
      const updated = await setMailScanPaused(account.connector_id, paused);
      setStatus(
        (prev) =>
          prev && {
            ...prev,
            accounts: prev.accounts.map((row) => (row.connector_id === updated.connector_id ? updated : row)),
          },
      );
    } catch (err) {
      setAccountErrors((prev) => ({
        ...prev,
        [account.connector_id]: errorText(
          err,
          paused ? "Checking this mailbox could not be paused." : "Checking this mailbox could not be resumed.",
        ),
      }));
    } finally {
      setBusyAccount(null);
    }
  };

  const loadOlder = async () => {
    if (!nextBefore) return;
    setOlderBusy(true);
    setOlderError("");
    try {
      const list = await listMailAlerts({ view, before: nextBefore });
      if (viewRef.current !== view) return;
      setAlerts((prev) => {
        const known = new Set((prev ?? []).map((row) => row.id));
        return [...(prev ?? []), ...list.alerts.filter((row) => !known.has(row.id))];
      });
      setNextBefore(list.next_before);
    } catch (err) {
      setOlderError(errorText(err, "Older alerts could not be loaded."));
    } finally {
      setOlderBusy(false);
    }
  };

  return (
    <section aria-labelledby={headingId}>
      <h2 id={headingId} className="text-base font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
        Mail alerts
      </h2>
      <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
        Crawler checks new email in your connected Gmail and Outlook accounts for signs of scams and
        phishing, and tells you when it finds some. Nothing in your mailbox changes unless you
        approve a card.
      </p>

      {loadError ? (
        <ErrorAlert>
          {loadError}{" "}
          <button type="button" className="underline font-medium" onClick={retry}>
            Retry
          </button>
        </ErrorAlert>
      ) : status === null ? (
        <p role="status" className="inline-flex items-center gap-2 text-sm" style={{ color: "var(--text-muted)" }}>
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          Loading mail alerts…
        </p>
      ) : (
        <>
          <StatusHeader status={status} isOwner={isOwner} />
          <Accounts
            accounts={status.accounts}
            now={now}
            busyAccount={busyAccount}
            errors={accountErrors}
            onToggle={(account) => void togglePaused(account)}
          />

          <div className="flex items-center justify-between gap-3 flex-wrap mt-6 mb-3">
            <h3 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
              Flagged emails
            </h3>
            <div role="group" aria-label="Which alerts to show" className="inline-flex gap-1">
              {(["open", "all"] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  aria-pressed={view === option}
                  onClick={() => chooseView(option)}
                  className="px-3 rounded-[8px] text-xs font-semibold"
                  style={{
                    minHeight: 32,
                    background: view === option ? "var(--accent-glow)" : "var(--bg-input)",
                    border: `1px solid ${view === option ? "var(--border-accent)" : "var(--claw-border)"}`,
                    color: view === option ? "var(--accent-primary)" : "var(--text-secondary)",
                  }}
                >
                  {option === "open" ? "Open" : "All"}
                </button>
              ))}
            </div>
          </div>

          {alerts === null ? (
            <p role="status" className="inline-flex items-center gap-2 text-sm" style={{ color: "var(--text-muted)" }}>
              <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
              Loading mail alerts…
            </p>
          ) : alerts.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              {EMPTY_OPEN_VIEW}
            </p>
          ) : (
            <ul className="space-y-3" aria-label="Flagged emails">
              {alerts.map((alert) => (
                <li key={alert.id}>
                  <AlertRow
                    alert={alert}
                    now={now}
                    busy={Boolean(busyRows[alert.id])}
                    error={rowErrors[alert.id] ?? ""}
                    onMove={() => void requestAction(alert)}
                    onDecide={(card, approved) => decide(alert, card, approved)}
                    onDismiss={() => setDismissing(alert)}
                  />
                </li>
              ))}
            </ul>
          )}

          {alerts !== null && nextBefore && (
            <div className="mt-3">
              <button
                type="button"
                disabled={olderBusy}
                onClick={() => void loadOlder()}
                className={smallButtonCls}
                style={quietButtonStyle}
              >
                {olderBusy && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
                Load older alerts
              </button>
            </div>
          )}
          {olderError && (
            <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-danger)" }}>
              {olderError}
            </p>
          )}
        </>
      )}

      <ConfirmDialog
        open={dismissing !== null}
        title="Mark this email as not a scam?"
        message="This alert leaves the open list (it stays under All). Nothing in your mailbox changes."
        confirmLabel="Not a scam"
        onConfirm={() => (dismissing ? dismiss(dismissing) : undefined)}
        onCancel={() => setDismissing(null)}
      />
    </section>
  );
}

/** The switch, today's AI reviews, the link and attachment check lines, and the owner's counts. */
function StatusHeader({ status, isOwner }: { status: MailScanStatus; isOwner: boolean }) {
  return (
    <div className="rounded-[10px] p-3 mb-4 space-y-1" style={rowStyle}>
      {status.enabled ? (
        <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
          Automatic scam checks: on.
        </p>
      ) : (
        <p role="status" className="text-sm font-medium" style={{ color: "var(--accent-warning)" }}>
          {status.when_off || OFF_FALLBACK}
        </p>
      )}
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        AI reviews today: {status.ai_reviews_today} of {status.ai_reviews_per_day}
      </p>
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        {linkChecksText(status.link_checks)}
      </p>
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        {fileChecksText(status.file_checks)}
      </p>
      {isOwner && status.install && (
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          On this Crawler: {status.install.accounts} mailboxes checked · {status.install.alerts_7d} alerts in the
          last 7 days · {status.install.reviews_today} AI reviews today
        </p>
      )}
    </div>
  );
}

/** This account's checked mailboxes, or where to connect one. */
function Accounts({
  accounts,
  now,
  busyAccount,
  errors,
  onToggle,
}: {
  accounts: MailScanAccount[];
  now: number;
  busyAccount: string | null;
  errors: Record<string, string>;
  onToggle: (account: MailScanAccount) => void;
}) {
  if (accounts.length === 0) {
    return (
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        Connect Gmail or Outlook in{" "}
        <Link to="/connectors" className="underline font-semibold">
          Connectors
        </Link>{" "}
        to have new mail checked.
      </p>
    );
  }
  return (
    <div>
      <h3 className="text-sm font-semibold mb-2" style={{ color: "var(--text-primary)" }}>
        Mailboxes
      </h3>
      <ul className="space-y-2" aria-label="Checked mailboxes">
        {accounts.map((account) => {
          const resumes = accountResumes(account.status);
          const error = errors[account.connector_id];
          return (
            <li key={account.connector_id} className="rounded-[10px] p-3" style={rowStyle}>
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <p className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
                    {account.account}{" "}
                    <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
                      · {accountStatusText(account.status)}
                    </span>
                  </p>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                    checked {account.checked_count} · flagged {account.flagged_count}
                    {account.skipped_count > 0 && ` · skipped ${account.skipped_count}`} ·{" "}
                    {account.last_checked_at
                      ? `last check ${lastCheckText(account.last_checked_at, now)}`
                      : "not checked yet"}
                  </p>
                  {account.status === "error" && account.last_error && (
                    <p className="text-xs mt-1 break-words" style={{ color: "var(--accent-danger)" }}>
                      {account.last_error}
                    </p>
                  )}
                  {account.note && (
                    <p className="text-xs mt-1 break-words" style={{ color: "var(--text-secondary)" }}>
                      {account.note}
                    </p>
                  )}
                </div>
                <button
                  type="button"
                  disabled={busyAccount === account.connector_id}
                  onClick={() => onToggle(account)}
                  aria-label={`${resumes ? "Resume" : "Pause"} scam checks for ${account.account}`}
                  className={smallButtonCls}
                  style={quietButtonStyle}
                >
                  {busyAccount === account.connector_id && (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
                  )}
                  {resumes ? "Resume" : "Pause"}
                </button>
              </div>
              {error && (
                <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-danger)" }}>
                  {error}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** One flagged email: what it is, why it was flagged, the AI review, its cards and its buttons. */
function AlertRow({
  alert,
  now,
  busy,
  error,
  onMove,
  onDecide,
  onDismiss,
}: {
  alert: MailAlert;
  now: number;
  busy: boolean;
  error: string;
  onMove: () => void;
  onDecide: (card: MailAlertCard, approved: boolean) => Promise<void>;
  onDismiss: () => void;
}) {
  const badge = verdictBadge(alert);
  const faded = badge.tone === "muted";
  const sender = [alert.from_name, alert.from_address].filter(Boolean).join(" · ");
  const note = alertNoteText(alert);
  const moveLabel = actionLabel(MOVE_TO_SPAM, alert.provider);
  const canMove = actionOffered(alert, MOVE_TO_SPAM, now);
  const canDismiss = alert.status === "alerted" || alert.status === "quiet";

  return (
    <article
      aria-label={`${badge.label}: ${alert.subject}`}
      className="rounded-[10px] p-3"
      style={{ ...rowStyle, opacity: faded ? 0.8 : 1 }}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span
          className="mono-tag px-2 py-0.5 rounded-[6px] text-[11px] font-semibold uppercase tracking-wide"
          style={TONE_STYLES[badge.tone]}
        >
          {badge.label}
        </span>
        <span className="text-xs" style={{ color: "var(--text-muted)" }}>
          {alert.account} · {formatReceived(alert.received_at ?? alert.detected_at)}
        </span>
      </div>
      <p className="text-sm mt-2 break-words" style={{ color: "var(--text-secondary)" }}>
        {sender}
      </p>
      <p className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
        {alert.subject}
      </p>

      {alert.status === "quiet" && (
        <p className="text-xs mt-2" style={{ color: "var(--text-secondary)" }}>
          {QUIET_SENTENCE}
        </p>
      )}

      {alert.reasons.length > 0 && (
        <div className="mt-3">
          <h4 className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
            Why Crawler flagged it
          </h4>
          <ul className="list-disc pl-5 mt-1 space-y-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>
            {alert.reasons.map((reason, i) => (
              <li key={i} className="break-words">
                {reason}
              </li>
            ))}
          </ul>
        </div>
      )}
      {alert.check_notes.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-xs" style={{ color: "var(--text-muted)" }} aria-label="Check notes">
          {alert.check_notes.map((line, i) => (
            <li key={i} className="break-words">
              {line}
            </li>
          ))}
        </ul>
      )}

      <Review alert={alert} />

      {note && (
        <p className="text-xs mt-2" style={{ color: "var(--accent-warning)" }}>
          {note}
        </p>
      )}

      {alert.cards.length > 0 && (
        <ul className="mt-3 space-y-2" aria-label="Approval cards">
          {alert.cards.map((card) => (
            <li key={card.action_id}>
              <CardRow card={card} provider={alert.provider} onDecide={(approved) => onDecide(card, approved)} />
            </li>
          ))}
        </ul>
      )}

      {(canMove || canDismiss) && (
        <div className="flex items-center gap-2 flex-wrap mt-3">
          {canMove && (
            <button
              type="button"
              disabled={busy}
              onClick={onMove}
              className={smallButtonCls}
              style={{ minHeight: 36, background: "var(--accent-primary)", color: "var(--text-on-accent)" }}
            >
              {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
              {moveLabel}
            </button>
          )}
          {canDismiss && (
            <button type="button" onClick={onDismiss} className={smallButtonCls} style={quietButtonStyle}>
              Not a scam…
            </button>
          )}
        </div>
      )}
      {alert.action_hint && (
        <p className="text-xs mt-2 break-words" style={{ color: "var(--text-muted)" }}>
          {alert.action_hint}
        </p>
      )}
      {error && (
        <p role="alert" className="text-xs mt-2 break-words" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
    </article>
  );
}

/** The AI review's reasons and advice, a plain "no further signs", or the note saying why none ran. */
function Review({ alert }: { alert: MailAlert }) {
  const { review, review_note: reviewNote } = alert;
  if (review) {
    const advice = review.advice.trim();
    return (
      <div className="mt-3">
        <h4 className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
          {reviewHeading(review)}
        </h4>
        {review.reasons.length > 0 ? (
          <ul className="list-disc pl-5 mt-1 space-y-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>
            {review.reasons.map((reason, i) => (
              <li key={i} className="break-words">
                {reason}
              </li>
            ))}
          </ul>
        ) : (
          alert.status !== "quiet" && (
            <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
              {NO_FURTHER_SIGNS}
            </p>
          )
        )}
        {advice && (
          <p className="text-xs mt-1 break-words" style={{ color: "var(--text-secondary)" }}>
            What to do: {advice}
          </p>
        )}
      </div>
    );
  }
  if (!reviewNote) return null;
  return (
    <p className="text-xs mt-3 break-words" style={{ color: "var(--text-muted)" }}>
      {reviewNote}
    </p>
  );
}

/** One approval card on a row: its status line and, while it waits, Approve and Deny. */
function CardRow({
  card,
  provider,
  onDecide,
}: {
  card: MailAlertCard;
  provider: MailAlert["provider"];
  onDecide: (approved: boolean) => Promise<void>;
}) {
  const [pending, setPending] = useState(false);
  const secondsLeft = useCountdown(card.expires_at);
  const line = cardStatusLine(card, provider, secondsLeft);
  const waiting = cardIsWaiting(card, secondsLeft);

  const decide = async (approved: boolean) => {
    setPending(true);
    try {
      await onDecide(approved);
    } finally {
      setPending(false);
    }
  };

  return (
    <div
      role="group"
      aria-label={line}
      className="flex items-center justify-between gap-3 flex-wrap rounded-[8px] p-2"
      style={{ background: "var(--claw-panel)", border: "1px solid var(--claw-border)" }}
    >
      <p className="text-xs font-medium" style={{ color: waiting ? "var(--accent-warning)" : "var(--text-secondary)" }}>
        {line}
      </p>
      {waiting && (
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={pending}
            onClick={() => void decide(true)}
            className={smallButtonCls}
            style={{ minHeight: 36, background: "var(--accent-success)", color: "var(--text-on-accent)" }}
          >
            {pending && <Loader2 className="w-3 h-3 animate-spin" aria-hidden />}
            Approve
          </button>
          <button
            type="button"
            disabled={pending}
            onClick={() => void decide(false)}
            className="px-3 rounded-[8px] text-xs font-medium disabled:opacity-50"
            style={{ minHeight: 36, border: "1px solid var(--border-danger)", color: "var(--accent-danger)" }}
          >
            Deny
          </button>
        </div>
      )}
    </div>
  );
}
