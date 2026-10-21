/**
 * mailAlertFormat: the words and tones of Security ▸ Mail alerts. A verdict's badge, an approval
 * card's status line and time left, how long ago a mailbox was checked, each mailbox's state, the
 * link and attachment check lines, and why an alert was not sent to Telegram or Slack.
 *
 * Why it exists: the tab must word every state the same way each time and must never call an
 * email safe (an empty finding only means no warning signs were seen). Keeping the wording in one
 * pure module lets a test pin it, and keeps Fast Refresh working for the tab component.
 */

import type { MailAlert, MailAlertCard, MailScanAccount, MailScanStatus } from "@/types";

/** How a badge is coloured: red, amber, grey, or faded for an alert that is no longer open. */
export type MailTone = "danger" | "warning" | "neutral" | "muted";

export interface MailBadge {
  label: string;
  tone: MailTone;
}

/** A quiet alert: weak signs, an authenticated sender and an AI review that found none. */
export const QUIET_SENTENCE =
  "No signs found by the AI review, and Crawler's own signs were weak (this does not mean it is safe).";

/** A review that ran and found nothing more never takes back Crawler's own findings. */
export const NO_FURTHER_SIGNS =
  "AI review: found no further signs (Crawler's own findings above still stand).";

/** The empty Open view. It says what silence means, so nobody reads it as "your mail is safe". */
export const EMPTY_OPEN_VIEW =
  "No suspicious mail found. Crawler checks new mail every few minutes and tells you only when it " +
  "finds warning signs; that never means an email is safe.";

/**
 * The badge on an alert row. Dismissed and expired alerts are faded whatever their verdict, a
 * quiet one is grey, and an open one is red (likely scam) or amber (suspicious, or a verdict this
 * tab does not know yet, which is still a warning and never a pass).
 */
export function verdictBadge(alert: Pick<MailAlert, "verdict" | "status">): MailBadge {
  if (alert.status === "dismissed") return { label: "Dismissed", tone: "muted" };
  if (alert.status === "expired") return { label: "Expired", tone: "muted" };
  if (alert.status === "quiet" || alert.verdict === "no_signs") {
    return { label: "No signs found by the AI review", tone: "neutral" };
  }
  if (alert.verdict === "likely_scam") return { label: "Likely scam", tone: "danger" };
  if (alert.verdict === "suspicious") return { label: "Suspicious", tone: "warning" };
  return { label: "Flagged", tone: "warning" };
}

/**
 * The button and card name for a mail action, in the mailbox's own words: Gmail has Spam, Outlook
 * has Junk Email. `kind` is a plain string so a kind this build does not know still gets a name.
 */
export function actionLabel(kind: string, provider: MailAlert["provider"]): string {
  if (kind === "move_to_spam") return provider === "outlook" ? "Move to Junk" : "Move to Spam";
  const words = kind.replace(/_/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Mail action";
}

/** Time left on a card, coarse on purpose: "23 h", "40 min", "under a minute". */
export function timeLeft(seconds: number): string {
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)} h`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)} min`;
  return "under a minute";
}

/**
 * A card is still waiting for a decision while the server says pending and its deadline (if any)
 * has not passed. `secondsLeft` is null when the card has no deadline or it cannot be read.
 */
export function cardIsWaiting(card: Pick<MailAlertCard, "status">, secondsLeft: number | null): boolean {
  return card.status === "pending" && (secondsLeft === null || secondsLeft > 0);
}

/** Seconds from `nowMs` to the card's deadline, or null when it has none (or it is not a date). */
export function secondsUntil(iso: string | null, nowMs: number): number | null {
  if (!iso) return null;
  const at = new Date(iso).getTime();
  return Number.isNaN(at) ? null : Math.max(0, Math.ceil((at - nowMs) / 1000));
}

/**
 * One card's status line, "Move to Spam: waiting (expires in 23 h)". A pending card past its
 * deadline reads as expired here even before the server says so, since a decision would fail.
 */
export function cardStatusLine(
  card: MailAlertCard,
  provider: MailAlert["provider"],
  secondsLeft: number | null,
): string {
  const label = actionLabel(card.kind, provider);
  switch (card.status) {
    case "pending":
      if (secondsLeft === null) return `${label}: waiting for your decision`;
      if (secondsLeft <= 0) return `${label}: expired`;
      return `${label}: waiting (expires in ${timeLeft(secondsLeft)})`;
    case "approved":
      return `${label}: approved`;
    case "denied":
      return `${label}: denied`;
    case "expired":
      return `${label}: expired`;
    default:
      return `${label}: the card no longer exists`;
  }
}

/** True when a card of `kind` on this alert is still waiting for a decision. */
export function hasWaitingCard(alert: Pick<MailAlert, "cards">, kind: string, nowMs: number): boolean {
  return alert.cards.some(
    (card) => card.kind === kind && cardIsWaiting(card, secondsUntil(card.expires_at, nowMs)),
  );
}

/**
 * Whether the row offers the button that makes a card of `kind`: the server must offer the action,
 * and no card of that kind may still be waiting (a second one would be a 409). Once a card was
 * decided, approved included, it can be asked for again: an approved card only says the person
 * agreed, not that the move worked (a sign-in that expired meanwhile fails it), so the server's
 * `actions` decide.
 */
export function actionOffered(alert: Pick<MailAlert, "actions" | "cards">, kind: string, nowMs: number): boolean {
  if (!alert.actions.some((offered) => offered === kind)) return false;
  return !hasWaitingCard(alert, kind, nowMs);
}

/**
 * How long ago a mailbox was last checked: "just now", "2 min ago", "3 h ago", "2 days ago", or
 * "not checked yet" before the first check. Minutes and hours are rounded, so a clock that ticks
 * every few seconds still reads naturally.
 */
export function lastCheckText(iso: string | null, nowMs: number): string {
  if (!iso) return "not checked yet";
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return "not checked yet";
  const seconds = Math.max(0, Math.round((nowMs - at) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}

/** When an email arrived, in the viewer's own time ("Tue, Oct 14, 9:12 AM"); as given if unreadable. */
export function formatReceived(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/** A mailbox's state in words. */
export function accountStatusText(status: MailScanAccount["status"]): string {
  switch (status) {
    case "active":
      return "Checking new mail";
    case "starting":
      return "First check soon";
    case "paused":
      return "Paused";
    case "error":
      return "Stopped after repeated errors";
    case "no_access":
      return "Reading mail isn't allowed on this account";
    default:
      return status;
  }
}

/** Whether the mailbox's button resumes it (paused or stopped) rather than pausing it. */
export function accountResumes(status: MailScanAccount["status"]): boolean {
  return status === "paused" || status === "error";
}

/** Which link checks ran: always on this computer, and Safe Browsing only with the owner's key. */
export function linkChecksText(linkChecks: MailScanStatus["link_checks"]): string {
  return linkChecks === "local_and_remote"
    ? "Links checked on this computer and with Google Safe Browsing."
    : "Links checked on this computer only (no Safe Browsing key).";
}

/** Whether attachments are looked up on VirusTotal (by fingerprint only, never the file). */
export function fileChecksText(fileChecks: MailScanStatus["file_checks"]): string {
  return fileChecks === "remote"
    ? "Attachments: checked with VirusTotal (only each file's fingerprint is sent)."
    : "Attachments: not checked with VirusTotal (no key).";
}

/** The server's short notes, said in full on the row. Anything else is shown as it came. */
const NOT_SENT_REASONS: Record<string, string> = {
  "not delivered": "no linked Telegram or Slack chat took it.",
  "held: too many alerts this hour": "held back, because there were too many alerts this hour.",
  "listed: weak signs and no AI review":
    "its signs were weak and no AI review was available, so it is only listed here and counted in the daily summary.",
};

export const CARD_NOT_MADE = "The card to move it could not be made. Use the button below to try again.";

/**
 * Why this alert is on the tab without having reached a chat, and that its card could not be made.
 * The server joins its short notes with "; " ("not delivered; card not made"). Null when there is
 * nothing to say: it was delivered, it went quiet by design, or it expired.
 */
export function alertNoteText(
  alert: Pick<MailAlert, "delivered" | "alert_note" | "status">,
): string | null {
  const parts = (alert.alert_note ?? "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);
  const cardFailed = parts.includes("card not made");
  const note = parts.filter((part) => part !== "card not made")[0] ?? "";
  const lines: string[] = [];
  if (!alert.delivered && alert.status !== "quiet" && alert.status !== "expired") {
    const reason = NOT_SENT_REASONS[note] ?? (note ? note : NOT_SENT_REASONS["not delivered"]);
    lines.push(`Not sent to Telegram or Slack: ${reason}`);
  }
  if (cardFailed) lines.push(CARD_NOT_MADE);
  return lines.length > 0 ? lines.join(" ") : null;
}

/** The AI review's heading: which model gave it, so a local model reads differently from a cloud one. */
export function reviewHeading(review: { provider: string; model: string }): string {
  const who = review.model.trim() || review.provider.trim();
  return who ? `AI review (${who})` : "AI review";
}
