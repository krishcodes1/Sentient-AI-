/**
 * Tests for mailAlertFormat (Security ▸ Mail alerts wording): they prove each verdict and alert
 * state gets its label and tone, that a card's status line reads its state and the time left
 * (and calls a pending card past its deadline expired), that a last-check time is said in minutes,
 * hours and days, that each mailbox state, link check and attachment check has its sentence, that
 * an alert that never reached a chat says why, and that none of it ever calls an email safe.
 *
 * Why it exists: the tab is the one place a person sees every flagged email. A badge that read as
 * a pass, a card that looked open after its deadline, or a silent "not sent" would each mislead
 * someone about mail that may be a scam.
 */

import { describe, expect, it } from "vitest";
import type { MailAlertCard } from "@/types";
import {
  CARD_NOT_MADE,
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
  hasWaitingCard,
  lastCheckText,
  linkChecksText,
  reviewHeading,
  secondsUntil,
  timeLeft,
  verdictBadge,
} from "@/pages/security/mailAlertFormat";

const NOW = Date.parse("2026-10-14T12:00:00Z");
const HOUR = 3600;

function card(overrides: Partial<MailAlertCard>): MailAlertCard {
  return { action_id: "act-1", kind: "move_to_spam", status: "pending", expires_at: null, ...overrides };
}

describe("mailAlertFormat", () => {
  it("maps each verdict to its label and tone", () => {
    expect(verdictBadge({ verdict: "likely_scam", status: "alerted" })).toEqual({ label: "Likely scam", tone: "danger" });
    expect(verdictBadge({ verdict: "suspicious", status: "alerted" })).toEqual({ label: "Suspicious", tone: "warning" });
    expect(verdictBadge({ verdict: "no_signs", status: "quiet" })).toEqual({
      label: "No signs found by the AI review",
      tone: "neutral",
    });
    // A verdict this build does not know is still a warning, never a pass.
    expect(verdictBadge({ verdict: "unknown", status: "alerted" })).toEqual({ label: "Flagged", tone: "warning" });
    // Closed alerts fade whatever their verdict was.
    expect(verdictBadge({ verdict: "likely_scam", status: "dismissed" })).toEqual({ label: "Dismissed", tone: "muted" });
    expect(verdictBadge({ verdict: "suspicious", status: "expired" })).toEqual({ label: "Expired", tone: "muted" });
  });

  it("reads a card's status and time left", () => {
    const in23h = new Date(NOW + 23.5 * HOUR * 1000).toISOString();
    const secs = secondsUntil(in23h, NOW);
    expect(secs).toBe(23.5 * HOUR);
    expect(cardStatusLine(card({ expires_at: in23h }), "gmail", secs)).toBe("Move to Spam: waiting (expires in 23 h)");
    expect(cardStatusLine(card({}), "outlook", 40 * 60)).toBe("Move to Junk: waiting (expires in 40 min)");
    expect(cardStatusLine(card({}), "gmail", 30)).toBe("Move to Spam: waiting (expires in under a minute)");
    expect(cardStatusLine(card({}), "gmail", null)).toBe("Move to Spam: waiting for your decision");
    // Pending on the server but past its deadline: a decision would fail, so it reads expired.
    expect(cardStatusLine(card({}), "gmail", 0)).toBe("Move to Spam: expired");
    expect(cardStatusLine(card({ status: "approved" }), "gmail", null)).toBe("Move to Spam: approved");
    expect(cardStatusLine(card({ status: "denied" }), "outlook", null)).toBe("Move to Junk: denied");
    expect(cardStatusLine(card({ status: "expired" }), "gmail", null)).toBe("Move to Spam: expired");
    expect(cardStatusLine(card({ status: "missing" }), "gmail", null)).toBe("Move to Spam: the card no longer exists");

    expect(cardIsWaiting(card({}), null)).toBe(true);
    expect(cardIsWaiting(card({}), 5)).toBe(true);
    expect(cardIsWaiting(card({}), 0)).toBe(false);
    expect(cardIsWaiting(card({ status: "approved" }), 500)).toBe(false);
    expect(secondsUntil(null, NOW)).toBeNull();
    expect(secondsUntil("not a date", NOW)).toBeNull();
    expect(secondsUntil(new Date(NOW - 1000).toISOString(), NOW)).toBe(0);
    expect(timeLeft(2 * HOUR + 59 * 60)).toBe("2 h");

    const waiting = { cards: [card({ expires_at: in23h })] };
    expect(hasWaitingCard(waiting, "move_to_spam", NOW)).toBe(true);
    expect(hasWaitingCard(waiting, "move_to_spam", NOW + 24 * HOUR * 1000)).toBe(false);
    expect(hasWaitingCard({ cards: [card({ status: "denied" })] }, "move_to_spam", NOW)).toBe(false);
    expect(hasWaitingCard({ cards: [] }, "move_to_spam", NOW)).toBe(false);

    // The button that makes a card shows only while the server offers it and no card of that kind
    // waits; a decided one (approved, denied or expired) can be asked for again, since an approved
    // card does not say the move worked.
    const offered = { actions: ["move_to_spam" as const], cards: [] as MailAlertCard[] };
    expect(actionOffered(offered, "move_to_spam", NOW)).toBe(true);
    expect(actionOffered({ ...offered, actions: [] }, "move_to_spam", NOW)).toBe(false);
    expect(actionOffered({ ...offered, cards: [card({ expires_at: in23h })] }, "move_to_spam", NOW)).toBe(false);
    expect(actionOffered({ ...offered, cards: [card({ status: "approved" })] }, "move_to_spam", NOW)).toBe(true);
    expect(actionOffered({ ...offered, cards: [card({ status: "denied" })] }, "move_to_spam", NOW)).toBe(true);
    expect(actionOffered({ ...offered, cards: [card({ status: "expired" })] }, "move_to_spam", NOW)).toBe(true);
    expect(
      actionOffered({ ...offered, cards: [card({ expires_at: in23h })] }, "move_to_spam", NOW + 24 * HOUR * 1000),
    ).toBe(true);

    expect(actionLabel("move_to_spam", "gmail")).toBe("Move to Spam");
    expect(actionLabel("move_to_spam", "outlook")).toBe("Move to Junk");
    expect(actionLabel("archive_it", "gmail")).toBe("Archive it");
  });

  it("formats a last-check time in minutes and hours", () => {
    const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();
    expect(lastCheckText(null, NOW)).toBe("not checked yet");
    expect(lastCheckText("garbage", NOW)).toBe("not checked yet");
    expect(lastCheckText(ago(20), NOW)).toBe("just now");
    expect(lastCheckText(ago(2 * 60), NOW)).toBe("2 min ago");
    // The tab's clock ticks every few seconds, so a check 1 min 50 s ago still reads "2 min ago".
    expect(lastCheckText(ago(110), NOW)).toBe("2 min ago");
    expect(lastCheckText(ago(59 * 60), NOW)).toBe("59 min ago");
    expect(lastCheckText(ago(3 * HOUR), NOW)).toBe("3 h ago");
    expect(lastCheckText(ago(26 * HOUR), NOW)).toBe("1 day ago");
    expect(lastCheckText(ago(72 * HOUR), NOW)).toBe("3 days ago");
    // A clock a little behind the server never says "in the future".
    expect(lastCheckText(new Date(NOW + 4000).toISOString(), NOW)).toBe("just now");
  });

  it("words each mailbox state and which button it gets", () => {
    expect(accountStatusText("active")).toBe("Checking new mail");
    expect(accountStatusText("starting")).toBe("First check soon");
    expect(accountStatusText("paused")).toBe("Paused");
    expect(accountStatusText("error")).toBe("Stopped after repeated errors");
    expect(accountStatusText("no_access")).toBe("Reading mail isn't allowed on this account");
    expect(["active", "starting", "paused", "error", "no_access"].map((s) => accountResumes(s as never))).toEqual([
      false,
      false,
      true,
      true,
      false,
    ]);
  });

  it("says which link and attachment checks ran", () => {
    expect(linkChecksText("local")).toBe("Links checked on this computer only (no Safe Browsing key).");
    expect(linkChecksText("local_and_remote")).toBe("Links checked on this computer and with Google Safe Browsing.");
    expect(fileChecksText("off")).toBe("Attachments: not checked with VirusTotal (no key).");
    expect(fileChecksText("remote")).toBe("Attachments: checked with VirusTotal (only each file's fingerprint is sent).");
  });

  it("says why an alert never reached Telegram or Slack, and nothing when it did", () => {
    expect(alertNoteText({ delivered: true, alert_note: null, status: "alerted" })).toBeNull();
    expect(alertNoteText({ delivered: false, alert_note: "not delivered", status: "alerted" })).toBe(
      "Not sent to Telegram or Slack: no linked Telegram or Slack chat took it.",
    );
    expect(alertNoteText({ delivered: false, alert_note: "held: too many alerts this hour", status: "alerted" })).toBe(
      "Not sent to Telegram or Slack: held back, because there were too many alerts this hour.",
    );
    expect(
      alertNoteText({ delivered: false, alert_note: "listed: weak signs and no AI review", status: "alerted" }),
    ).toMatch(/^Not sent to Telegram or Slack: its signs were weak and no AI review was available/);
    expect(alertNoteText({ delivered: false, alert_note: "something new", status: "alerted" })).toBe(
      "Not sent to Telegram or Slack: something new",
    );
    expect(alertNoteText({ delivered: false, alert_note: null, status: "dismissed" })).toBe(
      "Not sent to Telegram or Slack: no linked Telegram or Slack chat took it.",
    );
    expect(alertNoteText({ delivered: true, alert_note: "card not made", status: "alerted" })).toBe(CARD_NOT_MADE);
    // Both at once: not delivered, and the card failed too.
    expect(alertNoteText({ delivered: false, alert_note: "not delivered; card not made", status: "alerted" })).toBe(
      `Not sent to Telegram or Slack: no linked Telegram or Slack chat took it. ${CARD_NOT_MADE}`,
    );
    // Quiet alerts are never pushed by design, and expired ones were never alerted.
    expect(alertNoteText({ delivered: false, alert_note: null, status: "quiet" })).toBeNull();
    expect(alertNoteText({ delivered: false, alert_note: "expired", status: "expired" })).toBeNull();
  });

  it("names the model behind an AI review and formats when the email arrived", () => {
    expect(reviewHeading({ provider: "gemini", model: "gemini-2.5-flash" })).toBe("AI review (gemini-2.5-flash)");
    expect(reviewHeading({ provider: "ollama", model: "" })).toBe("AI review (ollama)");
    expect(reviewHeading({ provider: "", model: "" })).toBe("AI review");
    expect(formatReceived("not a date")).toBe("not a date");
    // In the viewer's own locale and zone, so only that it is formatted is pinned (not the words).
    const formatted = formatReceived("2026-10-14T09:12:00Z");
    expect(formatted).not.toBe("2026-10-14T09:12:00Z");
    expect(formatted.length).toBeGreaterThan(0);
    expect(formatted).toBe(
      new Date("2026-10-14T09:12:00Z").toLocaleString(undefined, {
        weekday: "short",
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      }),
    );
  });

  it("never calls an email safe except to say that silence does not mean it is", () => {
    const sentences = [
      QUIET_SENTENCE,
      NO_FURTHER_SIGNS,
      EMPTY_OPEN_VIEW,
      verdictBadge({ verdict: "no_signs", status: "quiet" }).label,
      verdictBadge({ verdict: "unknown", status: "alerted" }).label,
    ];
    for (const sentence of sentences) {
      const withoutDisclaimers = sentence
        .replace("this does not mean it is safe", "")
        .replace("that never means an email is safe", "");
      expect(withoutDisclaimers).not.toMatch(/safe/i);
    }
  });
});
