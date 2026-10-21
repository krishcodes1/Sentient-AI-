/**
 * Tests for MailAlertsTab (Security ▸ Mail alerts): they prove each flagged email is listed with
 * its verdict, account, sender, subject, Crawler's reasons and the AI review (or why none ran);
 * that the tab never calls an email safe; that the switch being off, a missing mail connection,
 * each mailbox's state, Pause and Resume, and the daily AI review count are shown plainly; that
 * Move to Spam makes a card which Approve then decides; that a refused action keeps its row and
 * shows the server's reason; that "Not a scam" asks first; that Block sender is never offered (the
 * owner deferred it); that install-wide counts reach the owner only; that a "not sent" alert says
 * so; and that older alerts and a failed load can be fetched again.
 *
 * Why it exists: this tab is where a person acts on mail that may be a scam. A row that hid
 * Crawler's reasons, a card decided on the wrong id, a refusal nobody saw, a member seeing the
 * install's numbers, or a tab that read as "your mail is safe" would each put someone at risk.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MailActionKind, MailAlert, MailAlertCard, MailScanAccount, MailScanStatus } from "@/types";

vi.mock("@/services/api", () => {
  class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
      this.name = "ApiError";
    }
  }
  return {
    ApiError,
    getMailScanStatus: vi.fn(),
    listMailAlerts: vi.fn(),
    requestMailAlertAction: vi.fn(),
    dismissMailAlert: vi.fn(),
    setMailScanPaused: vi.fn(),
    decideApproval: vi.fn(),
  };
});

import MailAlertsTab from "@/pages/security/MailAlertsTab";
import {
  ApiError,
  decideApproval,
  dismissMailAlert,
  getMailScanStatus,
  listMailAlerts,
  requestMailAlertAction,
  setMailScanPaused,
} from "@/services/api";

const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();
const hoursFromNow = (n: number) => new Date(Date.now() + n * 3_600_000).toISOString();

function account(overrides: Partial<MailScanAccount>): MailScanAccount {
  return {
    connector_id: "c1",
    account: "School Gmail",
    provider: "gmail",
    status: "active",
    last_checked_at: minutesAgo(2),
    checked_count: 128,
    flagged_count: 6,
    skipped_count: 0,
    last_error: null,
    note: null,
    ...overrides,
  };
}

function status(overrides: Partial<MailScanStatus> = {}): MailScanStatus {
  return {
    enabled: true,
    when_off: null,
    ai_reviews_today: 3,
    ai_reviews_per_day: 20,
    link_checks: "local_and_remote",
    file_checks: "off",
    accounts: [account({})],
    install: null,
    ...overrides,
  };
}

function alertOf(overrides: Partial<MailAlert>): MailAlert {
  return {
    id: "a1",
    connector_id: "c1",
    account: "School Gmail",
    provider: "gmail",
    verdict: "likely_scam",
    status: "alerted",
    from_name: "PayPal Service",
    from_address: "service@paypa1-support[.]com",
    subject: "Your account has been limited",
    received_at: "2026-10-14T09:12:00Z",
    detected_at: "2026-10-14T09:14:00Z",
    reasons: [
      "The sender's domain paypa1-support[.]com imitates paypal[.]com but is not it.",
      "A link shows paypal[.]com/signin but goes to bit[.]ly.",
    ],
    check_notes: [],
    review: {
      reasons: ["It asks you to confirm your details within 24 hours through a link that does not go to PayPal."],
      advice: "Don't click its links, open its attachments or reply.",
      provider: "gemini",
      model: "gemini-2.5-flash",
    },
    review_note: null,
    delivered: true,
    alert_note: null,
    cards: [],
    actions: ["move_to_spam"],
    action_hint: null,
    ...overrides,
  };
}

const SCAM = alertOf({});
const INVOICE = alertOf({
  id: "a2",
  connector_id: "c2",
  account: "Work Outlook",
  provider: "outlook",
  verdict: "suspicious",
  from_name: "Accounts Payable",
  from_address: "ap@vendor-invoices[.]net",
  subject: "(The subject is not shown: it looked like instructions aimed at an AI assistant.)",
  reasons: ["Replies would go to a free webmail address (gmail[.]com), not to the sender's domain."],
  check_notes: ["Links were not checked against the link service this time."],
  review: null,
  review_note: "AI review not done (today's limit of 20 AI reviews is used up).",
});

function pendingCard(overrides: Partial<MailAlertCard> = {}): MailAlertCard {
  return { action_id: "act-1", kind: "move_to_spam", status: "pending", expires_at: hoursFromNow(23.5), ...overrides };
}

function renderTab(isOwner = false) {
  return render(
    <MemoryRouter>
      <MailAlertsTab isOwner={isOwner} />
    </MemoryRouter>,
  );
}

/** The alert's own card on the page, found by its subject (waiting for it to appear). */
function findRow(subject: string): Promise<HTMLElement> {
  return waitFor(() => {
    const row = screen.queryAllByRole("article").find((el) => within(el).queryByText(subject) !== null);
    if (!row) throw new Error(`no alert row for ${subject}`);
    return row;
  });
}

describe("MailAlertsTab", () => {
  beforeEach(() => {
    vi.mocked(getMailScanStatus).mockReset().mockResolvedValue(status());
    vi.mocked(listMailAlerts).mockReset().mockResolvedValue({ alerts: [SCAM], next_before: null });
    vi.mocked(requestMailAlertAction).mockReset();
    vi.mocked(dismissMailAlert).mockReset();
    vi.mocked(setMailScanPaused).mockReset();
    vi.mocked(decideApproval).mockReset();
  });

  it("lists each alert with its verdict, account, sender, subject and Crawler's reasons", async () => {
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [SCAM, INVOICE], next_before: null });
    renderTab();

    expect(screen.getByRole("region", { name: "Mail alerts" })).toBeInTheDocument();
    expect(screen.getByText("Loading mail alerts…")).toBeInTheDocument();
    const scam = await findRow("Your account has been limited");
    expect(screen.getAllByRole("article")).toHaveLength(2);
    expect(scam).toHaveAccessibleName("Likely scam: Your account has been limited");
    expect(within(scam).getByText("Likely scam")).toBeInTheDocument();
    expect(within(scam).getByText(/^School Gmail · /)).toBeInTheDocument();
    expect(within(scam).getByText("PayPal Service · service@paypa1-support[.]com")).toBeInTheDocument();
    expect(within(scam).getByText("Why Crawler flagged it")).toBeInTheDocument();
    expect(
      within(scam).getByText("The sender's domain paypa1-support[.]com imitates paypal[.]com but is not it."),
    ).toBeInTheDocument();
    expect(within(scam).getByText("A link shows paypal[.]com/signin but goes to bit[.]ly.")).toBeInTheDocument();

    const invoice = await findRow(INVOICE.subject);
    expect(within(invoice).getByText("Suspicious")).toBeInTheDocument();
    expect(within(invoice).getByText(/^Work Outlook · /)).toBeInTheDocument();
    expect(within(invoice).getByText("Accounts Payable · ap@vendor-invoices[.]net")).toBeInTheDocument();
    expect(within(invoice).getByText("Links were not checked against the link service this time.")).toBeInTheDocument();
    // Outlook says Junk, Gmail says Spam.
    expect(within(invoice).getByRole("button", { name: "Move to Junk" })).toBeInTheDocument();
    expect(within(scam).getByRole("button", { name: "Move to Spam" })).toBeInTheDocument();

    expect(vi.mocked(listMailAlerts).mock.calls).toEqual([[{ view: "open" }]]);
    expect(getMailScanStatus).toHaveBeenCalledTimes(1);
  });

  it("shows the AI review's reasons and advice, or the note saying why there was none", async () => {
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [SCAM, INVOICE], next_before: null });
    renderTab();

    const scam = await findRow(SCAM.subject);
    expect(within(scam).getByText("AI review (gemini-2.5-flash)")).toBeInTheDocument();
    expect(
      within(scam).getByText(
        "It asks you to confirm your details within 24 hours through a link that does not go to PayPal.",
      ),
    ).toBeInTheDocument();
    expect(within(scam).getByText("What to do: Don't click its links, open its attachments or reply.")).toBeInTheDocument();

    const invoice = await findRow(INVOICE.subject);
    expect(within(invoice).getByText("AI review not done (today's limit of 20 AI reviews is used up).")).toBeInTheDocument();
    expect(within(invoice).queryByText(/^AI review \(/)).not.toBeInTheDocument();
  });

  it("never calls an email safe, even when the AI review found no signs", async () => {
    const stillSuspicious = alertOf({
      id: "a3",
      verdict: "suspicious",
      subject: "Invoice overdue",
      review: { reasons: [], advice: "", provider: "gemini", model: "gemini-2.5-flash" },
    });
    const quiet = alertOf({
      id: "a4",
      verdict: "no_signs",
      status: "quiet",
      subject: "Your weekly newsletter",
      reasons: ["A link's shown text names a different site than it goes to."],
      review: { reasons: [], advice: "", provider: "ollama", model: "llama3.1" },
      delivered: false,
      actions: [],
    });
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [stillSuspicious, quiet], next_before: null });
    renderTab();

    const suspicious = await findRow("Invoice overdue");
    expect(within(suspicious).getByText("Suspicious")).toBeInTheDocument();
    expect(
      within(suspicious).getByText("AI review: found no further signs (Crawler's own findings above still stand)."),
    ).toBeInTheDocument();
    const quietRow = await findRow("Your weekly newsletter");
    expect(within(quietRow).getByText("No signs found by the AI review")).toBeInTheDocument();
    expect(
      within(quietRow).getByText(
        "No signs found by the AI review, and Crawler's own signs were weak (this does not mean it is safe).",
      ),
    ).toBeInTheDocument();
    // A quiet alert was never meant for a chat, so it does not say "not sent".
    expect(within(quietRow).queryByText(/Not sent to Telegram or Slack/)).not.toBeInTheDocument();

    // Remove the disclaimer; no other "safe" may remain on any alert. (The header's "Google Safe
    // Browsing" is a service's name, not a verdict, so only the alerts are read.)
    const text = (screen.getByRole("list", { name: "Flagged emails" }).textContent ?? "").replace(
      "this does not mean it is safe",
      "",
    );
    expect(text).not.toMatch(/safe/i);

    // The empty Open view says what silence means.
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [], next_before: null });
    fireEvent.click(screen.getByRole("button", { name: "All" }));
    expect(
      await screen.findByText(
        "No suspicious mail found. Crawler checks new mail every few minutes and tells you only when it finds warning signs; that never means an email is safe.",
      ),
    ).toBeInTheDocument();
    expect(vi.mocked(listMailAlerts)).toHaveBeenLastCalledWith({ view: "all" });
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "true");
  });

  it("says plainly when automatic mail checks are off and still lists past alerts", async () => {
    const whenOff =
      "Automatic scam checks on new email are turned off. The owner can turn on 'Check new email for scams' in Settings → Permissions.";
    vi.mocked(getMailScanStatus).mockResolvedValue(status({ enabled: false, when_off: whenOff }));
    renderTab();

    expect(await screen.findByText(whenOff)).toHaveAttribute("role", "status");
    expect(screen.queryByText("Automatic scam checks: on.")).not.toBeInTheDocument();
    const row = await findRow(SCAM.subject);
    expect(within(row).getByRole("button", { name: "Move to Spam" })).toBeEnabled();
    expect(within(row).getByRole("button", { name: "Not a scam…" })).toBeEnabled();
  });

  it("points to Connectors when no Gmail or Outlook account is connected", async () => {
    vi.mocked(getMailScanStatus).mockResolvedValue(status({ accounts: [] }));
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [], next_before: null });
    renderTab();

    const link = await screen.findByRole("link", { name: "Connectors" });
    expect(link).toHaveAttribute("href", "/connectors");
    expect(link.parentElement).toHaveTextContent("Connect Gmail or Outlook in Connectors to have new mail checked.");
    expect(screen.queryByRole("list", { name: "Checked mailboxes" })).not.toBeInTheDocument();
  });

  it("shows each mailbox's status and pauses or resumes it with paused true or false", async () => {
    vi.mocked(getMailScanStatus).mockResolvedValue(
      status({
        accounts: [
          account({}),
          account({
            connector_id: "c2",
            account: "Work Outlook",
            provider: "outlook",
            status: "error",
            last_error: "The Microsoft sign-in needs to be renewed in Connectors.",
            last_checked_at: minutesAgo(180),
          }),
          account({ connector_id: "c3", account: "New Gmail", status: "starting", last_checked_at: null, checked_count: 0, flagged_count: 0 }),
          account({
            connector_id: "c4",
            account: "Shared Gmail",
            status: "no_access",
            note: "Reconnect it with mail reading allowed.",
            skipped_count: 4,
          }),
        ],
      }),
    );
    vi.mocked(setMailScanPaused)
      .mockResolvedValueOnce(account({ status: "paused" }))
      .mockResolvedValueOnce(account({ connector_id: "c2", account: "Work Outlook", provider: "outlook", status: "active" }));
    renderTab();

    const list = await screen.findByRole("list", { name: "Checked mailboxes" });
    const [school, work, fresh, shared] = within(list).getAllByRole("listitem");
    expect(school).toHaveTextContent("School Gmail · Checking new mail");
    expect(school).toHaveTextContent("checked 128 · flagged 6 · last check 2 min ago");
    expect(work).toHaveTextContent("Work Outlook · Stopped after repeated errors");
    expect(work).toHaveTextContent("The Microsoft sign-in needs to be renewed in Connectors.");
    expect(work).toHaveTextContent("last check 3 h ago");
    expect(fresh).toHaveTextContent("New Gmail · First check soon");
    expect(fresh).toHaveTextContent("checked 0 · flagged 0 · not checked yet");
    expect(shared).toHaveTextContent("Shared Gmail · Reading mail isn't allowed on this account");
    expect(shared).toHaveTextContent("skipped 4");
    expect(shared).toHaveTextContent("Reconnect it with mail reading allowed.");

    fireEvent.click(within(school).getByRole("button", { name: "Pause scam checks for School Gmail" }));
    await waitFor(() => expect(school).toHaveTextContent("School Gmail · Paused"));
    expect(within(school).getByRole("button", { name: "Resume scam checks for School Gmail" })).toBeInTheDocument();

    fireEvent.click(within(work).getByRole("button", { name: "Resume scam checks for Work Outlook" }));
    await waitFor(() => expect(work).toHaveTextContent("Work Outlook · Checking new mail"));
    expect(vi.mocked(setMailScanPaused).mock.calls).toEqual([
      ["c1", true],
      ["c2", false],
    ]);
  });

  it("Move to Spam makes a card, then Approve sends the decision for that card", async () => {
    vi.mocked(requestMailAlertAction).mockResolvedValue({ card: pendingCard() });
    vi.mocked(decideApproval).mockResolvedValue({ action_id: "act-1", approved: true });
    renderTab();

    const row = await findRow(SCAM.subject);
    fireEvent.click(within(row).getByRole("button", { name: "Move to Spam" }));
    const card = await within(row).findByRole("group", { name: "Move to Spam: waiting (expires in 23 h)" });
    expect(vi.mocked(requestMailAlertAction).mock.calls).toEqual([["a1", "move_to_spam"]]);
    // While its card waits, the button that makes one is gone.
    expect(within(row).queryByRole("button", { name: "Move to Spam" })).not.toBeInTheDocument();

    vi.mocked(listMailAlerts).mockResolvedValue({
      alerts: [alertOf({ cards: [pendingCard({ status: "approved" })] })],
      next_before: null,
    });
    fireEvent.click(within(card).getByRole("button", { name: "Approve" }));

    expect(await screen.findByText("Move to Spam: approved")).toBeInTheDocument();
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["act-1", true]]);
    expect(vi.mocked(listMailAlerts).mock.calls).toEqual([[{ view: "open" }], [{ view: "open" }]]);
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    // An approved card does not say the move worked (it may still fail when it runs), so while the
    // server still offers the action the row offers it again.
    expect(screen.getByRole("button", { name: "Move to Spam" })).toBeInTheDocument();
  });

  it("Deny sends a refusal for that card, and a failed decision is shown beside the alert", async () => {
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [alertOf({ cards: [pendingCard()] })], next_before: null });
    vi.mocked(decideApproval).mockRejectedValueOnce(new ApiError("This approval has expired.", 404));
    renderTab();

    const row = await findRow(SCAM.subject);
    fireEvent.click(within(row).getByRole("button", { name: "Deny" }));
    expect(await within(row).findByRole("alert")).toHaveTextContent("This approval has expired.");
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["act-1", false]]);
    // A failed decision changes nothing, so nothing reloads.
    expect(listMailAlerts).toHaveBeenCalledTimes(1);
  });

  it("a 409 or 422 from an action shows the server's reason beside the alert and keeps it", async () => {
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [SCAM, INVOICE], next_before: null });
    vi.mocked(requestMailAlertAction)
      .mockRejectedValueOnce(new ApiError("A card for this is already waiting.", 409))
      .mockRejectedValueOnce(
        new ApiError("Reconnect Outlook in Connectors with mail changes allowed to move mail to Junk.", 422),
      );
    renderTab();

    const scam = await findRow(SCAM.subject);
    fireEvent.click(within(scam).getByRole("button", { name: "Move to Spam" }));
    expect(await within(scam).findByRole("alert")).toHaveTextContent("A card for this is already waiting.");
    expect(within(scam).getByRole("button", { name: "Move to Spam" })).toBeEnabled();

    const invoice = await findRow(INVOICE.subject);
    fireEvent.click(within(invoice).getByRole("button", { name: "Move to Junk" }));
    expect(await within(invoice).findByRole("alert")).toHaveTextContent(
      "Reconnect Outlook in Connectors with mail changes allowed to move mail to Junk.",
    );
    // Both rows stay, each with its own reason.
    expect(screen.getAllByRole("article")).toHaveLength(2);
    expect(within(scam).getByRole("alert")).toHaveTextContent("A card for this is already waiting.");
  });

  it("never offers Block sender, which the owner deferred, even if the server lists it", async () => {
    const withBlock = alertOf({
      actions: ["move_to_spam", "block_sender"] as unknown as MailActionKind[],
      action_hint: "Block sender is not offered for this sender.",
    });
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [withBlock], next_before: null });
    renderTab();

    const row = await findRow(SCAM.subject);
    expect(within(row).getAllByRole("button").map((b) => b.textContent)).toEqual(["Move to Spam", "Not a scam…"]);
    expect(screen.queryByRole("button", { name: /block/i })).not.toBeInTheDocument();
    expect(within(row).getByText("Block sender is not offered for this sender.")).toBeInTheDocument();
  });

  it("Not a scam asks first and the alert leaves the open view", async () => {
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [SCAM, INVOICE], next_before: null });
    vi.mocked(dismissMailAlert).mockResolvedValue({ ok: true, status: "dismissed" });
    renderTab();

    const scam = await findRow(SCAM.subject);
    fireEvent.click(within(scam).getByRole("button", { name: "Not a scam…" }));
    const dialog = screen.getByRole("dialog", { name: "Mark this email as not a scam?" });
    expect(dialog).toHaveTextContent("leaves the open list (it stays under All). Nothing in your mailbox changes.");
    expect(dismissMailAlert).not.toHaveBeenCalled();

    // Cancel first: nothing is sent and the alert stays.
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(dismissMailAlert).not.toHaveBeenCalled();

    fireEvent.click(within(scam).getByRole("button", { name: "Not a scam…" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Not a scam" }));
    await waitFor(() => expect(screen.getAllByRole("article")).toHaveLength(1));
    expect(screen.queryByText(SCAM.subject)).not.toBeInTheDocument();
    expect(screen.getByText(INVOICE.subject)).toBeInTheDocument();
    expect(vi.mocked(dismissMailAlert).mock.calls).toEqual([["a1"]]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("in the All view a dismissed alert stays, marked Dismissed", async () => {
    vi.mocked(dismissMailAlert).mockResolvedValue({ ok: true, status: "dismissed" });
    renderTab();

    await findRow(SCAM.subject);
    fireEvent.click(screen.getByRole("button", { name: "All" }));
    const row = await findRow(SCAM.subject);
    fireEvent.click(within(row).getByRole("button", { name: "Not a scam…" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Not a scam" }));

    const dismissed = await screen.findByRole("article", { name: `Dismissed: ${SCAM.subject}` });
    expect(within(dismissed).queryByRole("button", { name: "Not a scam…" })).not.toBeInTheDocument();
  });

  it("shows today's AI reviews against the daily limit and the owner's install counts only to the owner", async () => {
    const withInstall = status({ install: { accounts: 7, alerts_7d: 12, reviews_today: 9 } });
    vi.mocked(getMailScanStatus).mockResolvedValue(withInstall);
    const member = renderTab(false);

    expect(await screen.findByText("AI reviews today: 3 of 20")).toBeInTheDocument();
    expect(screen.getByText("Automatic scam checks: on.")).toBeInTheDocument();
    expect(screen.getByText("Links checked on this computer and with Google Safe Browsing.")).toBeInTheDocument();
    expect(screen.getByText("Attachments: not checked with VirusTotal (no key).")).toBeInTheDocument();
    expect(screen.queryByText(/On this Crawler/)).not.toBeInTheDocument();
    member.unmount();

    renderTab(true);
    expect(
      await screen.findByText(
        "On this Crawler: 7 mailboxes checked · 12 alerts in the last 7 days · 9 AI reviews today",
      ),
    ).toBeInTheDocument();
  });

  it("says when an alert could not be sent to Telegram or Slack", async () => {
    const unsent = alertOf({ id: "a5", subject: "Gift card request", delivered: false, alert_note: "not delivered" });
    const held = alertOf({
      id: "a6",
      verdict: "suspicious",
      subject: "Shipping problem",
      delivered: false,
      alert_note: "held: too many alerts this hour",
    });
    vi.mocked(listMailAlerts).mockResolvedValue({ alerts: [SCAM, unsent, held], next_before: null });
    renderTab();

    expect(
      within(await findRow("Gift card request")).getByText(
        "Not sent to Telegram or Slack: no linked Telegram or Slack chat took it.",
      ),
    ).toBeInTheDocument();
    expect(
      within(await findRow("Shipping problem")).getByText(
        "Not sent to Telegram or Slack: held back, because there were too many alerts this hour.",
      ),
    ).toBeInTheDocument();
    expect(within(await findRow(SCAM.subject)).queryByText(/Not sent to Telegram or Slack/)).not.toBeInTheDocument();
  });

  it("loads older alerts with Load older alerts", async () => {
    const older = alertOf({ id: "a9", subject: "Old phishing attempt", detected_at: "2026-10-12T08:00:00Z" });
    vi.mocked(listMailAlerts)
      .mockResolvedValueOnce({ alerts: [SCAM], next_before: "2026-10-13T00:00:00Z" })
      .mockResolvedValueOnce({ alerts: [older], next_before: null });
    renderTab();

    await findRow(SCAM.subject);
    fireEvent.click(screen.getByRole("button", { name: "Load older alerts" }));
    await findRow("Old phishing attempt");
    expect(screen.getAllByRole("article")).toHaveLength(2);
    expect(vi.mocked(listMailAlerts).mock.calls).toEqual([
      [{ view: "open" }],
      [{ view: "open", before: "2026-10-13T00:00:00Z" }],
    ]);
    expect(screen.queryByRole("button", { name: "Load older alerts" })).not.toBeInTheDocument();
  });

  it("can retry a failed load", async () => {
    vi.mocked(getMailScanStatus).mockRejectedValueOnce(new Error(""));
    renderTab();

    expect(await screen.findByRole("alert")).toHaveTextContent("Mail alerts could not be loaded.");
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await findRow(SCAM.subject);
    expect(screen.queryByText("Mail alerts could not be loaded.")).not.toBeInTheDocument();
    expect(getMailScanStatus).toHaveBeenCalledTimes(2);
    expect(listMailAlerts).toHaveBeenCalledTimes(2);
  });
});
