/**
 * Tests for the chat's plain words: an approval card reads its sentence, every value as a labelled
 * row, "Okay to go ahead?" with the time left, the buttons and the quiet check code, with the tool
 * id and raw arguments only under a closed "Technical details"; the live status line, the step
 * chips and the skipped-step lines never name a tool.
 *
 * Why it exists: the chat used to show "Tool google_workspace.send_email wants to run" over a JSON
 * dump, "Running web.search…" while it worked and "desktop.act › Blocked: ..." for a skipped step.
 * The owner is not a developer (docs/bot-message-style.md); every value they approve must still
 * be on the card, whole (spec F3).
 */

import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Conversation, Message, PendingApproval, User } from "@/types";

vi.mock("@/services/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/services/api")>()),
  createConversation: vi.fn(),
  decideApproval: vi.fn(),
  deleteConversation: vi.fn(),
  getConversation: vi.fn(),
  getConversations: vi.fn(),
  getMe: vi.fn(),
  getPendingApprovals: vi.fn(async () => []),
  stopAgent: vi.fn(),
  streamMessage: vi.fn(),
  uploadFile: vi.fn(),
  deleteFile: vi.fn(),
  updateConversation: vi.fn(),
}));

import Chat from "@/pages/Chat";
import { getConversation, getConversations, getMe, streamMessage, type StreamHandlers } from "@/services/api";

const ASK = "Email Priya about lunch";
const BODY = "Hi Priya,\nare we still on for noon?";

const ME = {
  id: "u1",
  email: "owner@example.com",
  name: "Owner",
  created_at: "2026-09-25T12:00:00Z",
  default_permission_tier: "approval",
  rate_limit: 30,
} as unknown as User;

const CONV: Conversation = {
  id: "c1",
  user_id: "u1",
  title: "Lunch",
  created_at: "2026-09-25T12:00:00Z",
  updated_at: "2026-09-25T12:00:00Z",
};

const REPLY_ROW: Message = {
  id: "m2",
  conversation_id: "c1",
  role: "assistant",
  content: "I need your OK before I send it.",
  created_at: "2026-09-25T12:00:05Z",
};

// The card as the server streams it: sentence, labelled details and check code.
const EMAIL: PendingApproval = {
  action_id: "a1",
  tool_name: "google_workspace.send_email",
  reason: "Send an email to priya@acme.com from your Gmail",
  arguments: { to: "priya@acme.com", subject: "Friday lunch", body: BODY },
  details: [
    { label: "To", value: "priya@acme.com" },
    { label: "Subject", value: "Friday lunch" },
    { label: "Message", value: BODY },
  ],
  check_code: "6d3b dfca 7bf8 cfc5",
  expires_at: new Date(Date.now() + 14 * 60_000 + 30_000).toISOString(),
  conversation_id: "c1",
};

/** Sends the ask and hands back the open stream's handlers. */
async function startTurn(): Promise<StreamHandlers> {
  let handlers: StreamHandlers | undefined;
  vi.mocked(streamMessage).mockImplementation((_conv, _content, h) => {
    handlers = h;
    return new Promise<void>(() => {});
  });
  render(<Chat />);
  const box = await screen.findByRole("textbox", { name: "Message" });
  await waitFor(() => expect(box).not.toBeDisabled());
  fireEvent.change(box, { target: { value: ASK } });
  fireEvent.keyDown(box, { key: "Enter" });
  await waitFor(() => expect(handlers).toBeDefined());
  return handlers as StreamHandlers;
}

/** The page's text with every closed "Technical details" disclosure left out. */
function visibleText(): string {
  const copy = document.body.cloneNode(true) as HTMLElement;
  copy.querySelectorAll("details").forEach((el) => el.remove());
  return copy.textContent ?? "";
}

describe("The chat's plain words", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
    vi.mocked(getMe).mockResolvedValue(ME);
    vi.mocked(getConversations).mockResolvedValue([CONV]);
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [] });
  });

  it("shows an approval card as its sentence, labelled values, question and check code", async () => {
    const turn = await startTurn();
    await act(async () => {
      turn.onPendingApproval?.(EMAIL);
      turn.onContentDelta?.(REPLY_ROW.content);
      turn.onDone?.({ content: REPLY_ROW.content, tool_calls: [] });
    });

    expect(await screen.findByText(EMAIL.reason)).toBeInTheDocument();
    const card = screen.getByText(EMAIL.reason).parentElement as HTMLElement;
    expect(within(card).getByText("To")).toBeInTheDocument();
    expect(within(card).getByText("priya@acme.com")).toBeInTheDocument();
    expect(within(card).getByText("Subject")).toBeInTheDocument();
    expect(within(card).getByText((_, el) => el?.tagName === "DD" && el.textContent === BODY)).toBeInTheDocument();
    expect(within(card).getByText(/Okay to go ahead\?/).textContent).toBe(
      "Okay to go ahead? This expires in 14 minutes.",
    );
    expect(within(card).getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "Deny" })).toBeInTheDocument();
    expect(within(card).getByText(/Check code/).textContent).toBe("Check code 6d3b dfca 7bf8 cfc5");

    // The tool id and the JSON are one click away, never on the card itself.
    const technical = within(card).getByText("Technical details").closest("details") as HTMLDetailsElement;
    expect(technical.open).toBe(false);
    expect(within(technical).getByText("google_workspace.send_email")).toBeInTheDocument();
    expect(visibleText()).not.toContain("google_workspace");
    expect(visibleText()).not.toContain('"to"');
    expect(screen.queryByText(/wants to run/)).not.toBeInTheDocument();
  });

  it("puts the server's caution above the question, in calm words", async () => {
    const note = "This came from a web page you didn't write. Check the address before you approve.";
    const turn = await startTurn();
    await act(async () => {
      turn.onPendingApproval?.({ ...EMAIL, risk_note: note });
    });

    expect(await screen.findByText("Check this first")).toBeInTheDocument();
    const caution = screen.getByText(note);
    const ask = screen.getByText(/Okay to go ahead\?/);
    expect(caution.compareDocumentPosition(ask) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryByText(/warning/i)).not.toBeInTheDocument();
  });

  it("labels the values itself when an older server streams a card without details", async () => {
    const turn = await startTurn();
    await act(async () => {
      turn.onPendingApproval?.({ ...EMAIL, details: undefined, check_code: undefined });
    });

    expect(await screen.findByText(EMAIL.reason)).toBeInTheDocument();
    expect(screen.getByText("To")).toBeInTheDocument();
    expect(screen.getByText("Body")).toBeInTheDocument();
    expect(screen.queryByText(/Check code/)).not.toBeInTheDocument();
    expect(visibleText()).not.toMatch(/[{}]/);
  });

  it("says what it is doing in plain words, never the tool id", async () => {
    const turn = await startTurn();
    await act(async () => {
      turn.onToolCall?.("web.search", "Searching the web…");
    });
    expect(screen.getByRole("status")).toHaveTextContent("Searching the web…");

    await act(async () => {
      turn.onToolResult?.("web.search");
    });
    expect(screen.getByRole("status")).toHaveTextContent("Working on it…");

    // A step without its own line, or an older server, gets the plain stand-in.
    await act(async () => {
      turn.onToolCall?.("web.fetch_page");
    });
    expect(screen.getByRole("status")).toHaveTextContent("Working on it…");
    expect(screen.getByRole("status").textContent).not.toMatch(/web\.|Running|Finished/);
  });

  it("names a finished step plainly and a skipped step by what it would have done", async () => {
    const turn = await startTurn();
    const blocked = [
      {
        tool_name: "google_workspace.send_email",
        reason: "Your safety settings don't allow this.",
        policy: "p",
        phrase: "send an email",
      },
      // An older server sends no phrase.
      { tool_name: "desktop.act", reason: "", policy: "p" },
    ];
    await act(async () => {
      for (const ba of blocked) turn.onBlocked?.(ba);
      turn.onContentDelta?.("Here is what I found.");
      turn.onDone?.({
        content: "Here is what I found.",
        tool_calls: [{ name: "web.search", result: { ok: true, results: [] } }],
        blocked_actions: blocked,
      });
    });

    expect(await screen.findByText("Used the web")).toBeInTheDocument();
    expect(screen.getByText("I didn't send an email.").parentElement).toHaveTextContent(
      "I didn't send an email. Your safety settings don't allow this.",
    );
    expect(screen.getByText("I skipped a step.")).toBeInTheDocument();
    expect(visibleText()).not.toMatch(/web\.search|desktop\.act|google_workspace|Blocked:/);
    // The raw result is still there for anyone who opens the step's technical details.
    expect(document.body.textContent).toContain('"results": []');
  });
});
