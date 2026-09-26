/**
 * Tests for the weekly button on Chat's approval cards: a desktop.act card the server offers for a
 * week gets "Allow Calendar for 7 days" under Approve / Deny, whether it came with the streamed
 * turn or from the approvals list; pressing it approves with remember "week", removes the card as
 * Approve does and says until when the app is allowed; a failure keeps the card with the reason;
 * and a card without `weekly_app` has no third button while its Approve posts what it always did.
 *
 * Why it exists: Reading one day in Calendar took six cards and six full-context model calls
 * (spec 2026-09-25-weekly-app-approvals). The button is the web's way out of that, and only a
 * press on it may allow an app for a week: never a plain Approve, never a card it was not offered on.
 */

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  updateConversation: vi.fn(),
}));

import Chat from "@/pages/Chat";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import {
  decideApproval,
  getConversation,
  getConversations,
  getMe,
  getPendingApprovals,
  streamMessage,
  type StreamHandlers,
} from "@/services/api";

const ASK = "What am I doing on the 15th?";
const UNTIL = "2026-10-02T15:14:00Z";
const ALLOW = "Allow Calendar for 7 days";
const HELPER =
  "Crawler then acts in Calendar without asking, for requests from this browser, for 7 days. Revoke in Settings.";

const ME = {
  id: "u1",
  email: "owner@example.com",
  name: "Owner",
  created_at: "2026-09-25T12:00:00Z",
  default_permission_tier: "user_confirm",
  rate_limit: 30,
} as unknown as User;

const CONV: Conversation = {
  id: "c1",
  user_id: "u1",
  title: "My month",
  created_at: "2026-09-25T12:00:00Z",
  updated_at: "2026-09-25T12:00:00Z",
};

const REPLY_ROW: Message = {
  id: "m2",
  conversation_id: "c1",
  role: "assistant",
  content: "Approve the card and I will open the month view.",
  created_at: "2026-09-25T12:00:05Z",
};

// A desktop.act card as the backend parks it: the screen it was made from under `_screen`, and
// the app it can be allowed in for a week.
const CALENDAR: PendingApproval = {
  action_id: "a7",
  tool_name: "desktop.act",
  reason: 'Click "Month" in Calendar',
  arguments: { action: "click", ref: "e12", _screen: { app: "Calendar", outline: "4be1c2" } },
  expires_at: "2099-01-01T00:00:00Z",
  conversation_id: "c1",
  weekly_app: "Calendar",
};

/** Sends the ask and hands back the open stream's handlers; onSaved ends the turn. */
async function startTurn(): Promise<StreamHandlers> {
  let handlers: StreamHandlers | undefined;
  let finish: () => void = () => {};
  vi.mocked(streamMessage).mockImplementation((_conv, _content, h) => {
    handlers = h;
    return new Promise<void>((resolve) => {
      finish = resolve;
    });
  });
  render(<Chat />);
  const box = await screen.findByRole("textbox", { name: "Message" });
  await waitFor(() => expect(box).not.toBeDisabled());
  fireEvent.change(box, { target: { value: ASK } });
  fireEvent.keyDown(box, { key: "Enter" });
  await waitFor(() => expect(handlers).toBeDefined());
  const open = handlers as StreamHandlers;
  return {
    ...open,
    onSaved: (saved) => {
      open.onSaved?.(saved);
      finish();
    },
  };
}

describe("Chat's weekly button on an approval card", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
    vi.mocked(getMe).mockResolvedValue(ME);
    vi.mocked(getConversations).mockResolvedValue([CONV]);
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [] });
  });

  it("offers a streamed card's app for a week and, pressed, allows it and removes the card", async () => {
    const turn = await startTurn();
    await act(async () => {
      turn.onPendingApproval?.(CALENDAR);
      turn.onContentDelta?.(REPLY_ROW.content);
      turn.onDone?.({ content: REPLY_ROW.content, tool_calls: [] });
      turn.onSaved?.(REPLY_ROW);
    });

    const allow = await screen.findByRole("button", { name: ALLOW });
    expect(screen.getByText(HELPER)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deny" })).toBeInTheDocument();

    vi.mocked(decideApproval).mockResolvedValue({
      action_id: "a7",
      approved: true,
      result: { ok: true },
      weekly: { app: "Calendar", expires_at: UNTIL },
    });
    fireEvent.click(allow);

    expect(
      await screen.findByText(`Calendar is allowed until ${formatAllowedUntil(UNTIL)}.`),
    ).toBeInTheDocument();
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["a7", true, "week"]]);
    expect(screen.queryByRole("button", { name: ALLOW })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
  });

  it("keeps the card with the server's reason when allowing fails", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([CALENDAR]);
    vi.mocked(decideApproval).mockRejectedValue(new Error("Approval request not found or expired"));
    render(<Chat />);

    fireEvent.click(await screen.findByRole("button", { name: ALLOW }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Approval request not found or expired");
    await waitFor(() => expect(screen.getByRole("button", { name: ALLOW })).toBeEnabled());
    expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled();
    expect(screen.queryByText(/is allowed until/)).not.toBeInTheDocument();
  });

  it("gives a card without weekly_app no third button, and its Approve posts what it always did", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([{ ...CALENDAR, action_id: "a8", weekly_app: null }]);
    vi.mocked(decideApproval).mockResolvedValue({ action_id: "a8", approved: true, weekly: null });
    render(<Chat />);

    const approve = await screen.findByRole("button", { name: "Approve" });
    expect(screen.queryByRole("button", { name: /for 7 days/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/without asking/)).not.toBeInTheDocument();

    fireEvent.click(approve);

    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument(),
    );
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["a8", true]]);
    expect(screen.queryByText(/is allowed until/)).not.toBeInTheDocument();
  });
});
