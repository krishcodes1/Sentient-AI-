/**
 * Tests for the low-risk button on Chat's approval cards: a card the server offers a low-risk
 * grant for gets "Allow low-risk changes on <account> for 7 days" under Approve / Deny, whether it
 * came with the streamed turn or from the approvals list; pressing it approves with remember
 * "low_risk", removes the card as Approve does and says until when the account is allowed; a
 * decision that made no grant shows no note; and a card without `low_risk_account` has no third
 * button while its Approve posts what it always did.
 *
 * Why it exists: only a press on this button may let an account's changes run without asking for
 * a week: never a plain Approve, never a card the server did not offer it on.
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
  listPermissionGrants: vi.fn(async () => []),
  revokePermissionGrant: vi.fn(),
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

const ASK = "Star the email from my TA";
const UNTIL = "2026-10-07T15:14:00Z";
const ALLOW = "Allow low-risk changes on School Gmail for 7 days";

const ME = {
  id: "u1",
  email: "owner@example.com",
  name: "Owner",
  created_at: "2026-09-30T12:00:00Z",
  default_permission_tier: "user_confirm",
  rate_limit: 30,
} as unknown as User;

const CONV: Conversation = {
  id: "c1",
  user_id: "u1",
  title: "Inbox",
  created_at: "2026-09-30T12:00:00Z",
  updated_at: "2026-09-30T12:00:00Z",
};

const REPLY_ROW: Message = {
  id: "m2",
  conversation_id: "c1",
  role: "assistant",
  content: "Approve the card and I will star it.",
  created_at: "2026-09-30T12:00:05Z",
};

const STAR: PendingApproval = {
  action_id: "a9",
  tool_name: "google_workspace.modify_labels",
  reason: "Tool 'google_workspace.modify_labels' requires explicit user approval",
  arguments: { message_id: "m1", add_label_ids: ["STARRED"] },
  expires_at: "2099-01-01T00:00:00Z",
  conversation_id: "c1",
  low_risk_account: "School Gmail",
};

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

describe("Chat's low-risk button on an approval card", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
    vi.mocked(getMe).mockResolvedValue(ME);
    vi.mocked(getConversations).mockResolvedValue([CONV]);
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [] });
  });

  it("offers a streamed card's account and, pressed, allows it and removes the card", async () => {
    const turn = await startTurn();
    await act(async () => {
      turn.onPendingApproval?.(STAR);
      turn.onContentDelta?.(REPLY_ROW.content);
      turn.onDone?.({ content: REPLY_ROW.content, tool_calls: [] });
      turn.onSaved?.(REPLY_ROW);
    });

    const allow = await screen.findByRole("button", { name: ALLOW });
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Allow .* for 7 days/, hidden: false })).toBe(allow);

    vi.mocked(decideApproval).mockResolvedValue({
      action_id: "a9",
      approved: true,
      result: { ok: true },
      low_risk: { account: "School Gmail", expires_at: UNTIL },
    });
    fireEvent.click(allow);

    expect(
      await screen.findByText(
        `Low-risk changes on School Gmail are allowed until ${formatAllowedUntil(UNTIL)}.`,
      ),
    ).toBeInTheDocument();
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["a9", true, "low_risk"]]);
    expect(screen.queryByRole("button", { name: ALLOW })).not.toBeInTheDocument();
  });

  it("shows no note when the server approved the card once without a grant", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([STAR]);
    vi.mocked(decideApproval).mockResolvedValue({ action_id: "a9", approved: true, low_risk: null });
    render(<Chat />);

    fireEvent.click(await screen.findByRole("button", { name: ALLOW }));

    await waitFor(() => expect(screen.queryByRole("button", { name: ALLOW })).not.toBeInTheDocument());
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["a9", true, "low_risk"]]);
    expect(screen.queryByText(/are allowed until/)).not.toBeInTheDocument();
  });

  it("gives a card without low_risk_account no third button, and its Approve posts what it always did", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([{ ...STAR, action_id: "a10", low_risk_account: null }]);
    vi.mocked(decideApproval).mockResolvedValue({ action_id: "a10", approved: true });
    render(<Chat />);

    const approve = await screen.findByRole("button", { name: "Approve" });
    expect(screen.queryByRole("button", { name: /low-risk/ })).not.toBeInTheDocument();

    fireEvent.click(approve);

    await waitFor(() => expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument());
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["a10", true]]);
  });
});
