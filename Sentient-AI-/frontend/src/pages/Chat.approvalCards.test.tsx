/**
 * Tests for the chat's approval cards on the way to a purchase: a browser.act card is the one
 * sentence the backend built from facts (no tool line, no JSON, none of the typed text) with the
 * picture of the page it will run on, and approving a purchase shows the confirmation screenshot that comes back with the decision under
 * the row that records it.
 *
 * Why it exists: The owner approves several browser.act cards before any checkout; a card that
 * read `{"action": "fill", "ref": "e7", "text": …}` under "Tool browser.act wants to run" told
 * them nothing a person reads, and after Approve the confirmation page never reached the chat
 * (the transcript keeps only a placeholder), so the model's "here is the confirmation" pointed at
 * nothing.
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
import { PURCHASE_NOTICE } from "@/pages/purchaseNotice";
import {
  decideApproval,
  getConversation,
  getConversations,
  getMe,
  streamMessage,
  type StreamHandlers,
} from "@/services/api";

const PLACEHOLDER = "[image captured and delivered to the user separately]";
const SHOT = `data:image/jpeg;base64,${"/9j/".repeat(40)}`;
const ASK = "Buy a $5 ticket on shop.example.com";

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
  title: "Tickets",
  created_at: "2026-09-25T12:00:00Z",
  updated_at: "2026-09-25T12:00:00Z",
};

const USER_ROW: Message = {
  id: "m1",
  conversation_id: "c1",
  role: "user",
  content: ASK,
  created_at: "2026-09-25T12:00:00Z",
};

const REPLY_ROW: Message = {
  id: "m2",
  conversation_id: "c1",
  role: "assistant",
  content: "The checkout page is open; approve the card to pay.",
  created_at: "2026-09-25T12:00:05Z",
};

/** The row the server writes for an approved checkout: the placeholder, never the picture. */
const DECISION_ROW: Message = {
  id: "m3",
  conversation_id: "c1",
  role: "assistant",
  content: "[Approved] Executed 'browser.checkout'.\n\nResult:\n{...}",
  tool_calls: [
    {
      name: "browser.checkout",
      result: {
        ok: true,
        merchant: "shop.example.com",
        amount: "5.00",
        currency: "USD",
        confirmation_text_summary: "Thank you Order number 8841",
        user_image: PLACEHOLDER,
      },
    },
  ],
  created_at: "2026-09-25T12:01:00Z",
};

// The shapes the backend produces (browser.act's `_page`, browser.checkout's `_checkout`).
const ACT: PendingApproval = {
  action_id: "a0",
  tool_name: "browser.act",
  reason: 'Type 17 characters into "Email" on shop.example.com',
  arguments: {
    action: "fill",
    ref: "e7",
    text: "krish@example.com",
    _page: { origin: "https://shop.example.com", outline: "9f2c1a" },
  },
  expires_at: "2099-01-01T00:00:00Z",
  conversation_id: "c1",
};

const CHECKOUT: PendingApproval = {
  action_id: "a1",
  tool_name: "browser.checkout",
  reason: "Pay $5.00 to shop.example.com (1 item) with Visa ····4242",
  arguments: {
    merchant: "shop.example.com",
    amount: "5.00",
    _checkout: {
      checkout_id: "ck1",
      origin: "https://shop.example.com",
      host: "shop.example.com",
      amount_usd: "5.00",
      currency: "USD",
      items: ["General admission — $5.00"],
      card_label: "Visa ····4242",
      outline: "9f2c1a",
      notice: PURCHASE_NOTICE,
    },
  },
  expires_at: "2099-01-01T00:00:00Z",
  conversation_id: "c1",
};

/** Sends the ask and hands back the open stream's handlers. */
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

async function parkCards(...cards: PendingApproval[]) {
  const turn = await startTurn();
  await act(async () => {
    for (const card of cards) turn.onPendingApproval?.(card);
    turn.onContentDelta?.(REPLY_ROW.content);
    turn.onDone?.({ content: REPLY_ROW.content, tool_calls: [] });
    turn.onSaved?.(REPLY_ROW);
  });
}

describe("Approval cards on the way to a purchase", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
    vi.mocked(getMe).mockResolvedValue(ME);
    vi.mocked(getConversations).mockResolvedValue([CONV]);
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [] });
  });

  it("shows a browser.act card as its one sentence: no tool line, no JSON, no typed text", async () => {
    await parkCards(ACT);
    expect(await screen.findByText(ACT.reason)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(document.querySelector("pre")).toBeNull();
    expect(screen.queryByText(/wants to run/)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("krish@example.com");
    expect(document.body.textContent).not.toContain('"ref"');
    expect(screen.queryByText("Risk warning")).not.toBeInTheDocument();
  });

  it("shows a browser.act card with the picture of the page it will run on", async () => {
    const warned: PendingApproval = {
      ...ACT,
      reason:
        'Click "Continue" on shop.example.com. This page shows $499.00 and a saved payment method. ' +
        "This step may place an order. Crawler normally pays only through its checkout step.",
      image: SHOT,
    };
    await parkCards(warned);
    expect(await screen.findByText(warned.reason)).toBeInTheDocument();
    const img = screen.getByRole("img", {
      name: "The page this step will run on, with its target outlined in red",
    });
    expect(img).toHaveAttribute("src", SHOT);
  });

  it("draws no picture for a browser.act card whose image is not a raster data URL", async () => {
    // Only a raster data URL is drawn: anything else is dropped, not fetched.
    await parkCards({ ...ACT, image: "https://evil.example/pixel.svg" });
    expect(await screen.findByText(ACT.reason)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("shows the confirmation screenshot that comes with an approved purchase", async () => {
    await parkCards(CHECKOUT);
    expect(await screen.findByText(PURCHASE_NOTICE)).toBeInTheDocument();

    vi.mocked(decideApproval).mockResolvedValue({
      action_id: "a1",
      approved: true,
      images: [{ tool: "browser.checkout", source: "shop.example.com", index: 0, data_url: SHOT }],
      message_id: "m3",
    });
    vi.mocked(getConversation).mockResolvedValue({
      ...CONV,
      messages: [USER_ROW, REPLY_ROW, DECISION_ROW],
    });
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decideApproval).toHaveBeenCalledWith("a1", true));

    const img = await screen.findByRole("img", {
      name: "Screenshot of shop.example.com (browser.checkout)",
    });
    expect(img).toHaveAttribute("src", SHOT);
    expect(screen.queryByText(/Screenshot not kept/)).not.toBeInTheDocument();
    // The picture is on the decision row and nowhere else; the JSON of the
    // result is not printed under it.
    expect(document.body.textContent).not.toContain(PLACEHOLDER);
  });
});
