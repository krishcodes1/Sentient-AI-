/**
 * Tests for screenshots on the chat page: a screenshot a tool took this turn shows as an image
 * under its tool call, it stays when the saved reply replaces the streamed one and when an approval
 * refetches the thread, a reloaded thread shows the short "not kept" note instead of the result's
 * JSON, one past the per-reply limit says so, and an image that is not a base64 data URL is never
 * put in an <img>.
 *
 * Why it exists: The chat printed the flight screenshot as a JSON string. The server sends a
 * turn's screenshots to the live view once and saves only a placeholder, so the page has to show
 * the picture while it has it and say plainly when it does not.
 */

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Conversation, Message, PendingApproval, ToolCall, User } from "@/types";

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
import {
  decideApproval,
  getConversation,
  getConversations,
  getMe,
  streamMessage,
  type StreamHandlers,
} from "@/services/api";

const PLACEHOLDER = "[image captured and delivered to the user separately]";
const NOT_KEPT = "Screenshot not kept — ask again to see it";
const NOT_SHOWN = "Screenshot not shown";
const OVER_LIMIT = "Screenshot not shown (limit of 3 per reply)";
const SHOT = `data:image/png;base64,${"Zm9v".repeat(50)}`;
const ALT = "Screenshot of www.google.com (web.screenshot)";
const REPLY = "Here are the flights from JFK to LAX.";

const ME = {
  id: "u1",
  email: "student@example.com",
  name: "Student",
  created_at: "2026-09-25T12:00:00Z",
  default_permission_tier: "approval",
  rate_limit: 30,
} as unknown as User;

const CONV: Conversation = {
  id: "c1",
  user_id: "u1",
  title: "Flights",
  created_at: "2026-09-25T12:00:00Z",
  updated_at: "2026-09-25T12:00:00Z",
};

/** The tool calls as the server sends and saves them: the image replaced by the placeholder. */
const SAVED_CALLS: ToolCall[] = [
  { name: "web.search", result: { ok: true, results: [] }, tool_call_id: "c1" },
  {
    name: "web.screenshot",
    result: { ok: true, url: "https://www.google.com/travel/flights", format: "png", image: PLACEHOLDER },
    tool_call_id: "c2",
  },
];

const SAVED_REPLY: Message = {
  id: "m2",
  conversation_id: "c1",
  role: "assistant",
  content: REPLY,
  tool_calls: SAVED_CALLS,
  created_at: "2026-09-25T12:00:05Z",
};

const USER_ROW: Message = {
  id: "m1",
  conversation_id: "c1",
  role: "user",
  content: "find flights from JFK to LAX",
  created_at: "2026-09-25T12:00:00Z",
};

/** Sends one message and hands back the open stream's handlers. */
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
  fireEvent.change(box, { target: { value: "find flights from JFK to LAX" } });
  fireEvent.keyDown(box, { key: "Enter" });
  await waitFor(() => expect(handlers).toBeDefined());
  const open = handlers as StreamHandlers;
  // The server ends the stream once the reply is saved.
  return {
    ...open,
    onSaved: (saved) => {
      open.onSaved?.(saved);
      finish();
    },
  };
}

describe("Screenshots in the chat", () => {
  beforeEach(() => {
    // jsdom has no scrolling; the thread follows new messages with it.
    Element.prototype.scrollIntoView = vi.fn();
    vi.mocked(getMe).mockResolvedValue(ME);
    vi.mocked(getConversations).mockResolvedValue([CONV]);
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [] });
  });

  it("shows the turn's screenshot as an image under its tool call, and keeps it once saved", async () => {
    const turn = await startTurn();

    await act(async () => {
      turn.onContentDelta?.(REPLY);
      turn.onDone?.({
        content: REPLY,
        tool_calls: SAVED_CALLS,
        images: [{ tool: "web.screenshot", source: "www.google.com", index: 1, data_url: SHOT }],
      });
    });
    const image = await screen.findByRole("img", { name: ALT });
    expect(image).toHaveAttribute("src", SHOT);

    await act(async () => turn.onSaved?.(SAVED_REPLY));

    expect(screen.getByRole("img", { name: ALT })).toHaveAttribute("src", SHOT);
    expect(screen.getAllByRole("img")).toHaveLength(1);
    expect(screen.queryByText(NOT_KEPT)).not.toBeInTheDocument();
    expect(screen.queryByText(/image captured/)).not.toBeInTheDocument();
    // The other tool call still shows its result.
    expect(screen.getByText('{"ok":true,"results":[]}')).toBeInTheDocument();
  });

  it("shows the note, not the JSON, when a reloaded thread only has the placeholder", async () => {
    vi.mocked(getConversation).mockResolvedValue({
      ...CONV,
      messages: [USER_ROW, SAVED_REPLY],
    });
    render(<Chat />);

    expect(await screen.findByText(NOT_KEPT)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.queryByText(/image captured/)).not.toBeInTheDocument();
    expect(screen.getByText("web.screenshot")).toBeInTheDocument();
  });

  it.each([
    ["a remote URL", "https://tracker.example/pixel.png?id=42"],
    ["an SVG data URL", "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="],
  ])("never puts %s in an image", async (_label, url) => {
    const turn = await startTurn();

    await act(async () => {
      turn.onContentDelta?.(REPLY);
      turn.onDone?.({
        content: REPLY,
        tool_calls: SAVED_CALLS,
        images: [{ tool: "web.screenshot", source: "www.google.com", index: 1, data_url: url }],
      });
      turn.onSaved?.(SAVED_REPLY);
    });

    expect(await screen.findByText(NOT_SHOWN)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(document.querySelector(`img[src="${url}"]`)).toBeNull();
  });

  it("keeps the screenshot on screen when deciding an approval refetches the thread", async () => {
    const approval: PendingApproval = {
      action_id: "a1",
      tool_name: "browser.act",
      arguments: { action: "click", ref: "e3" },
      reason: "This tool requires your explicit approval before it runs.",
      expires_at: "2099-01-01T00:00:00Z",
      conversation_id: "c1",
    };
    const turn = await startTurn();

    await act(async () => {
      turn.onPendingApproval?.(approval);
      turn.onContentDelta?.(REPLY);
      turn.onDone?.({
        content: REPLY,
        tool_calls: SAVED_CALLS,
        images: [{ tool: "web.screenshot", source: "www.google.com", index: 1, data_url: SHOT }],
      });
      turn.onSaved?.(SAVED_REPLY);
    });
    expect(await screen.findByRole("img", { name: ALT })).toHaveAttribute("src", SHOT);

    // Deny the next action: the page refetches the thread, whose saved rows hold only the
    // placeholder.
    vi.mocked(decideApproval).mockResolvedValue({ action_id: "a1", approved: false });
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [USER_ROW, SAVED_REPLY] });
    fireEvent.click(await screen.findByRole("button", { name: "Deny" }));
    await waitFor(() => expect(getConversation).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Deny" })).not.toBeInTheDocument(),
    );

    expect(screen.getByRole("img", { name: ALT })).toHaveAttribute("src", SHOT);
    expect(screen.queryByText(NOT_KEPT)).not.toBeInTheDocument();
  });

  it("says a screenshot past the reply's limit was not shown, not to ask again", async () => {
    const calls: ToolCall[] = [0, 1, 2, 3].map((i) => ({
      name: "desktop.screenshot",
      result: { ok: true, app: "Google Chrome", image: PLACEHOLDER },
      tool_call_id: `d${i}`,
    }));
    const shots = [0, 1, 2].map((index) => ({
      tool: "desktop.screenshot",
      source: "Google Chrome",
      index,
      data_url: SHOT,
    }));
    const turn = await startTurn();

    await act(async () => {
      turn.onContentDelta?.(REPLY);
      turn.onDone?.({ content: REPLY, tool_calls: calls, images: shots });
      turn.onSaved?.({ ...SAVED_REPLY, tool_calls: calls });
    });

    const alt = "Screenshot of Google Chrome (desktop.screenshot)";
    expect(await screen.findAllByRole("img", { name: alt })).toHaveLength(3);
    expect(screen.getByText(OVER_LIMIT)).toBeInTheDocument();
    expect(screen.queryByText(NOT_KEPT)).not.toBeInTheDocument();
  });
});
