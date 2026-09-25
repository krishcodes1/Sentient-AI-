/**
 * Tests for the Stop button on the chat page: it asks the server to stop the task and keeps the
 * stream open, so the saved "Stopped." reply arrives like any other; it cuts the stream itself
 * only when that request fails or the turn has not ended within the fallback time.
 *
 * Why it exists: Stop used to abort the stream only, so the server ran the task (browsing,
 * several tools, desktop actions) to its end while the page showed it as stopped.
 */

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Conversation, User } from "@/types";

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
  getConversation,
  getConversations,
  getMe,
  stopAgent,
  streamMessage,
  type StreamHandlers,
} from "@/services/api";

const STOPPED = "Stopped. I didn't finish the task. 1 step ran before the stop.";

const ME = {
  id: "u1",
  email: "student@example.com",
  name: "Student",
  created_at: "2026-09-24T12:00:00Z",
  default_permission_tier: "approval",
  rate_limit: 30,
} as unknown as User;

const CONV: Conversation = {
  id: "c1",
  user_id: "u1",
  title: "Office hours",
  created_at: "2026-09-24T12:00:00Z",
  updated_at: "2026-09-24T12:00:00Z",
};

/** The turn the page is streaming: its handlers and signal, and a way to
 *  end it the way a server-side stop does. */
interface OpenStream {
  handlers: StreamHandlers;
  signal: AbortSignal;
  finish: () => void;
}

function holdStreams(): OpenStream[] {
  const streams: OpenStream[] = [];
  vi.mocked(streamMessage).mockImplementation(
    (_conv, _content, handlers, signal) =>
      new Promise<void>((resolve, reject) => {
        signal?.addEventListener("abort", () =>
          reject(new DOMException("The operation was aborted.", "AbortError")),
        );
        streams.push({ handlers, signal: signal!, finish: resolve });
      }),
  );
  return streams;
}

async function startTurn(): Promise<void> {
  render(<Chat />);
  const box = await screen.findByRole("textbox", { name: "Message" });
  await waitFor(() => expect(box).not.toBeDisabled());
  fireEvent.change(box, { target: { value: "find the office hours" } });
  fireEvent.keyDown(box, { key: "Enter" });
  await screen.findByRole("button", { name: "Stop generating" });
}

describe("Stop on the chat page", () => {
  beforeEach(() => {
    // jsdom has no scrolling; the thread follows new messages with it.
    Element.prototype.scrollIntoView = vi.fn();
    vi.mocked(getMe).mockResolvedValue(ME);
    vi.mocked(getConversations).mockResolvedValue([CONV]);
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [] });
    vi.mocked(stopAgent).mockResolvedValue({ ok: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("asks the server to stop and shows the saved Stopped reply from the open stream", async () => {
    const streams = holdStreams();
    await startTurn();
    const [turn] = streams;

    fireEvent.click(screen.getByRole("button", { name: "Stop generating" }));
    fireEvent.click(screen.getByRole("button", { name: "Stop generating" }));

    expect(stopAgent).toHaveBeenCalledTimes(1); // a second press sends nothing
    expect(turn.signal.aborted).toBe(false); // the stream stays open for the reply
    expect(await screen.findByText("Stopping…")).toBeInTheDocument();

    // What the server sends once the task stops at its next step.
    await act(async () => {
      turn.handlers.onContentDelta?.(STOPPED);
      turn.handlers.onDone?.({ content: STOPPED });
      turn.handlers.onSaved?.({
        id: "m2",
        conversation_id: "c1",
        role: "assistant",
        content: STOPPED,
        created_at: "2026-09-24T12:00:05Z",
      });
      turn.finish();
    });

    expect(await screen.findByText(STOPPED)).toBeInTheDocument();
    expect(screen.queryByText("— stopped")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop generating" })).not.toBeInTheDocument();
    expect(turn.signal.aborted).toBe(false);
  });

  it("cuts the stream when the stop request fails", async () => {
    vi.mocked(stopAgent).mockRejectedValue(new Error("Request failed: Bad Gateway"));
    const streams = holdStreams();
    await startTurn();
    const [turn] = streams;
    act(() => turn.handlers.onContentDelta?.("The office hours are"));

    fireEvent.click(screen.getByRole("button", { name: "Stop generating" }));

    await waitFor(() => expect(turn.signal.aborted).toBe(true));
    // What streamed so far stays, marked as cut short.
    expect(await screen.findByText("— stopped")).toBeInTheDocument();
    expect(screen.getByText(/The office hours are/)).toBeInTheDocument();
  });

  it("cuts the stream when the turn has not ended within ten seconds", async () => {
    const streams = holdStreams();
    await startTurn();
    const [turn] = streams;

    vi.useFakeTimers();
    fireEvent.click(screen.getByRole("button", { name: "Stop generating" }));
    await act(async () => {
      await Promise.resolve(); // the stop request resolves; no reply comes
      vi.advanceTimersByTime(9_999);
    });
    expect(turn.signal.aborted).toBe(false);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(turn.signal.aborted).toBe(true);
    vi.useRealTimers();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Stop generating" })).not.toBeInTheDocument(),
    );
  });
});
