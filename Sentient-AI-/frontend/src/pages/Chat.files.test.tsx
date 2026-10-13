/**
 * Tests for documents in the chat thread: a reloaded thread shows a user turn's file chips from
 * its stored attachments (name and what was found), and a document picked in the composer is
 * uploaded, shown on the sent bubble at once and sent by id with the turn.
 *
 * Why it exists: the server keeps only a document's metadata on the message, so the thread must
 * render the chips from that alone, and the optimistic bubble must not lose them when the saved
 * row replaces it.
 */

import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Conversation, FileAttachment, Message, User } from "@/types";

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
import {
  getConversation,
  getConversations,
  getMe,
  streamMessage,
  uploadFile,
  type StreamHandlers,
} from "@/services/api";

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
  title: "Biology",
  created_at: "2026-09-25T12:00:00Z",
  updated_at: "2026-09-25T12:00:00Z",
};

const SYLLABUS: FileAttachment = {
  kind: "file",
  file_id: "f-1",
  name: "Syllabus_BIO101.pdf",
  media_type: "application/pdf",
  doc_kind: "pdf",
  pages: 12,
  chars: 24000,
  size_bytes: 88000,
  scanned_pages_unread: [11],
};

const USER_ROW: Message = {
  id: "m1",
  conversation_id: "c1",
  role: "user",
  content: "When are the midterms?",
  attachments: [SYLLABUS, { media_type: "image/png", size_bytes: 10, sha256: "x" }],
  created_at: "2026-09-25T12:00:00Z",
};

describe("Documents in the chat", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
    vi.mocked(getMe).mockResolvedValue(ME);
    vi.mocked(getConversations).mockResolvedValue([CONV]);
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [] });
    vi.mocked(uploadFile).mockReset();
    vi.mocked(streamMessage).mockReset();
  });

  it("shows a reloaded turn's file chips from its attachments", async () => {
    vi.mocked(getConversation).mockResolvedValue({ ...CONV, messages: [USER_ROW] });
    render(<Chat />);

    const list = await screen.findByRole("list", { name: "Attached files" });
    expect(
      within(list).getByText("Syllabus_BIO101.pdf · 12 pages · 1 scanned page unread"),
    ).toBeInTheDocument();
    // An image metadata entry is not a file chip.
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
  });

  it("sends a picked document by id and keeps its chip on the sent bubble", async () => {
    const user = userEvent.setup();
    vi.mocked(uploadFile).mockResolvedValue({
      id: "f-9",
      name: "notes.pdf",
      kind: "pdf",
      media_type: "application/pdf",
      size_bytes: 10,
      pages: 3,
      sections: 3,
      chars: 900,
      scanned_pages_unread: [],
      truncated: false,
      warnings: [],
      source: "web",
      created_at: "2026-09-30T00:00:00Z",
      expires_at: "2026-10-30T00:00:00Z",
    });
    let handlers: StreamHandlers | undefined;
    vi.mocked(streamMessage).mockImplementation((_conv, _content, h) => {
      handlers = h;
      return new Promise<void>(() => {});
    });
    render(<Chat />);
    const box = await screen.findByRole("textbox", { name: "Message" });
    await waitFor(() => expect(box).not.toBeDisabled());

    await user.upload(
      screen.getByLabelText("File to attach"),
      new File(["%PDF"], "notes.pdf", { type: "application/pdf" }),
    );
    await screen.findByText("notes.pdf · 3 pages");
    fireEvent.change(box, { target: { value: "summarize" } });
    fireEvent.keyDown(box, { key: "Enter" });

    await waitFor(() => expect(streamMessage).toHaveBeenCalledOnce());
    const args = vi.mocked(streamMessage).mock.calls[0];
    expect(args[1]).toBe("summarize");
    expect(args[5]).toEqual(["f-9"]);
    const bubble = await screen.findByRole("list", { name: "Attached files" });
    expect(within(bubble).getByText("notes.pdf · 3 pages")).toBeInTheDocument();

    // The saved row (which echoes no attachments here) keeps the chip.
    await act(async () =>
      handlers?.onUserMessage?.({
        id: "m9",
        conversation_id: "c1",
        role: "user",
        content: "summarize",
        created_at: "2026-09-30T00:00:01Z",
      }),
    );
    expect(screen.getByText("notes.pdf · 3 pages")).toBeInTheDocument();
  });
});
