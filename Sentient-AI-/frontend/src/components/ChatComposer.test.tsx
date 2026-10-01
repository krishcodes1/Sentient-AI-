/**
 * Tests for ChatComposer: they prove Enter sends and Shift+Enter inserts a newline, IME
 * composition and empty or in-flight sends are ignored, Stop replaces Send while streaming,
 * images can be attached, capped, refused and removed, and documents are uploaded as soon as
 * they are picked, shown as chips (reading, read, refused), capped, and forgotten on removal.
 *
 * Why it exists: Guards against a message going out mid-IME candidate, a second send during
 * streaming, or an attachment that cannot be taken back before it is sent.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/services/api", () => ({
  uploadFile: vi.fn(),
  deleteFile: vi.fn(async () => undefined),
}));

import ChatComposer, { MAX_FILES, MAX_IMAGES } from "@/components/ChatComposer";
import { deleteFile, uploadFile } from "@/services/api";
import type { FileAttachment, UploadedFile } from "@/types";

/**
 * The composer is a textarea that sends on Enter, which puts two behaviours
 * in direct tension: a message must go on Enter, and a multi-line message
 * must still be possible. Both are covered here, along with the IME case
 * where Enter commits a candidate rather than finishing a sentence, and the
 * attachment flow — a picked image can always be taken back before it goes.
 */

function renderComposer(
  overrides: Omit<
    Partial<React.ComponentProps<typeof ChatComposer>>,
    "onSend" | "onStop"
  > = {},
) {
  const onSend = vi.fn<(content: string, images: string[], files: FileAttachment[]) => void>();
  const onStop = vi.fn<() => void>();
  render(
    <ChatComposer
      disabled={false}
      sending={false}
      placeholder="Ask Crawler AI anything..."
      {...overrides}
      onSend={onSend}
      onStop={onStop}
    />,
  );
  return { onSend, onStop };
}

const box = () => screen.getByRole("textbox", { name: "Message" });
const fileInput = () => screen.getByLabelText("File to attach");

/** The bordered area that accepts drops — the composer's outer field. */
const dropZone = () => box().closest("form")!.firstElementChild as HTMLElement;

/** Four bytes of PNG header: enough for FileReader to produce a data URL. */
function pngFile(name = "shot.png") {
  return new File([Uint8Array.from([137, 80, 78, 71])], name, {
    type: "image/png",
  });
}

beforeEach(() => {
  vi.mocked(uploadFile).mockReset();
  vi.mocked(deleteFile).mockReset();
  vi.mocked(deleteFile).mockResolvedValue(undefined);
});

describe("ChatComposer", () => {
  it("sends on Enter and clears the box", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.type(box(), "hello there");
    await user.keyboard("{Enter}");

    expect(onSend).toHaveBeenCalledWith("hello there", [], []);
    expect(box()).toHaveValue("");
  });

  it("inserts a newline on Shift+Enter and sends nothing", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.type(box(), "first line");
    await user.keyboard("{Shift>}{Enter}{/Shift}");
    await user.type(box(), "second line");

    expect(onSend).not.toHaveBeenCalled();
    expect(box()).toHaveValue("first line\nsecond line");

    await user.keyboard("{Enter}");
    expect(onSend).toHaveBeenCalledWith("first line\nsecond line", [], []);
  });

  it("does not send when Enter is committing an IME candidate", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.type(box(), "にほんご");

    // userEvent cannot drive a composition, so the keydown is delivered the
    // way an IME does: Enter, with isComposing set.
    const event = new KeyboardEvent("keydown", {
      key: "Enter",
      bubbles: true,
      cancelable: true,
    });
    Object.defineProperty(event, "isComposing", { value: true });
    fireEvent(box(), event);

    expect(onSend).not.toHaveBeenCalled();
    expect(box()).toHaveValue("にほんご");
  });

  it("ignores Enter on an empty box", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.click(box());
    await user.keyboard("{Enter}");
    await user.type(box(), "   ");
    await user.keyboard("{Enter}");

    expect(onSend).not.toHaveBeenCalled();
  });

  it("will not send while a turn is already streaming", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer({ sending: true });

    await user.type(box(), "second question");
    await user.keyboard("{Enter}");

    expect(onSend).not.toHaveBeenCalled();
  });

  it("swaps Send for Stop while streaming", async () => {
    const user = userEvent.setup();
    const { onStop } = renderComposer({ sending: true });

    expect(
      screen.queryByRole("button", { name: "Send message" }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Stop generating" }));

    expect(onStop).toHaveBeenCalledOnce();
  });

  it("attaches an image, shows it, and lets it be removed before sending", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pngFile("diagram.png"));

    const thumb = await screen.findByAltText("diagram.png");
    expect(thumb).toHaveAttribute("src", expect.stringContaining("data:image/png"));

    await user.click(screen.getByRole("button", { name: "Remove diagram.png" }));
    expect(screen.queryByAltText("diagram.png")).not.toBeInTheDocument();

    await user.type(box(), "no picture after all");
    await user.keyboard("{Enter}");

    expect(onSend).toHaveBeenCalledWith("no picture after all", [], []);
  });

  it("sends an attachment as a data URL alongside the text", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pngFile());
    await screen.findByAltText("shot.png");

    await user.type(box(), "what is this");
    await user.keyboard("{Enter}");

    expect(onSend).toHaveBeenCalledOnce();
    const [content, images] = onSend.mock.calls[0];
    expect(content).toBe("what is this");
    expect(images).toHaveLength(1);
    expect(images[0]).toMatch(/^data:image\/png/);
  });

  it("sends an image on its own, with no text", async () => {
    const user = userEvent.setup();
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pngFile());
    await screen.findByAltText("shot.png");

    await user.click(screen.getByRole("button", { name: "Send message" }));

    expect(onSend).toHaveBeenCalledOnce();
    expect(onSend.mock.calls[0][0]).toBe("");
    expect(onSend.mock.calls[0][1]).toHaveLength(1);
  });

  it("accepts an image dropped onto the composer", async () => {
    renderComposer();

    fireEvent.drop(dropZone(), {
      dataTransfer: { files: [pngFile("dropped.png")], types: ["Files"] },
    });

    expect(await screen.findByAltText("dropped.png")).toBeInTheDocument();
  });

  it("refuses a dropped file it cannot read with a readable reason", async () => {
    renderComposer();

    fireEvent.drop(dropZone(), {
      dataTransfer: {
        files: [new File(["#!/bin/sh"], "run.sh", { type: "application/x-sh" })],
        types: ["Files"],
      },
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("Crawler can't read run.sh.");
    expect(uploadFile).not.toHaveBeenCalled();
    expect(screen.queryByAltText("run.sh")).not.toBeInTheDocument();
  });

  it("tells how to fix an older Office file instead of calling it unreadable", async () => {
    renderComposer();

    fireEvent.drop(dropZone(), {
      dataTransfer: {
        files: [new File(["x"], "syllabus.doc", { type: "application/msword" })],
        types: ["Files"],
      },
    });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "syllabus.doc is an older Office format (.doc/.xls/.ppt). Save it as .docx/.xlsx/.pptx or PDF and send it again.",
    );
    expect(alert).not.toHaveTextContent("can't read");
    expect(uploadFile).not.toHaveBeenCalled();
  });

  it("caps the number of attachments and says so", async () => {
    const user = userEvent.setup();
    renderComposer();

    await user.upload(
      fileInput(),
      Array.from({ length: MAX_IMAGES + 1 }, (_, i) => pngFile(`shot-${i}.png`)),
    );

    await waitFor(() =>
      expect(screen.getAllByRole("img")).toHaveLength(MAX_IMAGES),
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      `Up to ${MAX_IMAGES} images per message.`,
    );
  });

  it("disables everything when there is no conversation to send to", () => {
    renderComposer({ disabled: true });

    expect(box()).toBeDisabled();
    expect(screen.getByRole("button", { name: "Attach a file" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Send message" })).toBeDisabled();
  });

  // -- Documents (top10:file_extraction) ----------------------------------

  const uploaded = (overrides: Partial<UploadedFile> = {}): UploadedFile => ({
    id: "f-1",
    name: "syllabus.pdf",
    kind: "pdf",
    media_type: "application/pdf",
    size_bytes: 1234,
    pages: 12,
    sections: 12,
    chars: 9000,
    scanned_pages_unread: [],
    truncated: false,
    warnings: [],
    source: "web",
    created_at: "2026-09-30T00:00:00Z",
    expires_at: "2026-10-30T00:00:00Z",
    ...overrides,
  });

  function pdfFile(name = "syllabus.pdf", size = 10) {
    return new File([new Uint8Array(size)], name, { type: "application/pdf" });
  }

  it("uploads a document at once instead of reading it into a data URL", async () => {
    const user = userEvent.setup();
    let finish: (value: UploadedFile) => void = () => {};
    vi.mocked(uploadFile).mockImplementation(
      () => new Promise<UploadedFile>((resolve) => (finish = resolve)),
    );
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pdfFile());
    expect(uploadFile).toHaveBeenCalledOnce();
    expect(await screen.findByText("Reading syllabus.pdf…")).toBeInTheDocument();
    // Send waits while the file is still being read.
    await user.type(box(), "when is the midterm?");
    expect(screen.getByRole("button", { name: "Send message" })).toBeDisabled();

    finish(uploaded({ scanned_pages_unread: [3, 4] }));
    expect(
      await screen.findByText("syllabus.pdf · 12 pages · 2 scanned pages unread"),
    ).toBeInTheDocument();
    await user.keyboard("{Enter}");

    expect(onSend).toHaveBeenCalledOnce();
    const [content, images, files] = onSend.mock.calls[0];
    expect(content).toBe("when is the midterm?");
    expect(images).toEqual([]);
    expect(files).toEqual([
      expect.objectContaining({ kind: "file", file_id: "f-1", name: "syllabus.pdf", pages: 12 }),
    ]);
    expect(screen.queryByText(/syllabus.pdf ·/)).not.toBeInTheDocument();
  });

  it("shows why a document could not be read", async () => {
    const user = userEvent.setup();
    vi.mocked(uploadFile).mockRejectedValue(
      new Error("This file is password-protected. Save a copy without a password and send it again."),
    );
    renderComposer();

    await user.upload(fileInput(), pdfFile("locked.pdf"));
    expect(
      await screen.findByText(/Couldn't read: This file is password-protected/),
    ).toBeInTheDocument();
  });

  it("refuses a document over 20 MB without uploading it", async () => {
    const user = userEvent.setup();
    renderComposer();

    await user.upload(fileInput(), pdfFile("huge.pdf", 20 * 1024 * 1024 + 1));
    expect(
      await screen.findByText("Couldn't read: huge.pdf is larger than 20MB."),
    ).toBeInTheDocument();
    expect(uploadFile).not.toHaveBeenCalled();
  });

  it("caps documents at five per message", async () => {
    const user = userEvent.setup();
    vi.mocked(uploadFile).mockImplementation(async (file: File) =>
      uploaded({ id: file.name, name: file.name }),
    );
    renderComposer();

    await user.upload(
      fileInput(),
      Array.from({ length: MAX_FILES + 1 }, (_, i) => pdfFile(`part-${i}.pdf`)),
    );
    await waitFor(() => expect(uploadFile).toHaveBeenCalledTimes(MAX_FILES));
    expect(screen.getByRole("alert")).toHaveTextContent(`Up to ${MAX_FILES} files per message.`);
  });

  it("forgets an uploaded document when its chip is removed", async () => {
    const user = userEvent.setup();
    vi.mocked(uploadFile).mockResolvedValue(uploaded());
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pdfFile());
    await screen.findByText("syllabus.pdf · 12 pages");
    await user.click(screen.getByRole("button", { name: "Remove syllabus.pdf" }));

    expect(deleteFile).toHaveBeenCalledWith("f-1");
    expect(screen.queryByText(/syllabus.pdf/)).not.toBeInTheDocument();
    await user.type(box(), "never mind");
    await user.keyboard("{Enter}");
    expect(onSend).toHaveBeenCalledWith("never mind", [], []);
  });

  it("keeps a file the server already had when its chip is removed", async () => {
    const user = userEvent.setup();
    vi.mocked(uploadFile).mockResolvedValue(uploaded({ deduped: true }));
    renderComposer();

    await user.upload(fileInput(), pdfFile());
    await screen.findByText("syllabus.pdf · 12 pages");
    await user.click(screen.getByRole("button", { name: "Remove syllabus.pdf" }));
    expect(deleteFile).not.toHaveBeenCalled();
  });

  it("sends a document on its own, with no text", async () => {
    const user = userEvent.setup();
    vi.mocked(uploadFile).mockResolvedValue(
      uploaded({ kind: "pptx", pages: 30, name: "deck.pptx" }),
    );
    const { onSend } = renderComposer();

    await user.upload(fileInput(), pdfFile("deck.pptx"));
    await screen.findByText("deck.pptx · 30 slides");
    await user.click(screen.getByRole("button", { name: "Send message" }));
    expect(onSend.mock.calls[0][0]).toBe("");
    expect(onSend.mock.calls[0][2]).toHaveLength(1);
  });
});
