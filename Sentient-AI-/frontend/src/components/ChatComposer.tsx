/**
 * The chat input form: an auto-growing textarea that sends on Enter, image and document
 * attachments by button, paste or drop, and a Stop button while a turn is streaming.
 *
 * Why it exists: Attachment validation (types, size and count caps) and the Enter /
 * Shift+Enter / IME rules are self-contained here, so Chat.tsx only receives the final text,
 * image data URLs and the uploaded documents. Images keep the inline data-URL path; a document
 * (PDF, Word, PowerPoint, Excel, CSV, text, Markdown, HTML, JSON) is uploaded the moment it is
 * picked and shows as a chip that says what the server found ("x · 12 pages") or why it could
 * not read it; only its id goes with the message.
 */

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ClipboardEvent,
  type DragEvent,
  type FormEvent,
  type KeyboardEvent,
} from "react";
import { FileText, Paperclip, Send, Square, X } from "lucide-react";
import {
  ACCEPT,
  asAttachment,
  fileChipLabel,
  isDocument,
  unreadableFileMessage,
} from "@/components/fileChips";
import { deleteFile, uploadFile } from "@/services/api";
import type { FileAttachment } from "@/types";

/** Attachments are inlined into the request body, so they stay small. */
export const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
export const MAX_IMAGES = 4;
/** Mirrors the server's upload cap (it stays the authority). */
export const MAX_FILE_BYTES = 20 * 1024 * 1024;
export const MAX_FILES = 5;

/** One picked document: uploading, read (with what the server found), or refused. */
interface FileChip {
  id: string;
  name: string;
  status: "reading" | "ready" | "error";
  message?: string;
  file?: FileAttachment;
  /** The server already had this file: removing the chip must not forget it. */
  deduped?: boolean;
  controller?: AbortController;
}

/** Past this the textarea scrolls instead of eating the thread. */
const MAX_TEXTAREA_PX = 200;

export interface ComposerAttachment {
  /** Stable across re-renders so React keys survive a removal. */
  id: string;
  name: string;
  dataUrl: string;
}

function readAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error ?? new Error("Could not read file"));
    reader.readAsDataURL(file);
  });
}

export default function ChatComposer({
  disabled,
  sending,
  placeholder,
  onSend,
  onStop,
}: {
  /** No conversation is open — there is nowhere to send to. */
  disabled: boolean;
  sending: boolean;
  placeholder: string;
  /** `files` are the documents already uploaded and read (their ids go
   *  with the message; the entries let the thread show them at once). */
  onSend: (content: string, images: string[], files: FileAttachment[]) => void;
  onStop: () => void;
}) {
  const [text, setText] = useState("");
  const [attachments, setAttachments] = useState<ComposerAttachment[]>([]);
  const [chips, setChips] = useState<FileChip[]>([]);
  const [attachError, setAttachError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  // Chips removed while their upload was still running: a late success is
  // forgotten on the server rather than left behind.
  const removedRef = useRef<Set<string>>(new Set());
  const textareaId = useId();

  // Grow with the content up to a cap. Height is cleared first so the
  // textarea can also shrink back down when text is deleted — scrollHeight
  // never reports less than the current height.
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, MAX_TEXTAREA_PX)}px`;
  }, [text]);

  const uploadDocument = useCallback((file: File) => {
    const id = `${file.name}-${file.lastModified}-${Math.random().toString(36).slice(2)}`;
    const name = file.name || "file";
    if (file.size > MAX_FILE_BYTES) {
      setChips((prev) => [
        ...prev,
        {
          id,
          name,
          status: "error",
          message: `${name} is larger than ${MAX_FILE_BYTES / (1024 * 1024)}MB.`,
        },
      ]);
      return;
    }
    const controller = new AbortController();
    setChips((prev) => [...prev, { id, name, status: "reading", controller }]);
    uploadFile(file, controller.signal)
      .then((uploaded) => {
        if (removedRef.current.has(id)) {
          if (!uploaded.deduped) void deleteFile(uploaded.id).catch(() => {});
          return;
        }
        setChips((prev) =>
          prev.map((chip) =>
            chip.id === id
              ? {
                  id,
                  name: uploaded.name,
                  status: "ready",
                  file: asAttachment(uploaded),
                  deduped: Boolean(uploaded.deduped),
                }
              : chip,
          ),
        );
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        const message = err instanceof Error && err.message ? err.message : "The file could not be read.";
        setChips((prev) =>
          prev.map((chip) =>
            chip.id === id ? { id, name, status: "error", message } : chip,
          ),
        );
      });
  }, []);

  const removeChip = (chip: FileChip) => {
    removedRef.current.add(chip.id);
    chip.controller?.abort();
    // A file the server already had (from an earlier message) is not
    // forgotten just because this chip is removed.
    if (chip.status === "ready" && chip.file && !chip.deduped) {
      void deleteFile(chip.file.file_id).catch(() => {});
    }
    setChips((prev) => prev.filter((x) => x.id !== chip.id));
  };

  const addFiles = useCallback(
    async (files: File[]) => {
      const documents = files.filter((f) => !f.type.startsWith("image/") && isDocument(f));
      const unreadable = files.filter((f) => !f.type.startsWith("image/") && !isDocument(f));
      const images = files.filter((f) => f.type.startsWith("image/"));
      let rejected: string | null = null;
      if (unreadable.length > 0) {
        rejected = unreadableFileMessage(unreadable[0]);
      }
      if (documents.length > 0) {
        const room = Math.max(0, MAX_FILES - chips.length);
        if (documents.length > room) {
          rejected = `Up to ${MAX_FILES} files per message.`;
        }
        documents.slice(0, room).forEach(uploadDocument);
      }
      if (images.length === 0) {
        setAttachError(rejected);
        return;
      }
      const accepted: ComposerAttachment[] = [];
      for (const file of images) {
        if (file.size > MAX_IMAGE_BYTES) {
          rejected = `${file.name || "That image"} is larger than ${
            MAX_IMAGE_BYTES / (1024 * 1024)
          }MB.`;
          continue;
        }
        try {
          accepted.push({
            id: `${file.name}-${file.lastModified}-${Math.random().toString(36).slice(2)}`,
            name: file.name || "image",
            dataUrl: await readAsDataUrl(file),
          });
        } catch {
          rejected = `${file.name || "That image"} could not be read.`;
        }
      }
      // Read the count here rather than inside the updater: the message
      // below depends on it, and a functional update can run twice (Strict
      // Mode) or after this line, either of which desynchronises the two.
      const room = Math.max(0, MAX_IMAGES - attachments.length);
      if (accepted.length > room) {
        rejected = `Up to ${MAX_IMAGES} images per message.`;
      }
      const toAdd = accepted.slice(0, room);
      if (toAdd.length > 0) setAttachments((prev) => [...prev, ...toAdd]);
      setAttachError(rejected);
    },
    [attachments.length, chips.length, uploadDocument],
  );

  const readyFiles = chips.filter((c) => c.status === "ready" && c.file).map((c) => c.file!);
  const reading = chips.some((c) => c.status === "reading");

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    if (disabled || sending) return;
    void addFiles(Array.from(event.dataTransfer.files));
  };

  const handlePaste = (event: ClipboardEvent<HTMLTextAreaElement>) => {
    const files = Array.from(event.clipboardData.files);
    if (files.length === 0) return;
    // Let the text half of a mixed paste through; only the files are ours.
    void addFiles(files);
  };

  const submit = () => {
    const content = text.trim();
    if (sending || disabled || reading) return;
    if (!content && attachments.length === 0 && readyFiles.length === 0) return;
    onSend(
      content,
      attachments.map((a) => a.dataUrl),
      readyFiles,
    );
    setText("");
    setAttachments([]);
    setChips([]);
    setAttachError(null);
  };

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    submit();
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    // `isComposing` guards IME candidate selection, where Enter commits the
    // candidate and must not also send a half-typed message.
    if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing) {
      return;
    }
    event.preventDefault();
    submit();
  };

  const canSend =
    !disabled &&
    !sending &&
    !reading &&
    (text.trim() !== "" || attachments.length > 0 || readyFiles.length > 0);

  return (
    <form
      onSubmit={handleSubmit}
      className="p-3 sm:p-4"
      style={{ borderTop: "1px solid var(--claw-border)" }}
    >
      <div
        onDragOver={(e) => {
          e.preventDefault();
          if (!disabled && !sending) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className="rounded-[12px] px-3 py-2 transition-colors"
        style={{
          background: "var(--bg-input)",
          border: `1px solid ${dragging ? "var(--accent-primary)" : "var(--claw-border)"}`,
        }}
      >
        {attachments.length > 0 && (
          <ul className="flex flex-wrap gap-2 pt-1 pb-2">
            {attachments.map((a) => (
              <li key={a.id} className="relative">
                <img
                  src={a.dataUrl}
                  alt={a.name}
                  className="w-14 h-14 rounded-[8px] object-cover"
                  style={{ border: "1px solid var(--claw-border)" }}
                />
                <button
                  type="button"
                  onClick={() =>
                    setAttachments((prev) => prev.filter((x) => x.id !== a.id))
                  }
                  aria-label={`Remove ${a.name}`}
                  className="absolute -top-1.5 -right-1.5 inline-flex items-center justify-center rounded-full"
                  style={{
                    width: 20,
                    height: 20,
                    background: "var(--claw-panel)",
                    border: "1px solid var(--claw-border)",
                    color: "var(--text-secondary)",
                  }}
                >
                  <X className="w-3 h-3" aria-hidden />
                </button>
              </li>
            ))}
          </ul>
        )}

        {chips.length > 0 && (
          <ul className="flex flex-wrap gap-2 pt-1 pb-2" aria-label="Attached files">
            {chips.map((chip) => {
              const label =
                chip.status === "reading"
                  ? `Reading ${chip.name}…`
                  : chip.status === "ready" && chip.file
                    ? fileChipLabel(chip.file)
                    : `Couldn't read: ${chip.message ?? chip.name}`;
              return (
                <li
                  key={chip.id}
                  className="inline-flex items-center gap-1.5 rounded-[8px] px-2 py-1 text-xs max-w-full"
                  style={{
                    border: `1px solid ${chip.status === "error" ? "var(--accent-danger)" : "var(--claw-border)"}`,
                    color: chip.status === "error" ? "var(--accent-danger)" : "var(--text-secondary)",
                    background: "var(--claw-panel)",
                  }}
                  aria-busy={chip.status === "reading"}
                >
                  <FileText className="w-3.5 h-3.5 shrink-0" aria-hidden />
                  <span className="truncate" title={label}>
                    {label}
                  </span>
                  <button
                    type="button"
                    onClick={() => removeChip(chip)}
                    aria-label={`Remove ${chip.name}`}
                    className="shrink-0 inline-flex items-center justify-center rounded-full"
                    style={{ width: 16, height: 16, color: "var(--text-muted)" }}
                  >
                    <X className="w-3 h-3" aria-hidden />
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        <div className="flex items-end gap-2">
          <label htmlFor={textareaId} className="sr-only">
            Message
          </label>
          <textarea
            id={textareaId}
            ref={textareaRef}
            rows={1}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={handleKeyDown}
            onPaste={handlePaste}
            placeholder={placeholder}
            disabled={disabled}
            aria-describedby={attachError ? `${textareaId}-error` : undefined}
            className="flex-1 min-w-0 bg-transparent outline-none text-sm resize-none py-2 disabled:opacity-50"
            style={{ color: "var(--text-primary)", maxHeight: MAX_TEXTAREA_PX }}
          />

          {/* Driven by the button beside it: kept out of the tab order so
              there is one way in, not two, but still rendered (rather than
              display:none) because a detached input cannot be opened. */}
          <input
            ref={fileInputRef}
            type="file"
            accept={ACCEPT}
            multiple
            tabIndex={-1}
            aria-label="File to attach"
            className="sr-only"
            onChange={(e) => {
              void addFiles(Array.from(e.target.files ?? []));
              // Clearing lets the same file be picked again after a removal.
              e.target.value = "";
            }}
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={
              disabled ||
              sending ||
              (attachments.length >= MAX_IMAGES && chips.length >= MAX_FILES)
            }
            aria-label="Attach a file"
            title="Attach an image or a document (PDF, Word, PowerPoint, Excel, CSV, text)"
            className="shrink-0 inline-flex items-center justify-center rounded-[8px] disabled:opacity-40"
            style={{ width: 40, height: 40, color: "var(--text-muted)" }}
          >
            <Paperclip className="w-4 h-4" aria-hidden />
          </button>

          {sending ? (
            <button
              type="button"
              onClick={onStop}
              aria-label="Stop generating"
              title="Stop generating"
              className="shrink-0 inline-flex items-center justify-center rounded-[8px]"
              style={{
                width: 40,
                height: 40,
                background: "var(--claw-surface)",
                border: "1px solid var(--claw-border)",
                color: "var(--text-primary)",
              }}
            >
              <Square className="w-3.5 h-3.5" fill="currentColor" aria-hidden />
            </button>
          ) : (
            <button
              type="submit"
              disabled={!canSend}
              aria-label="Send message"
              title="Send message"
              className="shrink-0 inline-flex items-center justify-center rounded-[8px] transition-colors disabled:opacity-50"
              style={{
                width: 40,
                height: 40,
                background: canSend ? "var(--accent-primary)" : "transparent",
                color: canSend ? "var(--text-on-accent)" : "var(--text-muted)",
              }}
            >
              <Send className="w-4 h-4" aria-hidden />
            </button>
          )}
        </div>
      </div>

      {attachError && (
        <p
          id={`${textareaId}-error`}
          role="alert"
          className="text-xs mt-2"
          style={{ color: "var(--accent-danger)" }}
        >
          {attachError}
        </p>
      )}
      <p className="text-xs mt-2 hidden sm:block" style={{ color: "var(--text-muted)" }}>
        Enter sends · Shift+Enter for a new line · drop or paste an image or a
        document to attach
      </p>
    </form>
  );
}
