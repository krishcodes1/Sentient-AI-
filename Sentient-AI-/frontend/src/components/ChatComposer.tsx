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
import { ImagePlus, Send, Square, X } from "lucide-react";

/** Attachments are inlined into the request body, so they stay small. */
export const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
export const MAX_IMAGES = 4;

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
  onSend: (content: string, images: string[]) => void;
  onStop: () => void;
}) {
  const [text, setText] = useState("");
  const [attachments, setAttachments] = useState<ComposerAttachment[]>([]);
  const [attachError, setAttachError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
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

  const addFiles = useCallback(
    async (files: File[]) => {
      const images = files.filter((f) => f.type.startsWith("image/"));
      if (images.length === 0) {
        if (files.length > 0) setAttachError("Only image files can be attached.");
        return;
      }
      const accepted: ComposerAttachment[] = [];
      let rejected: string | null = null;
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
    [attachments.length],
  );

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
    if (sending || disabled) return;
    if (!content && attachments.length === 0) return;
    onSend(
      content,
      attachments.map((a) => a.dataUrl),
    );
    setText("");
    setAttachments([]);
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

  const canSend = !disabled && !sending && (text.trim() !== "" || attachments.length > 0);

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
            accept="image/*"
            multiple
            tabIndex={-1}
            aria-label="Image file"
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
            disabled={disabled || sending || attachments.length >= MAX_IMAGES}
            aria-label="Attach image"
            title="Attach image"
            className="shrink-0 inline-flex items-center justify-center rounded-[8px] disabled:opacity-40"
            style={{ width: 40, height: 40, color: "var(--text-muted)" }}
          >
            <ImagePlus className="w-4 h-4" aria-hidden />
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
        Enter sends · Shift+Enter for a new line · drop or paste an image to
        attach
      </p>
    </form>
  );
}
