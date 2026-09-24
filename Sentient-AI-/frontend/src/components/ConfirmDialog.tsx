/**
 * Modal confirmation dialog that runs an async confirm action with a pending state and shows a
 * failure inline instead of closing.
 *
 * Why it exists: Deleting a conversation, memory, connector or account needs one branded
 * replacement for window.confirm() that cannot be double-submitted or dismissed mid-request.
 */

import { useCallback, useId, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { useFocusTrap } from "@/hooks/useFocusTrap";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  /** Extra content rendered between the message and the inline error
   * banner — e.g. a confirmation input a destructive action requires
   * (the account-deletion password). Optional; most callers need only
   * the message. */
  children?: ReactNode;
  onConfirm: () => Promise<void> | void;
  onCancel: () => void;
}

/**
 * Branded replacement for window.confirm(). Renders a modal with the
 * platform's visual language, runs an async confirm action with a
 * loading state, and surfaces failures inline instead of silently
 * closing.
 */
export default function ConfirmDialog({ open, ...panel }: ConfirmDialogProps) {
  // The panel unmounts while closed, so its pending/error state goes with
  // it: a reopened dialog never shows the last attempt's error or a stuck
  // spinner, and nothing has to reset them after the fact.
  if (!open) return null;
  return <ConfirmDialogPanel {...panel} />;
}

function ConfirmDialogPanel({
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  danger = false,
  children,
  onConfirm,
  onCancel,
}: Omit<ConfirmDialogProps, "open">) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const messageId = useId();

  // Escape is suppressed while the destructive action is in flight, for the
  // same reason the buttons are: the request cannot be taken back, so
  // closing here would only hide its outcome.
  const escape = useCallback(() => {
    if (!pending) onCancel();
  }, [pending, onCancel]);

  // Mounted only while open, so the trap holds for the panel's whole
  // lifetime and hands focus back when it unmounts.
  useFocusTrap(true, panelRef, escape);

  const handleConfirm = async () => {
    setPending(true);
    setError(null);
    try {
      await onConfirm();
    } catch (err) {
      setError((err as Error).message || "Something went wrong.");
      setPending(false);
    }
  };

  const accent = danger ? "var(--accent-danger)" : "var(--accent-primary)";

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center p-4"
      style={{ background: "var(--scrim)", backdropFilter: "blur(2px)" }}
      onClick={() => !pending && onCancel()}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={messageId}
        className="w-full max-w-sm rounded-[16px] p-6"
        style={{
          background: "var(--claw-panel)",
          border: "1px solid var(--claw-border)",
          boxShadow: "var(--shadow-modal)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-3 mb-3">
          {danger && (
            <div
              className="w-9 h-9 rounded-[10px] flex items-center justify-center shrink-0"
              style={{
                background: "var(--fill-danger)",
                border: "1px solid var(--border-danger)",
              }}
            >
              <AlertTriangle className="w-4 h-4" style={{ color: accent }} />
            </div>
          )}
          <div className="min-w-0">
            <h3 id={titleId} style={{ color: "var(--text-primary)" }}>
              {title}
            </h3>
            <p
              id={messageId}
              className="text-sm mt-1"
              style={{ color: "var(--text-secondary)" }}
            >
              {message}
            </p>
          </div>
        </div>

        {children && <div className="mb-3">{children}</div>}

        {error && (
          <p
            role="alert"
            className="text-xs mb-3 px-3 py-2 rounded-[8px]"
            style={{
              background: "var(--fill-danger)",
              color: "var(--accent-danger)",
              border: "1px solid var(--border-danger)",
            }}
          >
            {error}
          </p>
        )}

        <div className="flex items-center justify-end gap-2 mt-4">
          <button
            type="button"
            disabled={pending}
            onClick={onCancel}
            className="px-4 py-2 rounded-[10px] text-sm font-medium disabled:opacity-50"
            style={{
              background: "var(--bg-input)",
              border: "1px solid var(--claw-border)",
              color: "var(--text-primary)",
            }}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            disabled={pending}
            onClick={() => void handleConfirm()}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
            style={{ background: accent, color: "var(--text-on-accent)" }}
          >
            {pending && <Loader2 className="w-4 h-4 animate-spin" />}
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
