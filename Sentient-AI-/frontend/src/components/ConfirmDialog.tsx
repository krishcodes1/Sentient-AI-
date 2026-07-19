import { useEffect, useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";

/**
 * Branded replacement for window.confirm(). Renders a modal with the
 * platform's visual language, runs an async confirm action with a
 * loading state, and surfaces failures inline instead of silently
 * closing.
 */
export default function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  danger = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  onConfirm: () => Promise<void> | void;
  onCancel: () => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setPending(false);
      setError(null);
      return;
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !pending) onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, pending, onCancel]);

  if (!open) return null;

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
      style={{ background: "rgba(0,0,0,0.62)", backdropFilter: "blur(2px)" }}
      onClick={() => !pending && onCancel()}
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div
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
            <h3 style={{ color: "var(--text-primary)" }}>{title}</h3>
            <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
              {message}
            </p>
          </div>
        </div>

        {error && (
          <p
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
            style={{ background: accent, color: "#0a0a0b" }}
          >
            {pending && <Loader2 className="w-4 h-4 animate-spin" />}
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
