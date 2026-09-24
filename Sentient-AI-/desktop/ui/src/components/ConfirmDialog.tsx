/**
 * Modal yes/no question on a native <dialog>, e.g. "Replace the keys?".
 *
 * Why it exists: Overwriting the security keys can lock people out of credentials they already
 * saved, so it needs an explicit, focused confirmation. The native dialog gives a real modal
 * (focus kept inside, Escape to cancel) with no dependency; the attribute fallback keeps it
 * working where `showModal` is missing (older WebViews, the jsdom test environment).
 */

import { useEffect, useRef, type ReactNode } from "react";
import { Button } from "./ui";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  cancelLabel = "Cancel",
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      try {
        dialog.showModal();
      } catch {
        dialog.setAttribute("open", "");
      }
      // The safe answer takes focus, so Enter doesn't replace anything by accident.
      cancelRef.current?.focus();
    } else if (!open && dialog.open) {
      try {
        dialog.close();
      } catch {
        dialog.removeAttribute("open");
      }
    }
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby="confirm-title"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <h3 id="confirm-title">{title}</h3>
      {children}
      <div className="actions">
        <Button variant="ghost" ref={cancelRef} onClick={onCancel}>
          {cancelLabel}
        </Button>
        <Button variant="primary" onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </dialog>
  );
}
