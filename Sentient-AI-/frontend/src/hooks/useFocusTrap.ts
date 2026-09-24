import { useEffect, useRef, type RefObject } from "react";

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function focusable(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE));
}

/**
 * Keep keyboard focus inside an overlay while it is open, and hand it back
 * to whatever opened it on close.
 *
 * Without this a modal is only visually modal: Tab walks straight out into
 * the page behind it, where a screen-reader user has no way of knowing a
 * dialog is even on screen, and closing leaves focus on <body> so the next
 * Tab restarts from the top of the document.
 */
export function useFocusTrap(
  active: boolean,
  containerRef: RefObject<HTMLElement | null>,
  onEscape?: () => void,
): void {
  // The escape handler is usually an inline arrow from the parent, so its
  // identity changes on every parent render. Holding it in a ref keeps the
  // effect below keyed on `active` alone — re-running it would re-capture
  // the "previous" element and pull focus back to the top of the overlay
  // mid-interaction.
  const escapeRef = useRef(onEscape);
  useEffect(() => {
    escapeRef.current = onEscape;
  });

  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;

    const previous = document.activeElement as HTMLElement | null;
    // Prefer the first control over the container itself so the reader lands
    // on something actionable rather than on an unlabelled wrapper.
    if (!container.contains(document.activeElement)) {
      (focusable(container)[0] ?? container).focus();
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && escapeRef.current) {
        escapeRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable(container);
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const current = document.activeElement;
      // Wrap at both ends. The `!contains` case catches focus that started
      // outside the overlay — after a click on the scrim, say — which would
      // otherwise tab straight into the page behind it.
      if (event.shiftKey && (current === first || !container.contains(current))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && current === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      if (previous?.isConnected) previous.focus();
    };
  }, [active, containerRef]);
}
