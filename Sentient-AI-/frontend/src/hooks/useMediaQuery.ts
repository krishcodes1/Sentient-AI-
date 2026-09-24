/**
 * useMediaQuery subscribes to a CSS media query through useSyncExternalStore, alongside the
 * DESKTOP, REDUCED_MOTION and DARK query strings.
 *
 * Why it exists: Layout and the theme need a JS answer for the few decisions markup must make,
 * correct on the first render and safe where matchMedia is absent (jsdom).
 */

import { useCallback, useSyncExternalStore } from "react";

/**
 * Subscribe to a CSS media query from JS.
 *
 * Layout itself stays in CSS — this is only for the handful of decisions
 * markup has to make and stylesheets cannot, such as whether the sidebar is
 * currently a drawer (and therefore has to trap focus) or a static column.
 *
 * Read through useSyncExternalStore so the first render already has the
 * right answer: a subscribe-then-correct effect would render one frame of
 * the wrong layout, which on a phone means a visible flash of the desktop
 * shell.
 *
 * `matchMedia` is absent in jsdom and in any non-browser render, so both the
 * lookup and the subscription fall back to `fallback` rather than throwing.
 */
export function useMediaQuery(query: string, fallback = false): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      const mql = window.matchMedia?.(query);
      if (!mql) return () => {};
      mql.addEventListener("change", onChange);
      return () => mql.removeEventListener("change", onChange);
    },
    [query],
  );

  const getSnapshot = useCallback(
    () => evaluate(query, fallback),
    [query, fallback],
  );

  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export function evaluate(query: string, fallback = false): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return fallback;
  return window.matchMedia(query).matches;
}

/** The breakpoint at which the nav stops being a drawer (Tailwind `lg`). */
export const DESKTOP_QUERY = "(min-width: 1024px)";

/** Set when the reader has asked their OS to keep animation to a minimum. */
export const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

/** The OS-level dark preference, for anything JS has to resolve itself. */
export const DARK_QUERY = "(prefers-color-scheme: dark)";
