/**
 * ThemeProvider: reads the saved light/dark/system choice, resolves it against the OS preference,
 * and applies it via the data-theme attribute and the theme-color meta.
 *
 * Why it exists: The stylesheet and the inline bootstrap in index.html both key off the stored
 * choice and data-theme, so one component owns persisting and applying it; main.tsx mounts it
 * above every consumer of useTheme.
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { DARK_QUERY, useMediaQuery } from "@/hooks/useMediaQuery";
// The context and its hook live beside the other hooks so this module
// exports only the provider component (plus a constant), which keeps
// Fast Refresh working here. Consumers import useTheme from there.
import { ThemeContext, type ThemeMode } from "@/hooks/useTheme";

/** Also read by the inline bootstrap in index.html — keep the two in step. */
export const THEME_STORAGE_KEY = "crawler.theme";

/**
 * Pre-rename key. Read once as a fallback so a choice saved before the
 * Crawler AI rename is not silently dropped, then migrated onto
 * THEME_STORAGE_KEY so every later read only has one key to consider.
 */
const LEGACY_THEME_STORAGE_KEY = "sentientai_theme";

/** Matches the `theme-color` meta the document ships with. */
const META_COLORS: Record<"light" | "dark", string> = {
  light: "#f6f6f8",
  dark: "#0a0a0b",
};

function isMode(value: unknown): value is ThemeMode {
  return value === "light" || value === "dark" || value === "system";
}

/**
 * localStorage throws outright in a private window with site data blocked,
 * and returns nothing useful when it has been cleared. Neither is a reason
 * to fail to render, so both fall back to following the OS.
 */
function readStoredMode(): ThemeMode {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (isMode(stored)) return stored;

    // One-time migration: a choice saved under the pre-rename key still
    // applies. Move it onto the new key so this branch is never hit again.
    const legacy = localStorage.getItem(LEGACY_THEME_STORAGE_KEY);
    if (isMode(legacy)) {
      try {
        localStorage.setItem(THEME_STORAGE_KEY, legacy);
        localStorage.removeItem(LEGACY_THEME_STORAGE_KEY);
      } catch {
        /* best-effort migration; the resolved mode below is still correct */
      }
      return legacy;
    }
    return "system";
  } catch {
    return "system";
  }
}

function persistMode(mode: ThemeMode): void {
  try {
    if (mode === "system") localStorage.removeItem(THEME_STORAGE_KEY);
    else localStorage.setItem(THEME_STORAGE_KEY, mode);
  } catch {
    /* the choice still applies to this tab; it just won't outlive it */
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(readStoredMode);
  // Subscribed in every mode, not just "system", so switching back to
  // "system" resolves immediately rather than waiting for the OS to change.
  const systemDark = useMediaQuery(DARK_QUERY, true);

  const resolved: "light" | "dark" =
    mode === "system" ? (systemDark ? "dark" : "light") : mode;

  // The stylesheet's light-dark() pairs key off `color-scheme`, which the
  // data-theme attribute narrows. Removing the attribute (rather than
  // writing "system") hands the decision back to the browser, so the page
  // keeps following the OS even if this component never re-renders.
  useEffect(() => {
    const root = document.documentElement;
    if (mode === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", mode);
  }, [mode]);

  // Mobile browsers paint their own chrome with this, so a light page under
  // a dark status bar looks broken until it is updated too.
  useEffect(() => {
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", META_COLORS[resolved]);
  }, [resolved]);

  const setMode = useCallback((next: ThemeMode) => {
    setModeState(next);
    persistMode(next);
  }, []);

  const value = useMemo(
    () => ({ mode, resolved, setMode }),
    [mode, resolved, setMode],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
