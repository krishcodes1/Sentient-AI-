import { createContext, useContext } from "react";

export type ThemeMode = "light" | "dark" | "system";

export interface ThemeContextValue {
  /** What the user picked, including "follow the OS". */
  mode: ThemeMode;
  /** What that currently resolves to — what is actually on screen. */
  resolved: "light" | "dark";
  setMode: (mode: ThemeMode) => void;
}

/**
 * Filled by <ThemeProvider> in src/theme.tsx. Lives here, apart from the
 * provider, so that file exports only a component and keeps Fast Refresh.
 * Import it and the provider through the "@/" alias only — see main.tsx for
 * how a second specifier splits this into two contexts.
 */
export const ThemeContext = createContext<ThemeContextValue | null>(null);

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used inside <ThemeProvider>");
  }
  return ctx;
}
