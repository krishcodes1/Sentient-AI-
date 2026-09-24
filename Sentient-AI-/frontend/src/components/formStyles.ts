/**
 * Shared class strings and style objects for the setup wizard's and Settings' forms, plus the
 * errorText helper that prefers a server message over a fallback.
 *
 * Why it exists: ProviderForm, ServerSettings and Setup must read alike, and keeping these in a
 * non-component module keeps Fast Refresh working for all of them.
 *
 * Form styling shared by the setup wizard and the forms it lends to
 * Settings (ProviderForm), so the two screens read alike. A plain module
 * rather than a component file, so fast refresh keeps working for both.
 */

export const panelStyle = {
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  boxShadow: "var(--shadow-card)",
};
export const inputCls = "w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none";
export const inputStyle = {
  background: "var(--bg-input)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};
export const labelCls = "block text-sm font-medium mb-1.5 text-[var(--text-secondary)]";
export const primaryCls =
  "inline-flex items-center justify-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50";
export const primaryStyle = { minHeight: 44, background: "var(--accent-primary)", color: "var(--text-on-accent)" };
export const secondaryCls =
  "inline-flex items-center justify-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50";
export const secondaryStyle = {
  minHeight: 44,
  background: "transparent",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

/** The server's message when there is one (a 409's detail arrives verbatim), else `fallback`. */
export function errorText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}
