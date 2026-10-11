/**
 * A link to a page outside Crawler (a provider's token page, a setup guide, an API key console)
 * that opens in a new tab, with the external-link icon.
 *
 * Why it exists: the Connectors page and the AI provider form both send people to provider pages,
 * and every such link must follow the same safety rules: only an absolute http(s) URL is ever
 * rendered (never javascript: or data:, whatever a response carried), and the new tab gets no
 * handle on this window (rel="noopener noreferrer"). The desktop app hands target="_blank" links
 * to the system browser. Depends on externalUrl in pages/connectorCatalog.ts; no network.
 */

import type { CSSProperties, ReactNode } from "react";
import { ExternalLink } from "lucide-react";
import { externalUrl } from "@/pages/connectorCatalog";

// "action" is the prominent tinted button a form leads with (the token
// page); "inline" is a small underlined text link.
const ACTION_STYLE: CSSProperties = {
  minHeight: 44,
  background: "var(--accent-glow)",
  color: "var(--accent-primary)",
  border: "1px solid var(--border-accent)",
};

// Every link here says it opens a new tab, to screen readers too (the icon is decorative).
const NEW_TAB = "(opens in a new tab)";

export default function ExternalAnchor({
  href,
  children,
  label,
  variant = "inline",
}: {
  href: string | null | undefined;
  children: ReactNode;
  /** Accessible name, when the visible text alone would be ambiguous. Start it with the visible
   *  text (voice control matches on it); the new-tab cue is added here. */
  label?: string;
  variant?: "inline" | "action";
}) {
  const url = externalUrl(href);
  if (!url) return null;
  const action = variant === "action";
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={label ? `${label} ${NEW_TAB}` : undefined}
      className={
        action
          ? "inline-flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold transition-colors"
          : "inline-flex items-center gap-1 text-xs font-medium underline underline-offset-2"
      }
      style={action ? ACTION_STYLE : { color: "var(--accent-primary)" }}
    >
      {children}
      {/* The space sits outside the span: accessible names trim each element's text. */}
      {!label && " "}
      {!label && <span className="sr-only">{NEW_TAB}</span>}
      <ExternalLink className={action ? "w-4 h-4" : "w-3 h-3"} aria-hidden />
    </a>
  );
}
