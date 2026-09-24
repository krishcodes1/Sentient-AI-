/**
 * Shared building blocks of the setup window: the brand header, buttons with a busy state,
 * status messages, safe external links and the small SVG icons.
 *
 * Why it exists: Every screen uses the same 44 px buttons, spinner-in-button busy state,
 * role="status" message line and https-only links (the look and behaviour of
 * installer/page.html). Keeping them here stops the screens drifting apart.
 */

import type { ButtonHTMLAttributes, ReactNode } from "react";
import { forwardRef } from "react";
import { httpsUrl } from "../format";

export function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
    </svg>
  );
}

export function CheckIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M5 10.5l3.2 3.2L15 6.8" />
    </svg>
  );
}

export function CrossIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M6.5 6.5l7 7M13.5 6.5l-7 7" />
    </svg>
  );
}

export function WarnIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M10 5.5v5.5M10 14.3v.2" />
    </svg>
  );
}

export function InfoIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M10 9.2v5M10 5.8v.2" />
    </svg>
  );
}

export function DashIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M6.5 10h7" />
    </svg>
  );
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

export function Brand({ badge }: { badge: string }) {
  return (
    <div className="brand">
      <span className="mark" aria-hidden="true">
        <ShieldIcon />
      </span>
      <span className="brand-name">Crawler AI</span>
      <span className="badge">{badge}</span>
    </div>
  );
}

type Variant = "primary" | "secondary" | "ghost";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  small?: boolean;
  busy?: boolean;
  /** Label shown next to the spinner while `busy`. */
  busyLabel?: string;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "primary", small = false, busy = false, busyLabel, className, children, disabled, ...rest },
  ref,
) {
  const classes = ["btn", `btn-${variant}`, small ? "btn-small" : "", className ?? ""]
    .filter(Boolean)
    .join(" ");
  return (
    <button
      type="button"
      {...rest}
      ref={ref}
      className={classes}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
    >
      {busy ? (
        <>
          <Spinner />
          {busyLabel ?? "Working…"}
        </>
      ) : (
        children
      )}
    </button>
  );
});

export type Tone = "ok" | "bad" | "info";

export interface Message {
  tone: Tone;
  text: ReactNode;
}

/** A polite live-region line; renders nothing (but keeps the region) when empty. */
export function StatusMessage({ message, className = "msg" }: { message: Message | null; className?: string }) {
  return (
    <p className={className} role="status" data-tone={message?.tone ?? "info"} hidden={!message}>
      {message?.text}
    </p>
  );
}

/**
 * A link to a web page outside the app, only ever https. The Rust side opens target=_blank
 * links in the default browser; the address stays visible as text so it can be copied either way.
 */
export function ExternalLink({ href, children }: { href: string | null | undefined; children: ReactNode }) {
  const safe = httpsUrl(href);
  if (!safe) return <>{children}</>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}
