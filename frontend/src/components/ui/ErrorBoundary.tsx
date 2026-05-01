import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { IS_DEV } from "@/lib/env";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Optional override for the fallback UI. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
  showStack: boolean;
}

declare global {
  interface Window {
    Sentry?: { captureException?: (err: unknown) => void };
  }
}

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, showStack: false };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error, showStack: false };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Always log; in production this is the only signal devs have.
    // eslint-disable-next-line no-console
    console.error("[ErrorBoundary]", error, info);
    if (typeof window !== "undefined" && window.Sentry?.captureException) {
      try {
        window.Sentry.captureException(error);
      } catch {
        /* noop */
      }
    }
  }

  reset = () => {
    this.setState({ error: null, showStack: false });
  };

  toggleStack = () => {
    this.setState((s) => ({ showStack: !s.showStack }));
  };

  render() {
    const { error, showStack } = this.state;
    if (!error) return this.props.children;

    if (this.props.fallback) {
      return this.props.fallback(error, this.reset);
    }

    const stack = error.stack || `${error.name}: ${error.message}`;
    const reportSubject = encodeURIComponent(`SentientAI error: ${error.message.slice(0, 80)}`);
    const reportBody = encodeURIComponent(
      `Hi,\n\nI hit an error in SentientAI:\n\n${error.message}\n\n--- stack ---\n${stack}\n`
    );

    return (
      <div className="min-h-screen flex items-center justify-center p-5 bg-[var(--bg-primary)]">
        <div
          className="w-full max-w-[480px] rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-7 md:p-8"
          style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
          role="alert"
        >
          <div className="flex items-center gap-3 mb-5">
            <div
              className="w-11 h-11 rounded-[12px] flex items-center justify-center"
              style={{ backgroundColor: "rgba(248,113,113,0.15)" }}
              aria-hidden
            >
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </div>
            <div className="min-w-0">
              <h1 className="text-[18px] font-semibold tracking-tight text-[var(--text-primary)]">
                Something went wrong
              </h1>
              <p className="text-[13px] text-[var(--text-muted)]">
                The page hit an unexpected error and couldn&apos;t render.
              </p>
            </div>
          </div>

          <p className="text-[13px] text-[var(--text-secondary)] mb-5 break-words">
            {error.message || "Unknown error"}
          </p>

          <div className="flex items-center gap-2 mb-5">
            <button
              type="button"
              onClick={this.reset}
              className="px-4 py-2 rounded-[10px] text-[13px] font-semibold text-white bg-[var(--accent-primary)] hover:brightness-110 transition-all"
            >
              Try again
            </button>
            <a
              href={`mailto:support@sentientai.local?subject=${reportSubject}&body=${reportBody}`}
              className="px-4 py-2 rounded-[10px] text-[13px] font-medium text-[var(--text-secondary)] border border-[var(--border-subtle)] hover:bg-[rgba(255,255,255,0.06)] transition-colors"
            >
              Report
            </a>
          </div>

          {(IS_DEV || showStack) && (
            <details open={IS_DEV} className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-tertiary)] p-3">
              <summary className="cursor-pointer text-[12px] font-medium text-[var(--text-secondary)] select-none">
                Stack trace
              </summary>
              <pre className="mt-2 text-[11px] leading-snug text-[var(--text-muted)] font-mono whitespace-pre-wrap break-words max-h-[40vh] overflow-auto">
                {stack}
              </pre>
            </details>
          )}
          {!IS_DEV && !showStack && (
            <button
              type="button"
              onClick={this.toggleStack}
              className="text-[12px] font-medium text-[var(--text-muted)] hover:text-[var(--text-secondary)] underline-offset-2 hover:underline"
            >
              Show technical details
            </button>
          )}
        </div>
      </div>
    );
  }
}
