import { AlertTriangle, RefreshCw } from "lucide-react";

interface ErrorBannerProps {
  /** Either an Error instance or a string message. */
  error?: unknown;
  /** Plain message override; takes precedence over `error`. */
  message?: string;
  /** Called when the user clicks the retry button. Hidden if not supplied. */
  onRetry?: () => void;
  /** Pending state for retry button. */
  retrying?: boolean;
  className?: string;
  /** Optional title; default "Something went wrong". */
  title?: string;
}

function extractMessage(error: unknown): string {
  if (!error) return "An unknown error occurred.";
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (typeof error === "object" && "message" in error) {
    const m = (error as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "An unknown error occurred.";
}

/**
 * Inline error banner with optional retry. Used at the top of a page or
 * inside a card when a query fails.
 */
export function ErrorBanner({
  error,
  message,
  onRetry,
  retrying = false,
  className = "",
  title = "Something went wrong",
}: ErrorBannerProps) {
  const text = message ?? extractMessage(error);

  return (
    <div
      role="alert"
      className={[
        "rounded-[12px] border border-[rgba(255,69,58,0.3)] bg-[rgba(255,69,58,0.08)]",
        "px-4 py-3 flex items-start gap-3",
        className,
      ].join(" ")}
    >
      <AlertTriangle
        className="w-5 h-5 text-[var(--accent-danger)] shrink-0 mt-0.5"
        strokeWidth={2}
        aria-hidden="true"
      />
      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-semibold text-[var(--accent-danger)]">{title}</p>
        <p className="text-[13px] text-[var(--text-secondary)] mt-0.5 break-words">{text}</p>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          disabled={retrying}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] text-[12px] font-semibold border border-[var(--accent-danger)] text-[var(--accent-danger)] hover:bg-[rgba(255,69,58,0.1)] transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${retrying ? "animate-spin" : ""}`} strokeWidth={2} />
          Retry
        </button>
      )}
    </div>
  );
}

export default ErrorBanner;
