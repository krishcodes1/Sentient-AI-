import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

/**
 * Top-level error boundary. Without this, any uncaught render error
 * unmounts the entire React tree and leaves the user staring at a blank
 * page. Instead we log the error and offer a reload.
 */
export default class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught render error:", error, errorInfo.componentStack);
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div
        className="flex items-center justify-center min-h-screen p-6"
        style={{ background: "var(--bg-primary)" }}
      >
        <div
          className="w-full max-w-md p-8 rounded-[14px] text-center"
          style={{
            background: "var(--claw-panel)",
            border: "1px solid var(--claw-border)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <h2 className="mb-2">Something went wrong</h2>
          <p className="text-sm mb-6" style={{ color: "var(--text-secondary)" }}>
            An unexpected error occurred
            {this.state.error?.message ? `: ${this.state.error.message}` : "."}
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="px-5 py-2.5 rounded-[10px] text-sm font-semibold"
            style={{
              minHeight: 44,
              background: "var(--accent-primary)",
              color: "var(--text-on-accent)",
            }}
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
