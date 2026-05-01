import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center p-5 bg-[var(--bg-primary)]">
      <div
        className="w-full max-w-[420px] rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-8 text-center"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <p className="text-[12px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-3">
          Error 404
        </p>
        <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)] mb-2">
          Page not found
        </h1>
        <p className="text-[14px] text-[var(--text-secondary)] mb-6 leading-relaxed">
          We couldn&apos;t find the page you were looking for. It may have moved, or the link is wrong.
        </p>
        <Link
          to="/gateway"
          className="inline-flex items-center justify-center px-5 py-2.5 rounded-[10px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] hover:brightness-110 transition-all"
        >
          Back to dashboard
        </Link>
      </div>
    </div>
  );
}
