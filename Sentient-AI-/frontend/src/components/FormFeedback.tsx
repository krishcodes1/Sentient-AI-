import type { ReactNode } from "react";
import { CheckCircle2, XCircle } from "lucide-react";

/** A blocking error at the top of a form. */
export function ErrorAlert({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      className="mb-4 px-3 py-2.5 rounded-[8px] text-sm"
      style={{
        background: "var(--fill-danger)",
        color: "var(--accent-danger)",
        border: "1px solid var(--border-danger)",
      }}
    >
      {children}
    </div>
  );
}

/** The outcome of a test or save, next to the button that ran it. */
export function ResultLine({ ok, children }: { ok: boolean; children: ReactNode }) {
  const Icon = ok ? CheckCircle2 : XCircle;
  return (
    <p
      // A failure needs an assertive announcement (role="alert") since it
      // usually means the user must go fix something; a success is a
      // low-priority status update.
      role={ok ? "status" : "alert"}
      className="inline-flex items-start gap-1.5 text-sm"
      style={{ color: ok ? "var(--accent-success)" : "var(--accent-danger)" }}
    >
      <Icon className="w-4 h-4 mt-0.5 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  );
}
