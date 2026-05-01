import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}

/**
 * Dark-themed empty state. Use inside cards/panels where data is missing.
 *
 *   <EmptyState
 *     icon={MessageSquare}
 *     title="No conversations yet"
 *     description="Start one with the New Chat button."
 *     action={<button onClick={...}>New chat</button>}
 *   />
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className = "",
}: EmptyStateProps) {
  return (
    <div
      className={[
        "rounded-[var(--radius-xl,12px)] border border-dashed border-[var(--claw-border,rgba(255,255,255,0.12))]",
        "bg-[var(--claw-surface,var(--bg-tertiary))] px-6 py-10 text-center",
        className,
      ].join(" ")}
      role="status"
    >
      {Icon && (
        <Icon
          className="w-8 h-8 text-[var(--text-muted)] mx-auto mb-3"
          strokeWidth={1.5}
          aria-hidden="true"
        />
      )}
      <p className="text-[15px] font-medium text-[var(--text-primary)] max-w-sm mx-auto">
        {title}
      </p>
      {description && (
        <p className="mt-1 text-[13px] text-[var(--text-muted)] max-w-sm mx-auto leading-relaxed">
          {description}
        </p>
      )}
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  );
}

export default EmptyState;
