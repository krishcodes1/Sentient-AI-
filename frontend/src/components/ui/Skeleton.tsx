/**
 * Animated pulse skeleton block. Used across Dashboard, AuditLogs, Channels,
 * Settings, and Chat while data is loading.
 */

interface SkeletonProps {
  /** Tailwind width classes, e.g. "w-32" or "w-full". */
  width?: string;
  /** Tailwind height classes, e.g. "h-4" or "h-12". */
  height?: string;
  /** Additional class names to merge in. */
  className?: string;
  /** Optional inline style. */
  style?: React.CSSProperties;
  /** Render as inline-block instead of block. */
  inline?: boolean;
  /** Render as a circle (e.g. avatar). */
  circle?: boolean;
}

export function Skeleton({
  width = "w-full",
  height = "h-4",
  className = "",
  style,
  inline = false,
  circle = false,
}: SkeletonProps) {
  const shape = circle ? "rounded-full" : "rounded-md";
  const display = inline ? "inline-block" : "block";
  return (
    <span
      aria-hidden="true"
      className={[
        display,
        shape,
        width,
        height,
        "animate-pulse bg-[var(--bg-tertiary)]",
        className,
      ].join(" ")}
      style={{
        backgroundImage:
          "linear-gradient(90deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.08) 50%, rgba(255,255,255,0.04) 100%)",
        backgroundSize: "200% 100%",
        ...style,
      }}
    />
  );
}

/** A vertically stacked group of skeleton lines, decreasing in width. */
export function SkeletonLines({
  lines = 3,
  className = "",
}: {
  lines?: number;
  className?: string;
}) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton
          key={i}
          height="h-3"
          width={i === lines - 1 ? "w-2/3" : "w-full"}
        />
      ))}
    </div>
  );
}

export default Skeleton;
