import { Shield } from "lucide-react";
import { REDUCED_MOTION_QUERY, useMediaQuery } from "@/hooks/useMediaQuery";

type Variant = "emblem" | "animated" | "shield";

interface BrandProps {
  size?: number;
  variant?: Variant;
  rounded?: number;
  /** "" marks the mark decorative — use it wherever the wordmark is adjacent. */
  alt?: string;
}

/**
 * The mark.
 *
 * `sentientai-emblem.png` is deliberately not used: it ships with the mark
 * composited onto an opaque black square, which renders as a black tile on
 * any surface that is not pure black — the sidebar, a light theme, the
 * favicon. `sentientai-logo.png` is the same mark with a real alpha channel
 * and reads correctly on both themes.
 */
const MARK_SRC = "/brand/sentientai-logo.png";

export default function Brand({
  size = 32,
  variant = "emblem",
  rounded = 8,
  alt = "SentientAI",
}: BrandProps) {
  const reducedMotion = useMediaQuery(REDUCED_MOTION_QUERY);

  const common: React.CSSProperties = {
    width: size,
    height: size,
    borderRadius: rounded,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    overflow: "hidden",
    flexShrink: 0,
  };

  // A looping video that cannot be paused is exactly what a reduced-motion
  // preference is asking not to see, so it degrades to the still mark.
  if (variant === "animated" && !reducedMotion) {
    return (
      <div style={common}>
        <video
          src="/brand/sentientai-logo.mp4"
          autoPlay
          loop
          muted
          playsInline
          aria-label={alt || undefined}
          aria-hidden={alt ? undefined : true}
          style={{
            width: "100%",
            height: "100%",
            objectFit: "cover",
            display: "block",
          }}
        />
      </div>
    );
  }

  if (variant === "emblem" || variant === "animated") {
    return (
      <div style={common}>
        <img
          src={MARK_SRC}
          alt={alt}
          style={{
            width: "100%",
            height: "100%",
            objectFit: "contain",
            display: "block",
          }}
        />
      </div>
    );
  }

  return (
    <div
      style={{
        ...common,
        background:
          "linear-gradient(135deg, var(--accent-primary), var(--accent-bright))",
        color: "var(--text-on-accent)",
      }}
      role={alt ? "img" : undefined}
      aria-label={alt || undefined}
      aria-hidden={alt ? undefined : true}
    >
      <Shield size={Math.round(size * 0.55)} strokeWidth={2.25} />
    </div>
  );
}

export function Wordmark({
  height = 20,
  className,
  alt = "SentientAI",
}: {
  height?: number;
  className?: string;
  alt?: string;
}) {
  return (
    <img
      src="/brand/sentientai-wordmark.png"
      alt={alt}
      className={className}
      style={{
        height,
        width: "auto",
        display: "block",
        imageRendering: "auto",
      }}
    />
  );
}
