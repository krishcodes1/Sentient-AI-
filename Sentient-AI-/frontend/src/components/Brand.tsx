import { Shield } from "lucide-react";

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
 * and reads correctly on both themes, and (unlike the other brand assets)
 * does not bake in the old "SENTIENTAI" name.
 *
 * `sentientai-logo.mp4` — the video the "animated" variant used to play in
 * dark mode — does bake the old name into every frame, so it is not used;
 * "animated" renders this same still mark instead until new artwork exists.
 */
// TODO(brand): replace with Crawler AI artwork (including re-enabling an
// animated variant once a video without the old name exists).
const MARK_SRC = "/brand/sentientai-logo.png";

export default function Brand({
  size = 32,
  variant = "emblem",
  rounded = 8,
  alt = "Crawler AI",
}: BrandProps) {
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
  alt = "Crawler AI",
}: {
  height?: number;
  className?: string;
  alt?: string;
}) {
  // `sentientai-wordmark.png` still renders the old "SENTIENTAI" name, so
  // until new artwork exists this renders styled text instead — reusing the
  // `.eyebrow` treatment (mono, uppercase, letter-spaced) and design-token
  // colors rather than a new image asset.
  // TODO(brand): replace with Crawler AI artwork
  return (
    <span
      className={["eyebrow", className].filter(Boolean).join(" ")}
      aria-label={alt || undefined}
      aria-hidden={alt ? undefined : true}
      style={{
        display: "block",
        lineHeight: 1,
        fontSize: height * 0.85,
        color: "var(--text-primary)",
        whiteSpace: "nowrap",
      }}
    >
      Crawler AI
    </span>
  );
}
