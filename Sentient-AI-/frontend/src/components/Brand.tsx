/**
 * Brand mark and wordmark components: the Crawler AI knot emblem and the
 * "Crawler AI" worm wordmark.
 *
 * Why it exists: Login, Layout, Sidebar and Setup all show the brand, and only this file knows
 * which asset files back it.
 *
 * Assets in public/brand are transparent PNGs cut from the cream-background
 * originals. The wordmark ships twice — dark ink for the light theme, light
 * ink for the dark theme — and globals.css shows the one matching the
 * resolved theme (`.wordmark-light` / `.wordmark-dark`).
 */

const MARK_SRC = "/brand/crawler-emblem.png";

interface BrandProps {
  size?: number;
  rounded?: number;
  /** "" marks the mark decorative — use it wherever the wordmark is adjacent. */
  alt?: string;
}

export default function Brand({ size = 32, rounded = 8, alt = "Crawler AI" }: BrandProps) {
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: rounded,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        overflow: "hidden",
        flexShrink: 0,
      }}
    >
      <img
        src={MARK_SRC}
        alt={alt}
        style={{ width: "100%", height: "100%", objectFit: "contain", display: "block" }}
      />
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
  const img: React.CSSProperties = { height, width: "auto", maxWidth: "100%" };
  // One accessible name on the wrapper; the two images are interchangeable
  // art, and only one is ever displayed.
  return (
    <span
      className={className}
      role={alt ? "img" : undefined}
      aria-label={alt || undefined}
      aria-hidden={alt ? undefined : true}
      style={{ display: "inline-flex", lineHeight: 0, minWidth: 0 }}
    >
      <img src="/brand/crawler-wordmark.png" alt="" className="wordmark-light" style={img} />
      <img src="/brand/crawler-wordmark-dark.png" alt="" className="wordmark-dark" style={img} />
    </span>
  );
}
