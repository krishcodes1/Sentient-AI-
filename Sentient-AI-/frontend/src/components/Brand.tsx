import { Shield } from "lucide-react";

type Variant = "emblem" | "animated" | "shield";

interface BrandProps {
  size?: number;
  variant?: Variant;
  rounded?: number;
}

export default function Brand({
  size = 32,
  variant = "emblem",
  rounded = 8,
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

  if (variant === "animated") {
    return (
      <div style={{ ...common, background: "#000" }}>
        <video
          src="/brand/sentientai-logo.mp4"
          autoPlay
          loop
          muted
          playsInline
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

  if (variant === "emblem") {
    return (
      <div style={{ ...common, background: "transparent" }}>
        <img
          src="/brand/sentientai-emblem.png"
          alt="SentientAI"
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
        background: "linear-gradient(135deg, #22d3ee, #5eead4)",
        color: "#0a0a0b",
      }}
    >
      <Shield size={Math.round(size * 0.55)} strokeWidth={2.25} />
    </div>
  );
}

export function Wordmark({
  height = 20,
  className,
}: {
  height?: number;
  className?: string;
}) {
  return (
    <img
      src="/brand/sentientai-wordmark.png"
      alt="SentientAI"
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