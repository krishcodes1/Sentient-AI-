import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme, type ThemeMode } from "@/theme";

const OPTIONS: { value: ThemeMode; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "system", label: "System", icon: Monitor },
  { value: "dark", label: "Dark", icon: Moon },
];

/**
 * Three-way theme control. "System" is an explicit choice rather than an
 * implicit starting state, so a reader whose OS flips at sunset can opt out
 * of that without having to guess which of two positions means "follow the
 * OS".
 *
 * Built as a radiogroup: the arrow keys move between options natively, and
 * the current theme is announced rather than inferred from a highlight.
 */
export default function ThemeToggle({ className }: { className?: string }) {
  const { mode, setMode } = useTheme();

  return (
    <div
      role="radiogroup"
      aria-label="Color theme"
      className={className}
      style={{
        display: "inline-flex",
        padding: 2,
        gap: 2,
        borderRadius: "var(--radius-md)",
        background: "var(--claw-surface)",
        border: "1px solid var(--claw-border)",
      }}
    >
      {OPTIONS.map(({ value, label, icon: Icon }) => {
        const active = mode === value;
        return (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={`${label} theme`}
            onClick={() => setMode(value)}
            className="inline-flex items-center justify-center rounded-[8px] transition-colors"
            style={{
              // Sized rather than padded: three .tap-target pseudo-elements
              // sitting 2px apart would overlap and swallow each other's
              // taps, so the segments carry the 44px width themselves.
              width: 44,
              height: 40,
              background: active ? "var(--accent-glow)" : "transparent",
              color: active ? "var(--accent-primary)" : "var(--text-muted)",
              border: `1px solid ${active ? "var(--border-accent)" : "transparent"}`,
            }}
          >
            <Icon size={14} strokeWidth={2} aria-hidden />
          </button>
        );
      })}
    </div>
  );
}
