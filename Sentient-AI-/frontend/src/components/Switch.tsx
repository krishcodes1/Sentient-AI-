/**
 * Switch: the app's one on/off control, a pill track with a sliding knob (role="switch").
 *
 * Why it exists: Settings, Server, Tool rules and Memory each drew their own, three of them as a
 * 44px "On"/"Off" button that wrapped onto its own line under long descriptions and repeated the
 * status already written beside it. One small control keeps every list of switches compact and
 * reading alike. The knob shows a spinner while the change is saving.
 */

import type { ButtonHTMLAttributes } from "react";
import { Loader2 } from "lucide-react";

type SwitchProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "onChange" | "role" | "type"> & {
  checked: boolean;
  onChange: (next: boolean) => void;
  /** Saving: the knob spins and the switch takes no clicks. */
  busy?: boolean;
};

export default function Switch({ checked, onChange, busy = false, disabled, className = "", ...rest }: SwitchProps) {
  return (
    <button
      {...rest}
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled || busy}
      onClick={() => onChange(!checked)}
      className={`tap-target relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
      style={{
        // backgroundColor, not `background`: jsdom cannot re-parse a shorthand holding var().
        backgroundColor: checked
          ? "var(--accent-success)"
          : "color-mix(in srgb, var(--text-muted) 55%, transparent)",
      }}
    >
      <span
        aria-hidden
        className="inline-flex h-5 w-5 items-center justify-center rounded-full transition-transform"
        style={{
          backgroundColor: "#fff",
          boxShadow: "0 1px 2px rgba(0,0,0,0.25)",
          transform: checked ? "translateX(22px)" : "translateX(2px)",
        }}
      >
        {busy && <Loader2 className="h-3 w-3 animate-spin" style={{ color: "#5c534b" }} />}
      </span>
    </button>
  );
}
