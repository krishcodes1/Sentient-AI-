/**
 * CapabilitySettings: the per-capability settings under a Permissions row — for `purchases`, the
 * two spending caps ("Per purchase (USD)" and "Per day (USD)"), each saved on blur.
 *
 * Why it exists: Turning "Buy things for me" on is only half of the decision; how much Crawler may
 * spend is the other half and belongs right under that switch. Only `purchases` has settings, so
 * the component renders nothing for every other row, and the list stays one component.
 */

import { useId, useState } from "react";
import type { CapabilityStatus } from "@/types";

// Keep in step with PURCHASE_SETTINGS_DEFAULTS in backend/services/capabilities/purchases.py.
// The server merges the defaults into `settings`; these only cover a response that predates them.
const PURCHASE_CAPS = [
  { key: "per_purchase_cap_usd", label: "Per purchase (USD)", fallback: 25 },
  { key: "per_day_cap_usd", label: "Per day (USD)", fallback: 50 },
];

// The server's bounds for a cap (backend/services/installation.py SETTING_MIN
// / SETTING_MAX; a whole number of dollars, so a fraction is refused there
// too), so a value it would refuse never leaves the page.
const CAP_MIN = 1;
const CAP_MAX = 10000;
const CAP_BOUNDS = "Enter a whole number of dollars between $1 and $10,000.";

const inputStyle = {
  background: "var(--bg-input)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

function storedNumber(
  settings: Record<string, unknown> | undefined,
  key: string,
  fallback: number,
): number {
  const value = settings?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

interface CapFieldProps {
  label: string;
  stored: number;
  editable: boolean;
  onCommit: (value: number) => void;
}

function CapField({ label, stored, editable, onCommit }: CapFieldProps) {
  const id = useId();
  const errorId = useId();
  // null while the field is not being edited, so the value the server holds
  // shows through (including one it just saved) without an effect copying it
  // into local state; a draft exists only between the first keystroke and blur.
  const [draft, setDraft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const commit = () => {
    if (draft === null) return;
    setDraft(null);
    const text = draft.trim();
    const value = Number(text);
    if (text === "" || !Number.isInteger(value) || value < CAP_MIN || value > CAP_MAX) {
      setError(CAP_BOUNDS);
      return;
    }
    setError(null);
    // A blur that changed nothing must not send a request — the row's busy
    // state would flash on every tab through the form.
    if (value !== stored) onCommit(value);
  };

  return (
    <div>
      <label
        htmlFor={id}
        className="block text-xs font-medium mb-1"
        style={{ color: "var(--text-secondary)" }}
      >
        {label}
      </label>
      <div className="relative">
        <span
          aria-hidden
          className="absolute left-3 top-1/2 -translate-y-1/2 text-sm"
          style={{ color: "var(--text-muted)" }}
        >
          $
        </span>
        <input
          id={id}
          type="number"
          inputMode="decimal"
          min={CAP_MIN}
          max={CAP_MAX}
          step={1}
          value={draft ?? String(stored)}
          disabled={!editable}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? errorId : undefined}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
          }}
          className="w-full pl-7 pr-3 py-2 rounded-[10px] text-sm outline-none mono-num disabled:opacity-50"
          style={inputStyle}
        />
      </div>
      {error && (
        <p id={errorId} role="alert" className="text-xs mt-1" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
    </div>
  );
}

export interface CapabilitySettingsProps {
  item: CapabilityStatus;
  editable: boolean;
  /** Called with the one field that changed, e.g. `{ per_day_cap_usd: 80 }`. */
  onChange: (patch: Record<string, number>) => void;
}

/**
 * The spending caps under the "Buy things for me" row. Each field saves on
 * its own when it loses focus (or on Enter) and only when its value actually
 * changed; a blank or fractional entry, or one outside $1 to $10,000, is
 * refused here and the stored value shown again, so the server never sees an
 * amount it would 422.
 */
export default function CapabilitySettings({ item, editable, onChange }: CapabilitySettingsProps) {
  if (item.key !== "purchases") return null;
  return (
    <div className="mt-3">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {PURCHASE_CAPS.map((cap) => (
          <CapField
            key={cap.key}
            label={cap.label}
            stored={storedNumber(item.settings, cap.key, cap.fallback)}
            editable={editable}
            onCommit={(value) => onChange({ [cap.key]: value })}
          />
        ))}
      </div>
      <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
        Crawler refuses a checkout above these. The per-day figure counts
        every purchase whose card was submitted in the last 24 hours, whether
        or not the shop confirmed it.
      </p>
    </div>
  );
}
