/**
 * CapabilitySettings: the per-capability settings under a Permissions row — the spending caps of
 * `purchases`, the shared budgets of `scheduled_tasks`, the minutes and days of
 * `video_transcripts` and the per-person limits of `knowledge_base` — each field saved on blur.
 *
 * Why it exists: Turning a capability on is only half of the decision; how much it may spend or
 * keep is the other half and belongs right under that switch, where the messages that say "the
 * owner can change it in Settings → Permissions" send the owner. A capability without settings
 * renders nothing, so the list stays one component.
 */

import { useId, useState } from "react";
import type { CapabilityStatus } from "@/types";

// How a field's number is shown and entered. The server stores whole numbers from 1 to 10,000
// (backend/services/installation.py SETTING_MIN / SETTING_MAX) and refuses anything else, so each
// kind keeps the page to the same bounds: "usd" is whole dollars, "cents" is stored in cents and
// shown in dollars ($0.01 to $100.00), "count" is a plain whole number.
type Unit = "usd" | "cents" | "count";

interface SettingField {
  key: string;
  label: string;
  /** The backend default; the server merges defaults into `settings`, so this only covers a
   * response that predates them. */
  fallback: number;
  unit: Unit;
}

interface SettingsGroup {
  fields: SettingField[];
  note: string;
}

// Keep each list in step with its backend defaults: PURCHASE_SETTINGS_DEFAULTS
// (services/capabilities/purchases.py), SCHEDULE_SETTINGS_DEFAULTS
// (services/capabilities/scheduled_tasks.py), VIDEO_SETTINGS_DEFAULTS
// (services/capabilities/video_transcripts.py) and KNOWLEDGE_SETTINGS_DEFAULTS
// (services/knowledge/limits.py).
const SETTINGS: Record<string, SettingsGroup> = {
  purchases: {
    fields: [
      { key: "per_purchase_cap_usd", label: "Per purchase (USD)", fallback: 25, unit: "usd" },
      { key: "per_day_cap_usd", label: "Per day (USD)", fallback: 50, unit: "usd" },
    ],
    note:
      "Crawler refuses a checkout above these. The per-day figure counts every purchase whose " +
      "card was submitted in the last 24 hours, whether or not the shop confirmed it.",
  },
  scheduled_tasks: {
    fields: [
      { key: "run_cap_cents", label: "Per run (USD)", fallback: 5, unit: "cents" },
      { key: "day_cap_cents", label: "Per 24 hours (USD)", fallback: 25, unit: "cents" },
      { key: "runs_per_day", label: "Runs per 24 hours", fallback: 24, unit: "count" },
    ],
    note:
      "Scheduled tasks and app-trigger task runs share these budgets for runs made while you are " +
      "away. A run stops at its per-run budget; once the last 24 hours reach the day's budget or " +
      "run count, runs are skipped (with one message) until they are under it again.",
  },
  video_transcripts: {
    fields: [
      { key: "video_minutes_per_call", label: "Minutes per request", fallback: 45, unit: "count" },
      { key: "video_minutes_per_day", label: "Minutes per day", fallback: 240, unit: "count" },
      { key: "keep_transcripts_days", label: "Keep transcripts (days)", fallback: 14, unit: "count" },
    ],
    note:
      "Minutes of YouTube video the chat's Gemini model watches: at most this much per request " +
      "and per day (the day resets at 00:00 UTC). Saved transcripts are deleted after the days " +
      "kept.",
  },
  knowledge_base: {
    fields: [
      { key: "documents_per_user", label: "Documents per person", fallback: 400, unit: "count" },
      { key: "text_mb_per_user", label: "Text per person (MB)", fallback: 25, unit: "count" },
      { key: "file_mb", label: "Largest file (MB)", fallback: 25, unit: "count" },
      {
        key: "embed_ktokens_per_day",
        label: "Meaning index per day (thousand tokens)",
        fallback: 1000,
        unit: "count",
      },
    ],
    note:
      "Limits for each person's saved documents. The last one caps how much text a day is sent " +
      "to build the search-by-meaning index.",
  },
};

// The server's bounds (SETTING_MIN / SETTING_MAX), in each unit.
const SETTING_MIN = 1;
const SETTING_MAX = 10000;
const BOUNDS: Record<Unit, string> = {
  usd: "Enter a whole number of dollars between $1 and $10,000.",
  cents: "Enter an amount between $0.01 and $100.00.",
  count: "Enter a whole number from 1 to 10,000.",
};

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

/** What the field shows for a stored value. */
function shown(stored: number, unit: Unit): string {
  return unit === "cents" ? (stored / 100).toFixed(2) : String(stored);
}

/** The stored value for what was typed, or null when the server would refuse it. */
function parsed(text: string, unit: Unit): number | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  const value = Number(trimmed);
  if (!Number.isFinite(value)) return null;
  // Dollars and cents both end up a whole number of the stored unit; an
  // amount with a fraction of a cent (or of a dollar, or of a count) is refused.
  const scaled = unit === "cents" ? value * 100 : value;
  const whole = Math.round(scaled);
  if (Math.abs(scaled - whole) > 1e-6) return null;
  return whole >= SETTING_MIN && whole <= SETTING_MAX ? whole : null;
}

interface SettingInputProps {
  field: SettingField;
  stored: number;
  editable: boolean;
  onCommit: (value: number) => void;
}

function SettingInput({ field, stored, editable, onCommit }: SettingInputProps) {
  const id = useId();
  const errorId = useId();
  // null while the field is not being edited, so the value the server holds
  // shows through (including one it just saved) without an effect copying it
  // into local state; a draft exists only between the first keystroke and blur.
  const [draft, setDraft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const money = field.unit !== "count";

  const commit = () => {
    if (draft === null) return;
    setDraft(null);
    const value = parsed(draft, field.unit);
    if (value === null) {
      setError(BOUNDS[field.unit]);
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
        {field.label}
      </label>
      <div className="relative">
        {money && (
          <span
            aria-hidden
            className="absolute left-3 top-1/2 -translate-y-1/2 text-sm"
            style={{ color: "var(--text-muted)" }}
          >
            $
          </span>
        )}
        <input
          id={id}
          type="number"
          inputMode={field.unit === "count" ? "numeric" : "decimal"}
          min={field.unit === "cents" ? SETTING_MIN / 100 : SETTING_MIN}
          max={field.unit === "cents" ? SETTING_MAX / 100 : SETTING_MAX}
          step={field.unit === "cents" ? 0.01 : 1}
          value={draft ?? shown(stored, field.unit)}
          disabled={!editable}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? errorId : undefined}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
          }}
          className={`w-full ${money ? "pl-7" : "pl-3"} pr-3 py-2 rounded-[10px] text-sm outline-none mono-num disabled:opacity-50`}
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
 * The settings under a capability's row. Each field saves on its own when it
 * loses focus (or on Enter) and only when its value actually changed; a blank
 * entry, a fraction the unit cannot hold, or a value outside the server's
 * bounds is refused here and the stored value shown again, so the server
 * never sees a value it would 422.
 */
export default function CapabilitySettings({ item, editable, onChange }: CapabilitySettingsProps) {
  const group = SETTINGS[item.key];
  if (!group) return null;
  return (
    <div className="mt-3">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {group.fields.map((field) => (
          <SettingInput
            key={field.key}
            field={field}
            stored={storedNumber(item.settings, field.key, field.fallback)}
            editable={editable}
            onCommit={(value) => onChange({ [field.key]: value })}
          />
        ))}
      </div>
      <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
        {group.note}
      </p>
    </div>
  );
}
