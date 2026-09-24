import { useId } from "react";
import { Download, Loader2, ShieldAlert } from "lucide-react";
import type { CapabilityEffective, CapabilityStatus } from "@/types";

const riskColors: Record<CapabilityStatus["risk"], { text: string; fill: string; border: string }> = {
  low: {
    text: "var(--text-muted)",
    fill: "var(--claw-surface)",
    border: "var(--claw-border)",
  },
  medium: {
    text: "var(--accent-warning)",
    fill: "var(--fill-warning)",
    border: "var(--border-warning)",
  },
  high: {
    text: "var(--accent-danger)",
    fill: "var(--fill-danger)",
    border: "var(--border-danger)",
  },
};

function RiskBadge({ risk }: { risk: CapabilityStatus["risk"] }) {
  const c = riskColors[risk];
  const text = risk.charAt(0).toUpperCase() + risk.slice(1) + " risk";
  return (
    <span
      className="text-[11px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wide"
      style={{ backgroundColor: c.fill, border: `1px solid ${c.border}`, color: c.text }}
    >
      {text}
    </span>
  );
}

function effectiveColor(effective: CapabilityEffective): string {
  if (effective === "on") return "var(--accent-success)";
  if (effective === "blocked") return "var(--accent-danger)";
  return "var(--text-muted)";
}

function statusLine(item: CapabilityStatus): string {
  if (item.effective === "on") return "On";
  if (item.effective === "blocked") return `Blocked — ${item.reason}`;
  return item.reason ? `Off — ${item.reason}` : "Off";
}

interface CapabilityRowProps {
  item: CapabilityStatus;
  editable: boolean;
  busy: boolean;
  onToggle: (key: string, enabled: boolean) => void;
  onRequestAccess: (key: string) => void;
  onInstall: (key: string) => void;
}

function CapabilityRow({ item, editable, busy, onToggle, onRequestAccess, onInstall }: CapabilityRowProps) {
  const headingId = useId();
  const disabled = !editable || busy;
  return (
    <div
      className="rounded-[10px] p-4"
      style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
    >
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 id={headingId} className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
              {item.label}
            </h3>
            <RiskBadge risk={item.risk} />
          </div>
          <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
            {item.description}
          </p>
          <p className="text-xs mt-1.5 font-medium" style={{ color: effectiveColor(item.effective) }}>
            {statusLine(item)}
          </p>
        </div>

        <button
          type="button"
          role="switch"
          aria-checked={item.enabled}
          aria-labelledby={headingId}
          disabled={disabled}
          onClick={() => onToggle(item.key, !item.enabled)}
          className="inline-flex items-center justify-center px-4 rounded-[10px] text-sm font-medium transition-colors disabled:opacity-50"
          style={{
            minHeight: 44,
            background: item.enabled ? "var(--fill-success)" : "var(--claw-panel)",
            border: item.enabled
              ? "1px solid var(--border-success)"
              : "1px solid var(--claw-border)",
            color: item.enabled ? "var(--accent-success)" : "var(--text-muted)",
          }}
        >
          {busy ? (
            <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          ) : item.enabled ? (
            "On"
          ) : (
            "Off"
          )}
        </button>
      </div>

      {(item.can_request_access || (item.install && !item.available)) && (
        <div className="flex items-center gap-3 mt-3 flex-wrap">
          {item.can_request_access && (
            <button
              type="button"
              disabled={disabled}
              onClick={() => onRequestAccess(item.key)}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-[10px] text-xs font-semibold disabled:opacity-50"
              style={{
                background: "var(--accent-glow)",
                border: "1px solid var(--border-accent)",
                color: "var(--accent-primary)",
              }}
            >
              <ShieldAlert className="w-3.5 h-3.5" aria-hidden />
              Grant access
            </button>
          )}
          {item.install && !item.available && (
            <button
              type="button"
              disabled={disabled}
              onClick={() => onInstall(item.key)}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-[10px] text-xs font-semibold disabled:opacity-50"
              style={{
                background: "var(--claw-panel)",
                border: "1px solid var(--claw-border)",
                color: "var(--text-secondary)",
              }}
            >
              <Download className="w-3.5 h-3.5" aria-hidden />
              {/* The size comes from the server, which knows what this
                  install actually fetches; no guess when it has none. */}
              {item.install_size_hint ? `Install (${item.install_size_hint})` : "Install"}
            </button>
          )}
        </div>
      )}

      {item.fix_url && item.fix_steps.length > 0 && (
        <ol
          className="list-decimal pl-5 mt-3 space-y-1 text-xs"
          style={{ color: "var(--text-muted)" }}
        >
          {item.fix_steps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      )}
    </div>
  );
}

export interface CapabilityListProps {
  items: CapabilityStatus[];
  editable: boolean;
  onToggle: (key: string, enabled: boolean) => void;
  onRequestAccess: (key: string) => void;
  onInstall: (key: string) => void;
  /** Key of the capability currently mid-request, if any. Disables its switch and buttons. */
  busyKey?: string | null;
}

/**
 * One row per capability: label, risk badge, description, an on/off switch
 * that reflects the user's *stored preference* (`enabled`), and a status
 * line reflecting what actually happens right now (`effective`) — a
 * capability can be enabled and still be blocked by the OS or a missing
 * install. "Grant access" only appears when the OS itself denied the probe;
 * "Install" only appears when the capability ships an installer and isn't
 * available yet. Read-only viewers get every control disabled — switch,
 * "Grant access" and "Install" alike — instead of the controls being
 * hidden, so the list's shape does not shift between an owner and everyone
 * else.
 */
export default function CapabilityList({
  items,
  editable,
  onToggle,
  onRequestAccess,
  onInstall,
  busyKey = null,
}: CapabilityListProps) {
  return (
    <div className="space-y-4">
      {!editable && (
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          Only the owner can change these.
        </p>
      )}
      {items.map((item) => (
        <CapabilityRow
          key={item.key}
          item={item}
          editable={editable}
          busy={busyKey === item.key}
          onToggle={onToggle}
          onRequestAccess={onRequestAccess}
          onInstall={onInstall}
        />
      ))}
    </div>
  );
}

export interface CapabilityListErrorProps {
  /** Human-readable reason `getCapabilities()` failed. */
  message: string;
  onRetry: () => void;
}

/**
 * Shown in place of the Permissions section when the initial load of the
 * capability list fails, so the user isn't left staring at "Loading
 * permissions…" forever with no way to recover short of a full page reload.
 */
export function CapabilityListError({ message, onRetry }: CapabilityListErrorProps) {
  return (
    <div
      className="rounded-[10px] p-4"
      style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
    >
      <p className="text-sm font-semibold" style={{ color: "var(--accent-danger)" }}>
        Couldn't load permissions
      </p>
      <p className="text-xs mt-1" style={{ color: "var(--text-secondary)" }}>
        {message}
      </p>
      <button
        type="button"
        onClick={onRetry}
        className="inline-flex items-center gap-2 px-3.5 py-2 rounded-[10px] text-xs font-semibold mt-3"
        style={{
          background: "var(--claw-panel)",
          border: "1px solid var(--claw-border)",
          color: "var(--text-secondary)",
        }}
      >
        Retry
      </button>
    </div>
  );
}
