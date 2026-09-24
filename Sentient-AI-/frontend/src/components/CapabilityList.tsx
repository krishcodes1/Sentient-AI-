import type { CapabilityStatus } from "@/types";

// One list of switchable capabilities, rendered identically by the /setup
// wizard and the Settings > Permissions section so the two can never
// disagree about what a capability is or why it is blocked.

interface CapabilityListProps {
  items: CapabilityStatus[];
  editable: boolean;
  onToggle: (key: string, enabled: boolean) => void;
  onRequestAccess: (key: string) => void;
  onInstall: (key: string) => void;
  busyKey?: string | null;
}

const RISK_COLOR: Record<CapabilityStatus["risk"], string> = {
  high: "var(--accent-danger)",
  medium: "var(--accent-warning)",
  low: "var(--text-muted)",
};

function statusLine(c: CapabilityStatus): { text: string; color: string } {
  if (c.effective === "on") return { text: "On", color: "var(--accent-success)" };
  if (c.effective === "blocked") {
    return { text: `Blocked — ${c.reason}`, color: "var(--accent-danger)" };
  }
  return { text: c.reason ? `Off — ${c.reason}` : "Off", color: "var(--text-muted)" };
}

const secondaryBtn = "px-3 rounded-[10px] text-sm font-semibold disabled:opacity-50";
const secondaryStyle = {
  minHeight: 44,
  background: "transparent",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

export default function CapabilityList({
  items,
  editable,
  onToggle,
  onRequestAccess,
  onInstall,
  busyKey = null,
}: CapabilityListProps) {
  return (
    <div className="space-y-3">
      {!editable && (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Only the owner can change these.
        </p>
      )}
      <ul className="space-y-3">
        {items.map((c) => {
          const busy = busyKey === c.key;
          const status = statusLine(c);
          return (
            <li
              key={c.key}
              className="rounded-[10px] p-4"
              style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-sm font-semibold m-0">{c.label}</h3>
                    <span className="mono-tag" style={{ color: RISK_COLOR[c.risk] }}>
                      {c.risk} risk
                    </span>
                  </div>
                  <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
                    {c.description}
                  </p>
                  <p className="text-xs mt-1.5" style={{ color: status.color }}>
                    {status.text}
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={c.enabled}
                  aria-label={c.label}
                  disabled={!editable || busy}
                  onClick={() => onToggle(c.key, !c.enabled)}
                  className="shrink-0 inline-flex items-center justify-center disabled:opacity-50"
                  style={{ minHeight: 44, minWidth: 52 }}
                >
                  <span
                    aria-hidden
                    className="relative inline-block rounded-full transition-colors"
                    style={{
                      width: 40,
                      height: 22,
                      background: c.enabled ? "var(--accent-primary)" : "var(--fill-neutral)",
                      border: "1px solid var(--claw-border)",
                    }}
                  >
                    <span
                      className="absolute top-[2px] rounded-full transition-all"
                      style={{
                        width: 16,
                        height: 16,
                        left: c.enabled ? 20 : 2,
                        background: "var(--text-on-accent)",
                      }}
                    />
                  </span>
                </button>
              </div>

              {c.fix_steps.length > 0 && c.effective === "blocked" && (
                <ol
                  className="list-decimal pl-5 mt-2 space-y-0.5 text-xs"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {c.fix_steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
              )}

              {editable && (c.can_request_access || (c.install && !c.available)) && (
                <div className="flex gap-2 flex-wrap mt-3">
                  {c.can_request_access && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => onRequestAccess(c.key)}
                      className={secondaryBtn}
                      style={secondaryStyle}
                    >
                      Grant access
                    </button>
                  )}
                  {c.install && !c.available && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => onInstall(c.key)}
                      className={secondaryBtn}
                      style={secondaryStyle}
                    >
                      Install (~300 MB)
                    </button>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
