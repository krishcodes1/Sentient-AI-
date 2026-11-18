/**
 * The Permissions screen: a protection level to pick (how much Crawler does on its own), a plain
 * summary of what it can and can't do, anything that needs setup, and everyday categories
 * that open one at a time into their switches. Each row reads at a glance (name, risk, a one-line
 * summary, small pills such as "Asks first" or an amber "Audio goes to your AI provider", and for
 * one that is on but not working a "Needs setup" pill with its one fix: Grant access, Install, Add
 * key or Open Connectors); its info button opens three short facts (on its own / asks you first /
 * your data), what setup is missing, fix steps and limits (the purchase caps…). Also the panel shown when the
 * list fails to load.
 *
 * Why it exists: Settings and the setup wizard's Permissions step show the same list. It used to
 * be forty full-width cards in one column; now most people make one choice and never scroll, and
 * anyone fine-tuning is one click from any switch.
 */

import { useId, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  ChevronRight,
  Clock,
  CloudUpload,
  Download,
  Hand,
  Info,
  KeyRound,
  Lock,
  Monitor,
  Play,
  Plug,
  ShieldAlert,
  SlidersHorizontal,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import CapabilitySettings from "@/components/CapabilitySettings";
import ConfirmDialog from "@/components/ConfirmDialog";
import Switch from "@/components/Switch";
import {
  byRisk,
  groupByCategory,
  LEVELS,
  aboutOf,
  levelPatch,
  summaryOf,
  type ChipKind,
  type Category,
  type CategoryId,
  type Level,
} from "@/components/capabilityGroups";
import type { CapabilityStatus } from "@/types";

const surface = { backgroundColor: "var(--claw-surface)", border: "1px solid var(--claw-border)" };

function RiskTag({ risk }: { risk: CapabilityStatus["risk"] }) {
  if (risk === "low") return null;
  const high = risk === "high";
  return (
    <span
      className="text-[11px] px-1.5 py-px rounded-md font-medium whitespace-nowrap"
      style={{
        backgroundColor: high ? "var(--fill-danger)" : "var(--fill-warning)",
        color: high ? "var(--accent-danger)" : "var(--accent-warning)",
      }}
    >
      {high ? "High risk" : "Medium risk"}
    </span>
  );
}

const CHIPS: Record<ChipKind | "limits", { icon: LucideIcon; warn?: boolean }> = {
  asks: { icon: Hand },
  auto: { icon: Play },
  local: { icon: Monitor },
  cloud: { icon: CloudUpload, warn: true },
  schedule: { icon: Clock },
  limits: { icon: SlidersHorizontal },
};

function Chip({ kind, text }: { kind: ChipKind | "limits"; text: string }) {
  const { icon: Icon, warn } = CHIPS[kind];
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full whitespace-nowrap"
      style={{
        border: `1px solid ${warn ? "var(--border-warning)" : "var(--claw-border)"}`,
        color: warn ? "var(--accent-warning)" : "var(--text-secondary)",
      }}
    >
      <Icon className="w-3 h-3" aria-hidden />
      {text}
    </span>
  );
}

function Fact({ icon: Icon, color, label, children }: { icon: LucideIcon; color: string; label: string; children: string }) {
  return (
    <p className="flex gap-2 text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
      <Icon className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden style={{ color }} />
      <span>
        <span className="font-semibold" style={{ color: "var(--text-primary)" }}>
          {label}:{" "}
        </span>
        {children}
      </span>
    </p>
  );
}

/** Where a blocked capability's missing step lives in this app, when it is a page of its own.
 *  ponytail: matched on the server's wording; a link field on CapabilityStatus would be sturdier
 *  if more of these appear. */
function fixLink(item: CapabilityStatus): { to: string; label: string; icon: LucideIcon } | null {
  if (item.effective !== "blocked") return null;
  if (item.reason.includes("Service keys")) return { to: "/security?tab=keys", label: "Add key", icon: KeyRound };
  if (item.reason.includes("Connectors")) return { to: "/connectors", label: "Open Connectors", icon: Plug };
  return null;
}

interface RowHandlers {
  editable: boolean;
  busyKey: string | null;
  onToggle: (key: string, enabled: boolean) => void;
  onRequestAccess: (key: string) => void;
  onInstall: (key: string) => void;
  onSettingsChange?: (key: string, patch: Record<string, number>) => void;
}

function CapabilityRow({ item, ...h }: RowHandlers & { item: CapabilityStatus }) {
  const headingId = useId();
  const infoId = useId();
  const [open, setOpen] = useState(false);
  const busy = h.busyKey === item.key;
  const disabled = !h.editable || busy;
  const blocked = item.effective === "blocked";
  const link = fixLink(item);
  const canInstall = !!item.install && !item.available;
  const hasFix = item.can_request_access || canInstall || !!link;
  // With a button the button says what to do and the reason waits in the info panel; without one
  // (another switch must be on first) the reason itself is the next step, so it stays in sight.
  const note =
    blocked && !hasFix
      ? { text: item.reason, color: "var(--accent-warning)" }
      : item.effective === "off" && item.enabled && item.reason
        ? { text: `Off — ${item.reason}`, color: "var(--text-muted)" }
        : null;
  const about = aboutOf(item);
  const hasLimits = !!h.onSettingsChange && Object.keys(item.settings ?? {}).length > 0;
  const chips: [ChipKind | "limits", string][] = [...(about?.chips ?? []), ...(hasLimits ? [["limits", "Has limits"] as [ChipKind | "limits", string]] : [])];
  const sendsData = about?.chips?.some(([kind]) => kind === "cloud");
  const smallBtn = "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] text-xs font-semibold disabled:opacity-50";
  return (
    <li className="py-4 first:pt-1 border-t first:border-t-0" style={{ borderColor: "var(--claw-border)" }}>
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h4 id={headingId} className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
              {item.label}
            </h4>
            <RiskTag risk={item.risk} />
            {blocked && (
              <span
                className="inline-flex items-center gap-1 text-[11px] px-2 py-px rounded-full font-medium whitespace-nowrap"
                style={{ backgroundColor: "var(--fill-warning)", color: "var(--accent-warning)" }}
              >
                <Wrench className="w-3 h-3" aria-hidden />
                Needs setup
              </span>
            )}
          </div>
          <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
            {summaryOf(item)}
          </p>
          {chips.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {chips.map(([kind, text]) => (
                <Chip key={text} kind={kind} text={text} />
              ))}
            </div>
          )}
          {note && (
            <p className="text-xs mt-2 font-medium" style={{ color: note.color }}>
              {note.text}
            </p>
          )}

          {hasFix && (
            <div className="flex items-center gap-2 mt-2.5 flex-wrap">
              {item.can_request_access && (
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => h.onRequestAccess(item.key)}
                  className={smallBtn}
                  style={{
                    backgroundColor: "var(--accent-glow)",
                    border: "1px solid var(--border-accent)",
                    color: "var(--accent-primary)",
                  }}
                >
                  <ShieldAlert className="w-3.5 h-3.5" aria-hidden />
                  Grant access
                </button>
              )}
              {canInstall && (
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => h.onInstall(item.key)}
                  className={smallBtn}
                  style={{
                    backgroundColor: "var(--accent-glow)",
                    border: "1px solid var(--border-accent)",
                    color: "var(--accent-primary)",
                  }}
                >
                  <Download className="w-3.5 h-3.5" aria-hidden />
                  {/* The size comes from the server, which knows what this
                      install actually fetches; no guess when it has none. */}
                  {item.install_size_hint ? `Install (${item.install_size_hint})` : "Install"}
                </button>
              )}
              {link && (
                <Link
                  to={link.to}
                  className={smallBtn}
                  style={{
                    backgroundColor: "var(--accent-glow)",
                    border: "1px solid var(--border-accent)",
                    color: "var(--accent-primary)",
                  }}
                >
                  <link.icon className="w-3.5 h-3.5" aria-hidden />
                  {link.label}
                  <ArrowRight className="w-3.5 h-3.5" aria-hidden />
                </Link>
              )}
            </div>
          )}
        </div>
        <button
          type="button"
          aria-label={`About ${item.label}`}
          aria-expanded={open}
          aria-controls={infoId}
          onClick={() => setOpen((o) => !o)}
          className="tap-target inline-flex items-center justify-center w-6 h-6 rounded-full shrink-0 transition-colors"
          style={{
            border: `1px solid ${open ? "var(--border-accent)" : "var(--border-primary)"}`,
            backgroundColor: open ? "var(--accent-glow)" : "transparent",
            color: open ? "var(--accent-primary)" : "var(--text-muted)",
          }}
        >
          <Info className="w-3.5 h-3.5" aria-hidden />
        </button>
        <Switch
          checked={item.enabled}
          onChange={(next) => h.onToggle(item.key, next)}
          busy={busy}
          disabled={!h.editable}
          aria-labelledby={headingId}
          className={blocked ? "opacity-60" : undefined}
        />
      </div>

      {/* The full story, one click away: three short facts (or the server's description for a
          capability without them), how to fix a block, and the limits (purchase caps…). */}
      {open && (
        <div
          id={infoId}
          className="mt-3 rounded-[10px] px-3.5 py-3 space-y-2"
          style={{ backgroundColor: "var(--claw-surface-active)" }}
        >
          {about?.own && (
            <Fact icon={Play} color="var(--accent-success)" label="On its own">
              {about.own}
            </Fact>
          )}
          {about?.asks && (
            <Fact icon={Hand} color="var(--accent-warning)" label="Asks you first">
              {about.asks}
            </Fact>
          )}
          {about?.data && (
            <Fact
              icon={sendsData ? CloudUpload : Lock}
              color={sendsData ? "var(--accent-warning)" : "var(--text-secondary)"}
              label="Your data"
            >
              {about.data}
            </Fact>
          )}
          {blocked && hasFix && (
            <Fact icon={Wrench} color="var(--accent-warning)" label="To finish setup">
              {item.reason}
            </Fact>
          )}
          {!about && (
            <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
              {item.description}
            </p>
          )}
          {item.fix_url && item.fix_steps.length > 0 && (
            <ol className="list-decimal pl-5 space-y-0.5 text-xs" style={{ color: "var(--text-muted)" }}>
              {item.fix_steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          )}
          {/* Only where a save handler exists: the setup wizard turns things on and off and
              leaves these at their defaults. */}
          {h.onSettingsChange && (
            <CapabilitySettings
              item={item}
              editable={!disabled}
              onChange={(patch) => h.onSettingsChange?.(item.key, patch)}
            />
          )}
        </div>
      )}
    </li>
  );
}

function plural(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`;
}

function categoryStatus(items: CapabilityStatus[]): { text: string; color: string; dot: string } {
  const blocked = items.filter((i) => i.effective === "blocked").length;
  if (blocked) {
    return { text: `${plural(blocked, "needs", "need")} setup`, color: "var(--accent-warning)", dot: "var(--accent-warning)" };
  }
  const on = items.filter((i) => i.enabled).length;
  const text = items.length === 1 ? (on ? "On" : "Off") : `${on} of ${items.length} on`;
  return { text, color: "var(--text-muted)", dot: on ? "var(--accent-success)" : "var(--text-muted)" };
}

function LevelPicker({
  items,
  editable,
  onApply,
}: {
  items: CapabilityStatus[];
  editable: boolean;
  onApply: (patch: Record<string, boolean>) => Promise<void>;
}) {
  const headingId = useId();
  const [pending, setPending] = useState<Level | null>(null);
  const current = LEVELS.find((level) => Object.keys(levelPatch(level, items)).length === 0);
  const patch = pending ? levelPatch(pending, items) : {};
  const label = (key: string) => items.find((i) => i.key === key)?.label ?? key;
  const turnsOn = Object.keys(patch).filter((k) => patch[k]).map(label);
  const turnsOff = Object.keys(patch).filter((k) => !patch[k]).map(label);

  return (
    <section aria-labelledby={headingId}>
      <h3 id={headingId} className="text-base font-semibold mb-3" style={{ color: "var(--text-primary)" }}>
        How much should Crawler do on its own?
      </h3>
      <div role="radiogroup" aria-labelledby={headingId} className="grid gap-2 @xl:grid-cols-3">
        {LEVELS.map((level) => {
          const active = current?.id === level.id;
          const Icon = level.icon;
          return (
            <button
              key={level.id}
              type="button"
              role="radio"
              aria-checked={active}
              disabled={!editable}
              onClick={() => !active && setPending(level)}
              className="flex flex-col items-start text-left p-3.5 rounded-[12px] transition-colors disabled:cursor-not-allowed"
              style={{
                backgroundColor: active ? "var(--accent-glow)" : "var(--claw-surface)",
                border: `1px solid ${active ? "var(--border-accent)" : "var(--claw-border)"}`,
                boxShadow: active ? "inset 0 0 0 1px var(--border-accent)" : undefined,
              }}
            >
              <span
                className="flex items-center gap-2 text-sm font-semibold"
                style={{ color: active ? "var(--accent-primary)" : "var(--text-primary)" }}
              >
                <Icon className="w-4 h-4" aria-hidden />
                {level.label}
              </span>
              <span className="block text-xs mt-1 leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                {level.summary}
              </span>
            </button>
          );
        })}
      </div>
      {!current && (
        <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
          You&apos;ve made your own mix. Picking a level shows what it would change before anything happens.
        </p>
      )}

      <ConfirmDialog
        open={pending !== null}
        title={`Switch to ${pending?.label ?? ""}?`}
        message={pending?.summary ?? ""}
        confirmLabel={`Switch to ${pending?.label ?? ""}`}
        onCancel={() => setPending(null)}
        onConfirm={async () => {
          await onApply(patch);
          setPending(null);
        }}
      >
        <div className="space-y-2 text-xs" style={{ color: "var(--text-secondary)" }}>
          {turnsOn.length > 0 && (
            <p>
              <span className="font-semibold" style={{ color: "var(--accent-success)" }}>Turns on: </span>
              {turnsOn.join(", ")}
            </p>
          )}
          {turnsOff.length > 0 && (
            <p>
              <span className="font-semibold" style={{ color: "var(--text-primary)" }}>Turns off: </span>
              {turnsOff.join(", ")}
            </p>
          )}
          <p style={{ color: "var(--text-muted)" }}>Privacy and safety checks stay as they are.</p>
        </div>
      </ConfirmDialog>
    </section>
  );
}

function Overview({ items }: { items: CapabilityStatus[] }) {
  const columns = [
    { title: "Turned on", color: "var(--accent-success)", items: byRisk(items.filter((i) => i.effective === "on")) },
    { title: "Turned off", color: "var(--text-secondary)", items: byRisk(items.filter((i) => !i.enabled)) },
  ];
  return (
    <div className="grid gap-4 @lg:grid-cols-2 rounded-[12px] p-4" style={surface}>
      {columns.map((col) => (
        <div key={col.title} className="min-w-0">
          <p className="text-xs font-semibold mb-1.5" style={{ color: col.color }}>
            {col.title}
          </p>
          <ul className="space-y-1 text-xs" style={{ color: "var(--text-secondary)" }}>
            {col.items.slice(0, 4).map((i) => (
              <li key={i.key} className="truncate">
                {i.label}
              </li>
            ))}
            {col.items.length === 0 && <li style={{ color: "var(--text-muted)" }}>Nothing</li>}
            {col.items.length > 4 && <li style={{ color: "var(--text-muted)" }}>and {col.items.length - 4} more</li>}
          </ul>
        </div>
      ))}
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
  /** Saves one changed setting of a capability (the purchase caps). When
   *  absent, no settings fields are rendered. */
  onSettingsChange?: (key: string, patch: Record<string, number>) => void;
  /** Saves a protection level's switches in one request; throw to show the error in its dialog.
   *  When absent, no level picker is shown. */
  onApplyLevel?: (patch: Record<string, boolean>) => Promise<void>;
  /** Shown at the foot of a category's panel (the payment card under Money). */
  extras?: Partial<Record<CategoryId, ReactNode>>;
}

/**
 * Each switch reflects the stored preference (`enabled`); its status line says what actually
 * happens right now (`effective`), since a capability can be on and still blocked by the OS or a
 * missing install. Read-only viewers get every control disabled rather than hidden, so the
 * screen's shape does not shift between an owner and everyone else.
 */
export default function CapabilityList({
  items,
  editable,
  onToggle,
  onRequestAccess,
  onInstall,
  busyKey = null,
  onSettingsChange,
  onApplyLevel,
  extras = {},
}: CapabilityListProps) {
  const panelId = useId();
  const panelRef = useRef<HTMLElement>(null);
  const groups = groupByCategory(items).filter((g) => g.items.length > 0 || extras[g.category.id]);
  const [selected, setSelected] = useState<CategoryId | null>(null);
  const active = groups.find((g) => g.category.id === selected) ?? groups[0];
  const attention = items.filter((i) => i.effective === "blocked");
  const categoryOf = (key: string): Category | undefined =>
    groups.find((g) => g.items.some((i) => i.key === key))?.category;

  const open = (id: CategoryId) => {
    setSelected(id);
    // Stacked on a narrow screen, the panel sits under the list: bring it into view.
    const panel = panelRef.current;
    const top = panel?.getBoundingClientRect().top ?? 0;
    if (panel && (top < 0 || top > window.innerHeight - 160)) {
      panel.scrollIntoView?.({ block: "start", behavior: "smooth" });
    }
  };

  const handlers: RowHandlers = { editable, busyKey, onToggle, onRequestAccess, onInstall, onSettingsChange };

  return (
    <div className="@container space-y-5">
      {!editable && (
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          Only the owner can change these.
        </p>
      )}

      {onApplyLevel && <LevelPicker items={items} editable={editable} onApply={onApplyLevel} />}

      <Overview items={items} />

      {attention.length > 0 && (
        <div
          role="status"
          className="flex items-start gap-2.5 rounded-[12px] p-3.5 text-xs"
          style={{
            backgroundColor: "var(--fill-warning)",
            border: "1px solid var(--border-warning)",
            color: "var(--accent-warning)",
          }}
        >
          <Wrench className="w-4 h-4 shrink-0 mt-px" aria-hidden />
          <div className="min-w-0">
            <span className="font-semibold">{plural(attention.length, "permission needs", "permissions need")} setup: </span>
            {attention.map((item, n) => {
              const category = categoryOf(item.key);
              return (
                <span key={item.key}>
                  {n > 0 && ", "}
                  <button
                    type="button"
                    className="underline underline-offset-2 font-medium"
                    onClick={() => category && open(category.id)}
                  >
                    {item.label}
                  </button>
                </span>
              );
            })}
          </div>
        </div>
      )}

      {active && (
        <div className="grid gap-4 items-start @2xl:grid-cols-[15rem_minmax(0,1fr)]">
          <div className="grid gap-1.5 @md:grid-cols-2 @2xl:grid-cols-1" aria-label="Permission categories" role="group">
            {groups.map(({ category, items: catItems }) => {
              const isActive = category.id === active.category.id;
              const status = categoryStatus(catItems);
              const Icon = category.icon;
              return (
                <button
                  key={category.id}
                  type="button"
                  aria-pressed={isActive}
                  aria-controls={panelId}
                  onClick={() => open(category.id)}
                  className="flex items-center gap-3 text-left px-3 py-2.5 rounded-[10px] transition-colors"
                  style={{
                    minHeight: 44,
                    backgroundColor: isActive ? "var(--claw-surface-active)" : "transparent",
                    border: `1px solid ${isActive ? "var(--border-primary)" : "var(--claw-border)"}`,
                  }}
                >
                  <Icon
                    className="w-4 h-4 shrink-0"
                    aria-hidden
                    style={{ color: isActive ? "var(--accent-primary)" : "var(--text-muted)" }}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium truncate" style={{ color: "var(--text-primary)" }}>
                      {category.label}
                    </span>
                    <span className="flex items-center gap-1.5 text-xs" style={{ color: status.color }}>
                      <span aria-hidden className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: status.dot }} />
                      {status.text}
                    </span>
                  </span>
                  <ChevronRight
                    className="w-4 h-4 shrink-0 hidden @2xl:block"
                    aria-hidden
                    style={{ color: isActive ? "var(--text-secondary)" : "transparent" }}
                  />
                </button>
              );
            })}
          </div>

          <section
            ref={panelRef}
            id={panelId}
            aria-labelledby={`${panelId}-title`}
            className="rounded-[14px] p-5 scroll-mt-4"
            style={surface}
          >
            <h3 id={`${panelId}-title`} className="text-base font-semibold" style={{ color: "var(--text-primary)" }}>
              {active.category.label}
            </h3>
            <p className="text-xs mt-1 mb-4 leading-relaxed" style={{ color: "var(--text-muted)" }}>
              {active.category.blurb}
            </p>
            {active.items.length > 0 && (
              <ul>
                {active.items.map((item) => (
                  <CapabilityRow key={item.key} item={item} {...handlers} />
                ))}
              </ul>
            )}
            {extras[active.category.id] && <div className="mt-4 space-y-4">{extras[active.category.id]}</div>}
          </section>
        </div>
      )}
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
    <div className="rounded-[10px] p-4" style={surface}>
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
        style={{ ...surface, color: "var(--text-secondary)" }}
      >
        Retry
      </button>
    </div>
  );
}
