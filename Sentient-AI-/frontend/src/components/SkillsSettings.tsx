/**
 * SkillsSettings: the owner's Settings ▸ Skills section — every bundled skill with its title,
 * name, category, description and status badge (Ready / Blocked / Changed on disk / Not pinned /
 * Invalid), an on/off switch, and View: each of its files as plain text, its SHA-256, the tools it
 * uses and the safety scan's findings.
 *
 * Why it exists: A skill is a SKILL.md playbook the team reviewed and pinned by hash, and it steers
 * how a chat uses Crawler's own tools, so the owner must be able to read exactly what each one says
 * and switch it off. The files are shown in a <pre> and never rendered as Markdown, so a link or
 * image inside a skill is never fetched or made clickable. A skill that is not usable cannot be
 * switched on (the server answers 409), so its switch is disabled while off; one still on says it is
 * not in use and can be switched off. View reads the skill again each time it opens, and the row
 * follows what that read says, since the server marks a skill changed when its files no longer
 * match.
 */

import { useEffect, useId, useState } from "react";
import { Eye, Loader2 } from "lucide-react";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, panelStyle } from "@/components/formStyles";
import { ApiError, getSkill, listSkills, setSkillEnabled } from "@/services/api";
import type { SkillDetail, SkillFinding, SkillInfo, SkillStatus } from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };

interface Tone {
  text: string;
  fill: string;
  border: string;
}

const SUCCESS: Tone = {
  text: "var(--accent-success)",
  fill: "var(--fill-success)",
  border: "var(--border-success)",
};
const WARNING: Tone = {
  text: "var(--accent-warning)",
  fill: "var(--fill-warning)",
  border: "var(--border-warning)",
};
const DANGER: Tone = {
  text: "var(--accent-danger)",
  fill: "var(--fill-danger)",
  border: "var(--border-danger)",
};

const STATUS_BADGES: Record<SkillStatus, { label: string; tone: Tone }> = {
  ok: { label: "Ready", tone: SUCCESS },
  blocked: { label: "Blocked", tone: DANGER },
  changed: { label: "Changed on disk", tone: WARNING },
  unpinned: { label: "Not pinned", tone: WARNING },
  invalid: { label: "Invalid", tone: DANGER },
};

/** Why a skill that is not ready cannot be switched on, in the owner's terms. */
const STATUS_HELP: Record<Exclude<SkillStatus, "ok">, string> = {
  blocked: "The safety scan found something a skill must never contain, so it cannot be used.",
  changed:
    "Its files no longer match the hash pinned for this install, so it cannot be used until the " +
    "change is reviewed and pinned again.",
  unpinned: "It is not in the pinned manifest, so it cannot be used.",
  invalid: "It breaks a format, size or file rule, so it cannot be used.",
};

function Badge({ label, tone }: { label: string; tone: Tone }) {
  return (
    <span
      className="text-[11px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wide"
      style={{ backgroundColor: tone.fill, border: `1px solid ${tone.border}`, color: tone.text }}
    >
      {label}
    </span>
  );
}

function capitalize(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** "SKILL.md:12", or the file alone for a finding about the whole file. */
function findingPlace(finding: SkillFinding): string {
  return finding.line === null ? finding.file : `${finding.file}:${finding.line}`;
}

function SkillView({ skill, detail }: { skill: SkillInfo; detail: SkillDetail }) {
  const { connectors, capabilities } = detail.requires;
  const status = STATUS_BADGES[detail.status] ?? STATUS_BADGES.invalid;
  return (
    <div className="space-y-5">
      {detail.status !== "ok" && (
        <div
          className="rounded-[8px] px-3 py-2 text-xs space-y-1 break-words"
          style={{
            background: status.tone.fill,
            border: `1px solid ${status.tone.border}`,
            color: status.tone.text,
          }}
        >
          <p className="font-semibold">Not in use: {status.label}.</p>
          {detail.status_reason && <p>Reason: {detail.status_reason}</p>}
          <p>
            The files below are what is on disk now and may not match the SHA-256 shown. No chat
            can read this skill until it is ready again.
          </p>
        </div>
      )}
      <dl className="grid gap-x-4 gap-y-2 text-xs sm:grid-cols-[auto_1fr]">
        <dt style={{ color: "var(--text-muted)" }}>SHA-256</dt>
        <dd className="min-w-0">
          <code className="break-all">{detail.sha256}</code>
        </dd>
        <dt style={{ color: "var(--text-muted)" }}>Tools it uses</dt>
        <dd className="min-w-0 flex flex-wrap gap-1.5">
          {detail.tools.length > 0
            ? detail.tools.map((tool) => <code key={tool}>{tool}</code>)
            : <span style={{ color: "var(--text-secondary)" }}>None listed</span>}
        </dd>
        {connectors.length > 0 && (
          <>
            <dt style={{ color: "var(--text-muted)" }}>Needs one of these connected</dt>
            <dd className="min-w-0 break-words" style={{ color: "var(--text-secondary)" }}>
              {connectors.join(", ")}
            </dd>
          </>
        )}
        {capabilities.length > 0 && (
          <>
            <dt style={{ color: "var(--text-muted)" }}>Needs these permissions on</dt>
            <dd className="min-w-0 break-words" style={{ color: "var(--text-secondary)" }}>
              {capabilities.join(", ")}
            </dd>
          </>
        )}
        {detail.license && (
          <>
            <dt style={{ color: "var(--text-muted)" }}>License</dt>
            <dd className="min-w-0 break-words" style={{ color: "var(--text-secondary)" }}>
              {detail.license}
            </dd>
          </>
        )}
      </dl>
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        Reading a skill puts these tools within reach of the chat. It never grants one: each tool
        still needs its permission on, and every action still asks as usual.
      </p>

      <div>
        <h4 className="text-sm font-semibold mb-2" style={{ color: "var(--text-primary)" }}>
          Safety scan
        </h4>
        {detail.findings.length === 0 ? (
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            The scan found nothing to flag.
          </p>
        ) : (
          <ul className="space-y-2" aria-label={`Safety scan findings for ${skill.title}`}>
            {detail.findings.map((finding, index) => (
              <li
                key={`${finding.rule}-${finding.file}-${finding.line ?? "file"}-${index}`}
                className="rounded-[8px] px-3 py-2 text-xs"
                style={{ background: "var(--claw-panel)", border: "1px solid var(--claw-border)" }}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge
                    label={finding.severity === "block" ? "Block" : "Warn"}
                    tone={finding.severity === "block" ? DANGER : WARNING}
                  />
                  <span className="mono-tag" style={{ color: "var(--text-primary)" }}>
                    {finding.rule}
                  </span>
                  <span className="mono-tag break-all" style={{ color: "var(--text-muted)" }}>
                    {findingPlace(finding)}
                  </span>
                </div>
                <p className="mt-1 break-words" style={{ color: "var(--text-secondary)" }}>
                  {finding.message}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
          Files
        </h4>
        <p className="text-xs mb-2" style={{ color: "var(--text-muted)" }}>
          Plain text, exactly as stored. Nothing in them is opened, loaded or run.
        </p>
        {detail.files.map((file) => (
          <figure key={file.path} className="mt-3">
            <figcaption className="mono-tag break-all" style={{ color: "var(--text-secondary)" }}>
              {file.path}
            </figcaption>
            {/* Plain text only: React escapes it, and nothing here parses Markdown or HTML. */}
            <pre
              tabIndex={0}
              className={
                "mt-1.5 p-3 rounded-[8px] text-xs whitespace-pre-wrap break-words " +
                "overflow-auto max-h-96"
              }
              style={{
                background: "var(--bg-primary)",
                color: "var(--text-secondary)",
                border: "1px solid var(--border-subtle)",
              }}
            >
              {file.text}
            </pre>
          </figure>
        ))}
      </div>
    </div>
  );
}

interface SkillRowProps {
  skill: SkillInfo;
  busy: boolean;
  error: string;
  onToggle: (skill: SkillInfo) => void;
  /** View read a status or switch that differs from the list's: the row should show it. */
  onRefreshed: (skill: SkillInfo) => void;
}

function SkillRow({ skill, busy, error, onToggle, onRefreshed }: SkillRowProps) {
  const titleId = useId();
  const viewId = useId();
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<SkillDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [viewError, setViewError] = useState("");
  const usable = skill.status === "ok";
  // Switched on but not usable: never offered to a chat, so it is not shown as active.
  const inUse = usable && skill.enabled;
  const badge = STATUS_BADGES[skill.status] ?? STATUS_BADGES.invalid;

  const load = async () => {
    setLoading(true);
    setViewError("");
    try {
      const loaded = await getSkill(skill.name);
      setDetail(loaded);
      // The server hashes the files again on this read and may have just marked the skill
      // changed; the badge, help text and switch must not keep claiming it is ready.
      if (
        loaded.status !== skill.status ||
        loaded.status_reason !== skill.status_reason ||
        loaded.enabled !== skill.enabled
      ) {
        const { files: _files, ...info } = loaded;
        onRefreshed(info);
      }
    } catch (err) {
      setViewError(errorText(err, `The ${skill.title} skill could not be loaded.`));
    } finally {
      setLoading(false);
    }
  };

  const toggleView = () => {
    const next = !open;
    setOpen(next);
    // Read on every View: the files on disk can change while Crawler runs. What was read last
    // stays on screen until the new read answers.
    if (next && !loading) void load();
  };

  const meta = [
    skill.category && capitalize(skill.category),
    skill.version && `v${skill.version}`,
    "built in",
  ].filter(Boolean);

  return (
    <li className="rounded-[10px] p-4" style={rowStyle}>
      <div className="flex items-start justify-between gap-x-4 gap-y-3 flex-wrap">
        {/* At least 14rem of text: on a phone the buttons wrap below rather than squeeze it. */}
        <div className="min-w-[14rem] flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h3
              id={titleId}
              className="text-sm font-semibold"
              style={{ color: "var(--text-primary)" }}
            >
              {skill.title}
            </h3>
            <Badge label={badge.label} tone={badge.tone} />
          </div>
          <p className="text-xs mt-1 break-words" style={{ color: "var(--text-muted)" }}>
            <span className="mono-tag">{skill.name}</span>
            {meta.map((part) => ` · ${part}`).join("")}
          </p>
          <p className="text-xs mt-1.5 break-words" style={{ color: "var(--text-secondary)" }}>
            {skill.description}
          </p>
          {!usable && (
            <p
              className="text-xs mt-1.5 font-medium break-words"
              style={{ color: badge.tone.text }}
            >
              {STATUS_HELP[skill.status as Exclude<SkillStatus, "ok">] ?? STATUS_HELP.invalid}
              {skill.status_reason && ` Reason: ${skill.status_reason}`}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={toggleView}
            aria-expanded={open}
            aria-controls={viewId}
            aria-label={`View ${skill.title}`}
            className="inline-flex items-center gap-1.5 px-3.5 rounded-[10px] text-xs font-semibold"
            style={{
              minHeight: 44,
              background: "var(--claw-panel)",
              border: "1px solid var(--claw-border)",
              color: "var(--text-secondary)",
            }}
          >
            <Eye className="w-3.5 h-3.5" aria-hidden />
            View
          </button>
          <button
            type="button"
            role="switch"
            aria-checked={skill.enabled}
            aria-labelledby={titleId}
            // The server refuses only switching an unusable skill on; switching off always works.
            disabled={busy || (!usable && !skill.enabled)}
            onClick={() => onToggle(skill)}
            className={
              "inline-flex items-center justify-center px-4 rounded-[10px] text-sm font-medium " +
              "transition-colors disabled:opacity-50"
            }
            style={{
              minHeight: 44,
              minWidth: 64,
              background: inUse ? "var(--fill-success)" : "var(--claw-panel)",
              border: inUse ? "1px solid var(--border-success)" : "1px solid var(--claw-border)",
              color: inUse ? "var(--accent-success)" : "var(--text-muted)",
            }}
          >
            {busy ? (
              <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
            ) : skill.enabled ? (
              usable ? "On" : "On (not in use)"
            ) : (
              "Off"
            )}
          </button>
        </div>
      </div>

      {error && (
        <p role="alert" className="text-xs mt-2" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}

      <div
        id={viewId}
        hidden={!open}
        className="mt-4 pt-4"
        style={{ borderTop: "1px solid var(--claw-border)" }}
      >
        {viewError ? (
          <ErrorAlert>
            {viewError}{" "}
            <button type="button" className="underline font-medium" onClick={() => void load()}>
              Try again
            </button>
          </ErrorAlert>
        ) : detail === null ? (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Loading the skill…
          </p>
        ) : (
          <SkillView skill={skill} detail={detail} />
        )}
      </div>
    </li>
  );
}

export default function SkillsSettings() {
  const headingId = useId();
  const [skills, setSkills] = useState<SkillInfo[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  // Names with a switch request in flight; each row waits only for its own.
  const [pending, setPending] = useState<string[]>([]);
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    let cancelled = false;
    listSkills()
      .then((list) => {
        if (cancelled) return;
        setSkills(Array.isArray(list) ? list : []);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "The skills could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const withEnabled = (name: string, enabled: boolean) =>
    setSkills((prev) => prev && prev.map((s) => (s.name === name ? { ...s, enabled } : s)));

  const refreshed = (fresh: SkillInfo) =>
    setSkills((prev) => prev && prev.map((s) => (s.name === fresh.name ? fresh : s)));

  const toggle = async (target: SkillInfo) => {
    const next = !target.enabled;
    setPending((prev) => [...prev, target.name]);
    setRowErrors((prev) => ({ ...prev, [target.name]: "" }));
    // Optimistic: the switch moves now, and moves back if the server refuses.
    withEnabled(target.name, next);
    try {
      const saved = await setSkillEnabled(target.name, next);
      setSkills((prev) => prev && prev.map((s) => (s.name === target.name ? saved : s)));
    } catch (err) {
      withEnabled(target.name, target.enabled);
      setRowErrors((prev) => ({
        ...prev,
        [target.name]: errorText(
          err,
          `The ${target.title} skill could not be switched ${next ? "on" : "off"}. Try again.`,
        ),
      }));
      // 404: the skill is gone; 409: it stopped being usable since the list was read. Either
      // way the list on screen is out of date, so read it again rather than guess.
      if (err instanceof ApiError && (err.status === 404 || err.status === 409)) {
        setAttempt((n) => n + 1);
      }
    } finally {
      setPending((prev) => prev.filter((name) => name !== target.name));
    }
  };

  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-6" style={panelStyle}>
      <div className="eyebrow mb-1">Playbooks</div>
      <h2 id={headingId} className="mb-1">
        Skills
      </h2>
      <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
        Skills are built-in playbooks that guide how Crawler uses its own tools for tasks like
        research, trip planning or keeping up with a goal. A skill is text only: it never runs
        code, never grants a tool and never skips an approval. Each one is checked against a
        SHA-256 hash pinned for this install, and a skill whose files changed, or that fails the
        safety scan, cannot be used. The Skills switch under Permissions turns them all off.
      </p>

      {loadError ? (
        <ErrorAlert>
          {loadError}{" "}
          <button
            type="button"
            className="underline font-medium"
            onClick={() => {
              setLoadError("");
              setSkills(null);
              setAttempt((n) => n + 1);
            }}
          >
            Try again
          </button>
        </ErrorAlert>
      ) : skills === null ? (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Loading skills…
        </p>
      ) : skills.length === 0 ? (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          This Crawler has no built-in skills. Chats use Crawler&apos;s tools as usual.
        </p>
      ) : (
        <ul className="space-y-3">
          {skills.map((skill) => (
            <SkillRow
              key={skill.name}
              skill={skill}
              busy={pending.includes(skill.name)}
              error={rowErrors[skill.name] ?? ""}
              onToggle={(target) => void toggle(target)}
              onRefreshed={refreshed}
            />
          ))}
        </ul>
      )}
    </section>
  );
}
