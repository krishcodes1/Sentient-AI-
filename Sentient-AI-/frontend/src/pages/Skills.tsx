/**
 * Skills page: the signed-in user's skills (add, edit, turn on or off, delete).
 *
 * Why it exists: a skill is a playbook the user writes so Crawler does a kind of task their way.
 * Crawler sees each enabled skill's name and description in every chat and reads the instructions
 * only when a task needs them; it can never add, change or remove a skill itself. The server
 * screens every save, and its refusal is shown as it is.
 */

import { useEffect, useState, type FormEvent } from "react";
import { Check, Loader2, Pencil, Plus, RefreshCw, Sparkles, Trash2, X } from "lucide-react";
import type { Skill } from "@/types";
import { createSkill, deleteSkill, getCapabilities, listSkills, updateSkill } from "@/services/api";
import ConfirmDialog from "@/components/ConfirmDialog";
import Switch from "@/components/Switch";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, inputCls, inputStyle, labelCls, panelStyle, primaryCls, primaryStyle } from "@/components/formStyles";

// The server's limits (services/skills.py).
const NAME_MAX = 40;
const DESCRIPTION_MAX = 200;
const INSTRUCTIONS_MAX = 10000;

/** A name as the server takes it: lowercase words joined by single hyphens. */
function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+/, "");
}

export default function SkillsPage() {
  const [skills, setSkills] = useState<Skill[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [instructions, setInstructions] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");

  const [editing, setEditing] = useState<Skill | null>(null);
  const [saving, setSaving] = useState(false);
  const [editError, setEditError] = useState("");

  const [busyId, setBusyId] = useState<string | null>(null);
  const [toggleError, setToggleError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<Skill | null>(null);
  // The owner's "Use your skills" switch: while it is off, Crawler ignores every skill.
  const [switchedOff, setSwitchedOff] = useState("");

  useEffect(() => {
    getCapabilities()
      .then((list) => {
        const skills = list.find((c) => c.key === "skills");
        if (skills && skills.effective !== "on") setSwitchedOff(skills.when_denied);
      })
      // Only a hint: the page works the same without it.
      .catch(() => {});
  }, []);

  useEffect(() => {
    let cancelled = false;
    listSkills()
      .then((list) => {
        if (cancelled) return;
        setSkills(list);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "Could not load your skills."));
      });
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  const replace = (skill: Skill) => setSkills((list) => (list ?? []).map((s) => (s.id === skill.id ? skill : s)));

  async function handleAdd(event: FormEvent) {
    event.preventDefault();
    setAdding(true);
    setAddError("");
    try {
      const created = await createSkill({
        name: name.replace(/-+$/, ""),
        description: description.trim(),
        instructions: instructions.trim(),
      });
      setSkills((list) => [...(list ?? []), created].sort((a, b) => a.name.localeCompare(b.name)));
      setName("");
      setDescription("");
      setInstructions("");
    } catch (err) {
      setAddError(errorText(err, "The skill was not saved."));
    } finally {
      setAdding(false);
    }
  }

  async function handleSave(event: FormEvent) {
    event.preventDefault();
    if (!editing) return;
    setSaving(true);
    setEditError("");
    try {
      replace(
        await updateSkill(editing.id, {
          description: editing.description.trim(),
          instructions: editing.instructions.trim(),
        }),
      );
      setEditing(null);
    } catch (err) {
      setEditError(errorText(err, "The skill was not saved."));
    } finally {
      setSaving(false);
    }
  }

  async function handleToggle(skill: Skill) {
    setBusyId(skill.id);
    setToggleError("");
    try {
      replace(await updateSkill(skill.id, { enabled: !skill.enabled }));
    } catch (err) {
      setToggleError(errorText(err, "That didn't work. Try again."));
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    await deleteSkill(deleteTarget.id);
    setSkills((list) => (list ?? []).filter((s) => s.id !== deleteTarget.id));
    setDeleteTarget(null);
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <div className="eyebrow mb-2">Personalization</div>
        <h1 className="flex items-center gap-2.5" style={{ color: "var(--text-primary)" }}>
          <Sparkles className="w-6 h-6" style={{ color: "var(--accent-primary)" }} />
          Skills
        </h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Teach Crawler how you like a kind of task done. Crawler sees each skill's name and description
          in every chat and reads the instructions when a request matches. Skills never run code, and
          anything that sends or changes something still asks you first.
        </p>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Only add skills you wrote or have read line by line: Crawler follows them like your own messages.
        </p>
      </div>

      {switchedOff && <ErrorAlert>{switchedOff}</ErrorAlert>}

      <section className="rounded-[14px] p-6" style={panelStyle}>
        <h2 className="mb-4">New skill</h2>
        <form onSubmit={handleAdd} className="space-y-4">
          {addError && <ErrorAlert>{addError}</ErrorAlert>}
          <div>
            <label htmlFor="skill-name" className={labelCls}>
              Name
            </label>
            <input
              id="skill-name"
              required
              maxLength={NAME_MAX}
              value={name}
              onChange={(e) => setName(slug(e.target.value))}
              placeholder="weekly-canvas"
              aria-describedby="skill-name-help"
              className={inputCls}
              style={inputStyle}
            />
            <p id="skill-name-help" className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              Lowercase words joined by hyphens.
            </p>
          </div>
          <div>
            <label htmlFor="skill-description" className={labelCls}>
              When should Crawler use it?
            </label>
            <input
              id="skill-description"
              required
              maxLength={DESCRIPTION_MAX}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="When I ask what's due this week"
              className={inputCls}
              style={inputStyle}
            />
          </div>
          <div>
            <label htmlFor="skill-instructions" className={labelCls}>
              Instructions
            </label>
            <textarea
              id="skill-instructions"
              required
              rows={6}
              maxLength={INSTRUCTIONS_MAX}
              value={instructions}
              onChange={(e) => setInstructions(e.target.value)}
              placeholder={"Check Canvas for everything due in the next 7 days.\nGroup it by course, soonest first.\nMark anything overdue at the top."}
              className={`${inputCls} resize-y`}
              style={inputStyle}
            />
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              {instructions.length}/{INSTRUCTIONS_MAX}. Leave out passwords and keys: skills are sent to your AI
              provider.
            </p>
          </div>
          <button type="submit" disabled={adding} className={primaryCls} style={primaryStyle}>
            {adding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            Save skill
          </button>
        </form>
      </section>

      <section className="rounded-[14px] p-6" style={panelStyle}>
        <h2 className="mb-4">Your skills</h2>
        {toggleError && <ErrorAlert>{toggleError}</ErrorAlert>}
        {!skills && !loadError && (
          <p role="status" className="text-sm" style={{ color: "var(--text-muted)" }}>
            Loading…
          </p>
        )}
        {loadError && (
          <div role="alert" className="flex items-center justify-between gap-3 flex-wrap text-sm" style={{ color: "var(--accent-danger)" }}>
            {loadError}
            <button type="button" onClick={() => setReloadKey((k) => k + 1)} className="inline-flex items-center gap-1.5 text-xs font-semibold">
              <RefreshCw className="w-3 h-3" /> Retry
            </button>
          </div>
        )}
        {skills && skills.length === 0 && (
          <p className="text-sm py-4" style={{ color: "var(--text-muted)" }}>
            No skills yet. Add one above.
          </p>
        )}
        {skills && skills.length > 0 && (
          <ul className="space-y-2">
            {skills.map((skill) => (
              <li
                key={skill.id}
                className="rounded-[10px] px-4 py-3"
                style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
              >
                {editing?.id === skill.id ? (
                  <form onSubmit={handleSave} className="space-y-2">
                    <div className="mono-tag" style={{ color: "var(--text-primary)" }}>
                      {skill.name}
                    </div>
                    {editError && <ErrorAlert>{editError}</ErrorAlert>}
                    <input
                      aria-label="When should Crawler use it?"
                      required
                      maxLength={DESCRIPTION_MAX}
                      value={editing.description}
                      onChange={(e) => setEditing({ ...editing, description: e.target.value })}
                      className={inputCls}
                      style={inputStyle}
                    />
                    <textarea
                      aria-label="Instructions"
                      required
                      rows={6}
                      maxLength={INSTRUCTIONS_MAX}
                      value={editing.instructions}
                      onChange={(e) => setEditing({ ...editing, instructions: e.target.value })}
                      className={`${inputCls} resize-y`}
                      style={inputStyle}
                    />
                    <div className="flex gap-2">
                      <button
                        type="submit"
                        disabled={saving}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[6px] text-xs font-semibold disabled:opacity-50"
                        style={{ minHeight: 32, background: "var(--accent-success)", color: "var(--text-on-accent)" }}
                      >
                        {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />} Save
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditing(null)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[6px] text-xs font-medium"
                        style={{ border: "1px solid var(--claw-border)", color: "var(--text-secondary)" }}
                      >
                        <X className="w-3 h-3" /> Cancel
                      </button>
                    </div>
                  </form>
                ) : (
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="mono-tag" style={{ color: "var(--text-primary)" }}>
                        {skill.name}
                      </div>
                      <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
                        {skill.description}
                      </p>
                      <details className="mt-1">
                        <summary className="text-xs cursor-pointer" style={{ color: "var(--text-muted)" }}>
                          Instructions
                        </summary>
                        <p className="text-sm mt-1 whitespace-pre-wrap break-words" style={{ color: "var(--text-primary)" }}>
                          {skill.instructions}
                        </p>
                      </details>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <Switch
                        checked={skill.enabled}
                        busy={busyId === skill.id}
                        onChange={() => void handleToggle(skill)}
                        aria-label={`Use ${skill.name}`}
                      />
                      <button
                        type="button"
                        aria-label={`Edit ${skill.name}`}
                        onClick={() => {
                          setEditError("");
                          setEditing(skill);
                        }}
                        className="tap-target p-1.5 rounded-[6px]"
                        style={{ color: "var(--text-muted)" }}
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        aria-label={`Delete ${skill.name}`}
                        onClick={() => setDeleteTarget(skill)}
                        className="tap-target p-1.5 rounded-[6px]"
                        style={{ color: "var(--accent-danger)" }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <ConfirmDialog
        open={deleteTarget !== null}
        danger
        title="Delete this skill?"
        message={`"${deleteTarget?.name ?? ""}" will be deleted. This cannot be undone.`}
        confirmLabel="Delete"
        onCancel={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
      />
    </div>
  );
}
