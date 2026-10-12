/**
 * Goals page: the signed-in account's goals by status (Active / Paused / Completed / All), a "New
 * goal" form, and one card per goal with its category, target date, where it stands and a progress
 * bar. Opening a card loads its plan: milestones with check boxes, Drop and Add milestone, and the
 * progress log with Add note. Each card also has Pause / Resume, Complete, Archive and Delete
 * (after a confirm step).
 *
 * Why it exists: A goal set up in a chat (goals.create) and one made here obey the same store
 * rules, and this is where the user sees every goal and corrects it without asking the model. A
 * goal runs nothing by itself, so nothing on this page schedules or sends. The server is the judge
 * of every rule (a duplicate title, a limit, text it will not save), and its reason is shown next
 * to the click that met it.
 */

import { useId, useEffect, useRef, useState, type FormEvent } from "react";
import { ChevronDown, Loader2, Plus, Target, Trash2, X } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert } from "@/components/FormFeedback";
import {
  errorText,
  inputCls,
  inputStyle,
  labelCls,
  panelStyle,
  primaryCls,
  primaryStyle,
  secondaryCls,
  secondaryStyle,
} from "@/components/formStyles";
import {
  addGoalEntry,
  ApiError,
  createGoal,
  deleteGoal,
  getGoal,
  listGoals,
  updateGoal,
} from "@/services/api";
import type {
  CreateGoalRequest,
  Goal,
  GoalCategory,
  GoalDetail,
  GoalMilestone,
  GoalMilestoneInput,
  GoalStatus,
  UpdateGoalRequest,
} from "@/types";

type Filter = GoalStatus | "all";

const FILTERS: { value: Filter; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "paused", label: "Paused" },
  { value: "completed", label: "Completed" },
  { value: "all", label: "All" },
];

const CATEGORIES: { value: GoalCategory; label: string }[] = [
  { value: "school", label: "School" },
  { value: "career", label: "Career" },
  { value: "health", label: "Health" },
  { value: "money", label: "Money" },
  { value: "personal", label: "Personal" },
  { value: "other", label: "Other" },
];

const CATEGORY_COLORS: Record<GoalCategory, string> = {
  school: "var(--accent-primary)",
  career: "var(--accent-bright)",
  health: "var(--accent-success)",
  money: "var(--accent-warning)",
  personal: "var(--text-secondary)",
  other: "var(--text-muted)",
};

interface StatusStyle {
  label: string;
  color: string;
  fill: string;
  border: string;
}

const STATUS_STYLES: Record<GoalStatus, StatusStyle> = {
  active: {
    label: "Active",
    color: "var(--accent-primary)",
    fill: "var(--accent-glow)",
    border: "var(--border-accent)",
  },
  paused: {
    label: "Paused",
    color: "var(--accent-warning)",
    fill: "var(--fill-warning)",
    border: "var(--border-warning)",
  },
  completed: {
    label: "Completed",
    color: "var(--accent-success)",
    fill: "var(--fill-success)",
    border: "var(--border-success)",
  },
  archived: {
    label: "Archived",
    color: "var(--text-muted)",
    fill: "var(--fill-neutral)",
    border: "var(--claw-border)",
  },
};

// The store's limits (spec 2026-10-12 §5), so typing never runs into a 422 the page could have
// prevented. The goal and milestone counts are left to the server, which names the limit.
const TITLE_MAX = 200;
const DESCRIPTION_MAX = 1000;
const NOTE_MAX = 500;
// POST /goals takes at most 12 milestones at once (as goals.create does).
const FIRST_MILESTONES_MAX = 12;

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const smallButtonCls =
  "inline-flex items-center justify-center gap-1.5 px-3 rounded-[10px] text-xs font-semibold " +
  "disabled:opacity-50";
const insetStyle = { background: "var(--claw-panel)", border: "1px solid var(--claw-border)" };
const spinner = <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />;
const smallButtonStyle = {
  minHeight: 44,
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-secondary)",
};
const dangerButtonStyle = {
  ...smallButtonStyle,
  border: "1px solid var(--border-danger)",
  color: "var(--accent-danger)",
};

/** "Dec 1, 2026" for a "YYYY-MM-DD" day, read as a local date so no time zone shifts it a day. */
function formatDay(day: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!match) return day;
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

/** When a progress note was written, in the viewer's locale ("Oct 12, 3:14 PM"). */
function formatMoment(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/** "2 of 5 milestones done", the words the progress bar is read out with. */
function progressText(progress: Goal["progress"]): string {
  if (progress.total === 0) return "No milestones yet";
  const noun = progress.total === 1 ? "milestone" : "milestones";
  return `${progress.done} of ${progress.total} ${noun} done`;
}

/** The status buttons a goal offers in its current status. */
function statusActions(status: GoalStatus): { status: GoalStatus; label: string }[] {
  switch (status) {
    case "active":
      return [
        { status: "paused", label: "Pause" },
        { status: "completed", label: "Complete" },
        { status: "archived", label: "Archive" },
      ];
    case "paused":
      return [
        { status: "active", label: "Resume" },
        { status: "completed", label: "Complete" },
        { status: "archived", label: "Archive" },
      ];
    case "completed":
      return [
        { status: "active", label: "Reopen" },
        { status: "archived", label: "Archive" },
      ];
    case "archived":
      return [{ status: "active", label: "Restore" }];
  }
}

/** A 404: the goal was deleted elsewhere (a chat, another tab), so the list is out of date. */
function isGone(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

function CategoryChip({ category }: { category: GoalCategory }) {
  const color = CATEGORY_COLORS[category] ?? CATEGORY_COLORS.other;
  const label = CATEGORIES.find((c) => c.value === category)?.label ?? category;
  return (
    <span
      className="mono-tag px-2 py-1 rounded-[6px]"
      style={{ color, border: `1px solid ${color}` }}
    >
      {label}
    </span>
  );
}

function StatusChip({ status }: { status: GoalStatus }) {
  const style = STATUS_STYLES[status];
  return (
    <span
      className="mono-tag px-2 py-1 rounded-[6px]"
      style={{ color: style.color, background: style.fill, border: `1px solid ${style.border}` }}
    >
      {style.label}
    </span>
  );
}

function GoalProgress({ goal }: { goal: Goal }) {
  const { done, total } = goal.progress;
  const text = progressText(goal.progress);
  const percent = total > 0 ? Math.round((Math.min(done, total) / total) * 100) : 0;
  const fill = goal.status === "completed" ? "var(--accent-success)" : "var(--accent-primary)";
  return (
    <div className="flex items-center gap-3 mt-3">
      <div
        // No milestones: nothing to measure, so the empty track is decoration and the words say so.
        role={total > 0 ? "progressbar" : undefined}
        aria-hidden={total > 0 ? undefined : true}
        aria-label={total > 0 ? `Progress on ${goal.title}` : undefined}
        aria-valuemin={total > 0 ? 0 : undefined}
        aria-valuemax={total > 0 ? total : undefined}
        aria-valuenow={total > 0 ? Math.min(done, total) : undefined}
        aria-valuetext={total > 0 ? text : undefined}
        className="h-2 flex-1 min-w-0 rounded-full overflow-hidden"
        style={{ background: "var(--bg-hover)" }}
      >
        <div
          className="h-full rounded-full"
          style={{
            width: `${percent}%`,
            background: fill,
            transition: "width var(--dur-base) var(--ease-out)",
          }}
        />
      </div>
      <span className="text-xs shrink-0" style={{ color: "var(--text-secondary)" }}>
        {text}
      </span>
    </div>
  );
}

interface MilestoneRow {
  key: number;
  title: string;
  due: string;
}

function NewGoalForm({
  panelId,
  onCreated,
  onCancel,
}: {
  panelId: string;
  onCreated: (goal: GoalDetail) => void;
  onCancel: () => void;
}) {
  const headingId = useId();
  const fieldId = useId();
  const nextKey = useRef(1);
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState<GoalCategory>("other");
  const [targetDate, setTargetDate] = useState("");
  const [description, setDescription] = useState("");
  const [rows, setRows] = useState<MilestoneRow[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const addRow = () => {
    const key = nextKey.current;
    nextKey.current += 1;
    setRows((prev) => [...prev, { key, title: "", due: "" }]);
  };

  const editRow = (key: number, patch: Partial<MilestoneRow>) =>
    setRows((prev) => prev.map((row) => (row.key === key ? { ...row, ...patch } : row)));

  const removeRow = (key: number) => setRows((prev) => prev.filter((row) => row.key !== key));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (saving) return;
    const name = title.trim();
    if (!name) {
      setError("Give the goal a title.");
      return;
    }
    const body: CreateGoalRequest = { title: name, category };
    if (targetDate) body.target_date = targetDate;
    if (description.trim()) body.description = description.trim();
    // A row left blank is a row the user never filled in, not a milestone.
    const milestones: GoalMilestoneInput[] = rows
      .filter((row) => row.title.trim())
      .map((row) => ({ title: row.title.trim(), ...(row.due ? { due_date: row.due } : {}) }));
    if (milestones.length > 0) body.milestones = milestones;

    setSaving(true);
    setError("");
    try {
      onCreated(await createGoal(body));
    } catch (err) {
      setError(errorText(err, "The goal could not be saved. Try again."));
      setSaving(false);
    }
  };

  return (
    <section
      id={panelId}
      aria-labelledby={headingId}
      className="rounded-[14px] p-4 sm:p-6"
      style={panelStyle}
    >
      <div className="eyebrow mb-1">Add</div>
      <h2 id={headingId} className="mb-4">
        New goal
      </h2>
      <form onSubmit={(e) => void submit(e)} noValidate className="space-y-4">
        {error && <ErrorAlert>{error}</ErrorAlert>}
        <div>
          <label className={labelCls} htmlFor={`${fieldId}-title`}>
            Title
          </label>
          <input
            id={`${fieldId}-title`}
            className={inputCls}
            style={inputStyle}
            value={title}
            required
            maxLength={TITLE_MAX}
            placeholder="Run a 10k by June"
            onChange={(e) => setTitle(e.target.value)}
          />
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className={labelCls} htmlFor={`${fieldId}-category`}>
              Category
            </label>
            <select
              id={`${fieldId}-category`}
              className={inputCls}
              style={inputStyle}
              value={category}
              onChange={(e) => setCategory(e.target.value as GoalCategory)}
            >
              {CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className={labelCls} htmlFor={`${fieldId}-target`}>
              Target date (optional)
            </label>
            <input
              id={`${fieldId}-target`}
              type="date"
              className={inputCls}
              style={inputStyle}
              value={targetDate}
              onChange={(e) => setTargetDate(e.target.value)}
            />
          </div>
        </div>
        <div>
          <label className={labelCls} htmlFor={`${fieldId}-description`}>
            Description (optional)
          </label>
          <textarea
            id={`${fieldId}-description`}
            className={`${inputCls} resize-y`}
            style={inputStyle}
            rows={3}
            value={description}
            maxLength={DESCRIPTION_MAX}
            placeholder="Why it matters, or what done looks like."
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        <fieldset className="space-y-3">
          <legend className={labelCls}>First milestones (optional)</legend>
          {rows.map((row, index) => {
            const rowId = `${fieldId}-m${row.key}`;
            return (
              <div
                key={row.key}
                className="flex flex-wrap items-end gap-2 rounded-[10px] p-3"
                style={rowStyle}
              >
                <div className="flex-[2] min-w-[12rem]">
                  <label id={`${rowId}-label`} className={labelCls} htmlFor={`${rowId}-title`}>
                    Milestone {index + 1}
                  </label>
                  <input
                    id={`${rowId}-title`}
                    className={inputCls}
                    style={inputStyle}
                    value={row.title}
                    maxLength={TITLE_MAX}
                    onChange={(e) => editRow(row.key, { title: e.target.value })}
                  />
                </div>
                <div className="flex-1 min-w-[9rem]">
                  <label id={`${rowId}-due-label`} className={labelCls} htmlFor={`${rowId}-due`}>
                    Due date
                  </label>
                  <input
                    id={`${rowId}-due`}
                    type="date"
                    aria-labelledby={`${rowId}-label ${rowId}-due-label`}
                    className={inputCls}
                    style={inputStyle}
                    value={row.due}
                    onChange={(e) => editRow(row.key, { due: e.target.value })}
                  />
                </div>
                <button
                  type="button"
                  onClick={() => removeRow(row.key)}
                  aria-label={`Remove milestone ${index + 1}`}
                  className="inline-flex items-center justify-center rounded-[10px] shrink-0"
                  style={{ width: 44, height: 44, ...insetStyle, color: "var(--text-muted)" }}
                >
                  <X className="w-4 h-4" aria-hidden />
                </button>
              </div>
            );
          })}
          {rows.length < FIRST_MILESTONES_MAX ? (
            <button
              type="button"
              onClick={addRow}
              className={smallButtonCls}
              style={smallButtonStyle}
            >
              <Plus className="w-3.5 h-3.5" aria-hidden />
              Add a milestone
            </button>
          ) : (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Up to {FIRST_MILESTONES_MAX} to start; add more from the goal once it is saved.
            </p>
          )}
        </fieldset>

        <div className="flex flex-wrap items-center justify-end gap-2">
          <button type="button" onClick={onCancel} className={secondaryCls} style={secondaryStyle}>
            Cancel
          </button>
          <button type="submit" disabled={saving} className={primaryCls} style={primaryStyle}>
            {saving && <Loader2 className="w-4 h-4 animate-spin" aria-hidden />}
            Save goal
          </button>
        </div>
      </form>
    </section>
  );
}

/** "Add milestone" under an open goal's milestones. Resolves to "" when saved, else the reason. */
function AddMilestoneForm({
  goalTitle,
  disabled,
  onAdd,
}: {
  goalTitle: string;
  disabled: boolean;
  onAdd: (milestone: GoalMilestoneInput) => Promise<string>;
}) {
  const fieldId = useId();
  const [title, setTitle] = useState("");
  const [due, setDue] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const name = title.trim();
    if (!name) {
      setError("Name the milestone first.");
      return;
    }
    setSaving(true);
    setError("");
    const failed = await onAdd(due ? { title: name, due_date: due } : { title: name });
    setSaving(false);
    if (failed) {
      setError(failed);
      return;
    }
    setTitle("");
    setDue("");
  };

  return (
    <form
      onSubmit={(e) => void submit(e)}
      noValidate
      aria-label={`Add a milestone to ${goalTitle}`}
      className="mt-3 space-y-2"
    >
      <div className="flex flex-wrap items-end gap-2">
        <div className="flex-[2] min-w-[12rem]">
          <label className={labelCls} htmlFor={`${fieldId}-title`}>
            New milestone
          </label>
          <input
            id={`${fieldId}-title`}
            className={inputCls}
            style={inputStyle}
            value={title}
            maxLength={TITLE_MAX}
            onChange={(e) => setTitle(e.target.value)}
          />
        </div>
        <div className="flex-1 min-w-[9rem]">
          <label className={labelCls} htmlFor={`${fieldId}-due`}>
            Due date (optional)
          </label>
          <input
            id={`${fieldId}-due`}
            type="date"
            className={inputCls}
            style={inputStyle}
            value={due}
            onChange={(e) => setDue(e.target.value)}
          />
        </div>
        <button
          type="submit"
          disabled={disabled || saving}
          className={smallButtonCls}
          style={smallButtonStyle}
        >
          {saving ? spinner : <Plus className="w-3.5 h-3.5" aria-hidden />}
          Add milestone
        </button>
      </div>
      {error && (
        <p role="alert" className="text-xs" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
    </form>
  );
}

/** "Add note" under an open goal's progress log. Resolves to "" when saved, else the reason. */
function AddNoteForm({
  goalTitle,
  milestones,
  onAdd,
}: {
  goalTitle: string;
  milestones: GoalMilestone[];
  onAdd: (note: string, milestoneId: string) => Promise<string>;
}) {
  const fieldId = useId();
  const [note, setNote] = useState("");
  const [milestoneId, setMilestoneId] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  // A milestone dropped since it was picked is no longer an option, and the select then shows
  // "The whole goal": the note goes where the select shows.
  const selected = milestones.some((m) => m.id === milestoneId) ? milestoneId : "";

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const text = note.trim();
    if (!text) {
      setError("Write the note first.");
      return;
    }
    setSaving(true);
    setError("");
    const failed = await onAdd(text, selected);
    setSaving(false);
    if (failed) {
      setError(failed);
      return;
    }
    setNote("");
    setMilestoneId("");
  };

  return (
    <form
      onSubmit={(e) => void submit(e)}
      noValidate
      aria-label={`Add a note to ${goalTitle}`}
      className="mt-3 space-y-2"
    >
      <div>
        <label className={labelCls} htmlFor={`${fieldId}-note`}>
          Note
        </label>
        <textarea
          id={`${fieldId}-note`}
          className={`${inputCls} resize-y`}
          style={inputStyle}
          rows={2}
          value={note}
          maxLength={NOTE_MAX}
          placeholder="Ran 5k without stopping."
          onChange={(e) => setNote(e.target.value)}
        />
      </div>
      <div className="flex flex-wrap items-end gap-2">
        {milestones.length > 0 && (
          <div className="flex-1 min-w-[12rem]">
            <label className={labelCls} htmlFor={`${fieldId}-milestone`}>
              About a milestone (optional)
            </label>
            <select
              id={`${fieldId}-milestone`}
              className={inputCls}
              style={inputStyle}
              value={selected}
              onChange={(e) => setMilestoneId(e.target.value)}
            >
              <option value="">The whole goal</option>
              {milestones.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.title}
                </option>
              ))}
            </select>
          </div>
        )}
        <button type="submit" disabled={saving} className={smallButtonCls} style={smallButtonStyle}>
          {saving ? spinner : <Plus className="w-3.5 h-3.5" aria-hidden />}
          Add note
        </button>
      </div>
      {error && (
        <p role="alert" className="text-xs" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
    </form>
  );
}

interface GoalCardProps {
  goal: Goal;
  /** The server's goal after a change made from this card. */
  onUpdated: (goal: Goal) => void;
  onDelete: (goal: Goal) => void;
  /** The server no longer has this goal (404). */
  onGone: () => void;
}

function GoalCard({ goal, onUpdated, onDelete, onGone }: GoalCardProps) {
  const titleId = useId();
  const planId = useId();
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<GoalDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  // One change at a time per card: every control waits while one is in flight.
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState("");
  const [planError, setPlanError] = useState("");

  const loadDetail = async () => {
    setDetailLoading(true);
    setDetailError("");
    try {
      setDetail(await getGoal(goal.id));
    } catch (err) {
      if (isGone(err)) onGone();
      else setDetailError(errorText(err, "This goal's plan could not be loaded."));
    } finally {
      setDetailLoading(false);
    }
  };

  const toggleOpen = () => {
    const next = !open;
    setOpen(next);
    // Loaded on first open, then kept: every change below hands back the goal and its plan.
    if (next && detail === null && !detailLoading) void loadDetail();
  };

  /** Sends one change; resolves to "" when the server took it, else the reason to show. */
  const change = async (
    key: string,
    body: UpdateGoalRequest,
    fallback: string,
  ): Promise<string> => {
    setBusy(key);
    try {
      const updated = await updateGoal(goal.id, body);
      // A change never touches the log, and its answer carries only the newest notes: keep the
      // log already shown, and leave a plan not yet opened to load in full when it is.
      setDetail((prev) => (prev ? { ...updated, entries: prev.entries } : prev));
      onUpdated(updated);
      return "";
    } catch (err) {
      if (isGone(err)) {
        onGone();
        return "";
      }
      return errorText(err, fallback);
    } finally {
      setBusy(null);
    }
  };

  const setStatus = async (status: GoalStatus, label: string) => {
    setActionError("");
    const fallback = `${label} did not work. Try again.`;
    setActionError(await change(`status:${status}`, { status }, fallback));
  };

  const editMilestone = async (milestone: GoalMilestone, body: UpdateGoalRequest) => {
    setPlanError("");
    const fallback = `“${milestone.title}” could not be changed. Try again.`;
    setPlanError(await change(`m:${milestone.id}`, body, fallback));
  };

  const addMilestone = (milestone: GoalMilestoneInput) =>
    change(
      "add-milestone",
      { add_milestones: [milestone] },
      "The milestone could not be added. Try again.",
    );

  const addNote = async (note: string, milestoneId: string): Promise<string> => {
    try {
      const entry = await addGoalEntry(
        goal.id,
        milestoneId ? { note, milestone_id: milestoneId } : { note },
      );
      setDetail((prev) => prev && { ...prev, entries: [entry, ...prev.entries] });
      return "";
    } catch (err) {
      if (isGone(err)) {
        onGone();
        return "";
      }
      return errorText(err, "The note could not be saved. Try again.");
    }
  };

  const milestones = detail?.milestones ?? [];
  // Newest first, whatever order the server sends.
  const entries = [...(detail?.entries ?? [])].sort((a, b) =>
    b.created_at.localeCompare(a.created_at),
  );
  const milestoneTitle = (id: string | null) =>
    id ? milestones.find((m) => m.id === id)?.title : undefined;

  return (
    <article aria-labelledby={titleId} className="rounded-[12px] p-4" style={rowStyle}>
      <h3
        id={titleId}
        className="text-base font-semibold break-words"
        style={{ color: "var(--text-primary)" }}
      >
        {goal.title}
      </h3>
      <div
        className="flex items-center gap-2 flex-wrap mt-2 text-xs"
        style={{ color: "var(--text-muted)" }}
      >
        <CategoryChip category={goal.category} />
        {goal.status !== "active" && <StatusChip status={goal.status} />}
        <span>{goal.target_date ? `Target ${formatDay(goal.target_date)}` : "No target date"}</span>
        {goal.check_in !== "none" && (
          <span>· {goal.check_in === "daily" ? "Daily" : "Weekly"} check-in</span>
        )}
      </div>
      {goal.current_state && (
        <p className="text-sm mt-2 break-words" style={{ color: "var(--text-secondary)" }}>
          <span style={{ color: "var(--text-muted)" }}>Where it stands: </span>
          {goal.current_state}
        </p>
      )}
      <GoalProgress goal={goal} />

      {actionError && (
        <div className="mt-3">
          <ErrorAlert>{actionError}</ErrorAlert>
        </div>
      )}
      <div className="flex flex-wrap gap-2 mt-3">
        <button
          type="button"
          onClick={toggleOpen}
          aria-expanded={open}
          aria-controls={planId}
          aria-label={`Plan and notes for ${goal.title}`}
          className={smallButtonCls}
          style={smallButtonStyle}
        >
          <ChevronDown
            className="w-3.5 h-3.5 transition-transform"
            style={{ transform: open ? "rotate(180deg)" : "none" }}
            aria-hidden
          />
          Plan and notes
        </button>
        {statusActions(goal.status).map((action) => (
          <button
            key={action.status}
            type="button"
            onClick={() => void setStatus(action.status, action.label)}
            disabled={busy !== null}
            aria-label={`${action.label} goal: ${goal.title}`}
            className={smallButtonCls}
            style={smallButtonStyle}
          >
            {busy === `status:${action.status}` && spinner}
            {action.label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => onDelete(goal)}
          disabled={busy !== null}
          aria-label={`Delete goal: ${goal.title}`}
          className={smallButtonCls}
          style={dangerButtonStyle}
        >
          <Trash2 className="w-3.5 h-3.5" aria-hidden />
          Delete
        </button>
      </div>

      <div
        id={planId}
        hidden={!open}
        className="mt-4 pt-4"
        style={{ borderTop: "1px solid var(--claw-border)" }}
      >
        {detailError ? (
          <ErrorAlert>
            {detailError}{" "}
            <button
              type="button"
              className="underline font-medium"
              onClick={() => void loadDetail()}
            >
              Try again
            </button>
          </ErrorAlert>
        ) : detail === null ? (
          <p
            role="status"
            className="text-sm flex items-center gap-2"
            style={{ color: "var(--text-muted)" }}
          >
            {spinner}
            Loading the plan…
          </p>
        ) : (
          <>
            {detail.description && (
              <p
                className="text-sm mb-4 whitespace-pre-wrap break-words"
                style={{ color: "var(--text-secondary)" }}
              >
                {detail.description}
              </p>
            )}

            <h4 className="text-sm font-semibold mb-2" style={{ color: "var(--text-primary)" }}>
              Milestones
            </h4>
            {planError && (
              <p role="alert" className="text-xs mb-2" style={{ color: "var(--accent-danger)" }}>
                {planError}
              </p>
            )}
            {milestones.length === 0 ? (
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                No milestones yet. Break the goal into a few steps you can tick off.
              </p>
            ) : (
              <ul className="space-y-1.5">
                {milestones.map((m) => {
                  const dropped = m.state === "dropped";
                  const boxId = `${planId}-${m.id}`;
                  return (
                    <li
                      key={m.id}
                      className="flex items-center gap-3 rounded-[10px] px-3 py-1"
                      style={{ minHeight: 44, ...insetStyle }}
                    >
                      <input
                        id={boxId}
                        type="checkbox"
                        checked={m.state === "done"}
                        disabled={dropped || busy !== null}
                        aria-describedby={m.due_date ? `${boxId}-due` : undefined}
                        onChange={() =>
                          void editMilestone(
                            m,
                            m.state === "done"
                              ? { reopen_milestones: [m.id] }
                              : { complete_milestones: [m.id] },
                          )
                        }
                        className="w-4 h-4 shrink-0"
                        style={{ accentColor: "var(--accent-primary)" }}
                      />
                      <div className="flex-1 min-w-0 py-1">
                        <label
                          htmlFor={boxId}
                          className="block text-sm break-words cursor-pointer"
                          style={{
                            color:
                              dropped || m.state === "done"
                                ? "var(--text-muted)"
                                : "var(--text-primary)",
                            textDecoration: dropped ? "line-through" : "none",
                          }}
                        >
                          {m.title}
                        </label>
                        {(m.due_date || dropped) && (
                          <p
                            id={`${boxId}-due`}
                            className="text-xs mt-0.5"
                            style={{ color: "var(--text-muted)" }}
                          >
                            {[m.due_date && `Due ${formatDay(m.due_date)}`, dropped && "Dropped"]
                              .filter(Boolean)
                              .join(" · ")}
                          </p>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          void editMilestone(
                            m,
                            dropped ? { reopen_milestones: [m.id] } : { drop_milestones: [m.id] },
                          )
                        }
                        disabled={busy !== null}
                        aria-label={`${dropped ? "Restore" : "Drop"} milestone: ${m.title}`}
                        className={
                          "tap-target shrink-0 inline-flex items-center gap-1 px-2 py-1 " +
                          "rounded-[8px] text-xs font-medium disabled:opacity-50"
                        }
                        style={{ color: "var(--text-muted)" }}
                      >
                        {busy === `m:${m.id}` && spinner}
                        {dropped ? "Restore" : "Drop"}
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
            <AddMilestoneForm
              goalTitle={goal.title}
              disabled={busy !== null}
              onAdd={addMilestone}
            />

            <h4
              className="text-sm font-semibold mt-6 mb-2"
              style={{ color: "var(--text-primary)" }}
            >
              Progress log
            </h4>
            {entries.length === 0 ? (
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                No notes yet. Add one below, or tell Crawler in a chat how it went.
              </p>
            ) : (
              <ul className="space-y-2" aria-label={`Progress log for ${goal.title}`}>
                {entries.map((entry) => {
                  const about = milestoneTitle(entry.milestone_id);
                  const agent = entry.source === "agent";
                  return (
                    <li key={entry.id} className="rounded-[10px] px-3 py-2" style={insetStyle}>
                      <div
                        className="flex items-center gap-2 flex-wrap text-xs"
                        style={{ color: "var(--text-muted)" }}
                      >
                        <span
                          className="mono-tag px-1.5 py-0.5 rounded-[6px]"
                          style={{
                            color: agent ? "var(--accent-primary)" : "var(--text-secondary)",
                            border: `1px solid ${agent ? "var(--border-accent)" : "var(--claw-border)"}`,
                          }}
                        >
                          {agent ? "Crawler" : "You"}
                        </span>
                        <time dateTime={entry.created_at}>{formatMoment(entry.created_at)}</time>
                        {about && <span className="break-words">on “{about}”</span>}
                      </div>
                      <p
                        className="text-sm mt-1 whitespace-pre-wrap break-words"
                        style={{ color: "var(--text-primary)" }}
                      >
                        {entry.note}
                      </p>
                    </li>
                  );
                })}
              </ul>
            )}
            <AddNoteForm
              goalTitle={goal.title}
              milestones={milestones.filter((m) => m.state !== "dropped")}
              onAdd={addNote}
            />
          </>
        )}
      </div>
    </article>
  );
}

function EmptyState({ filter }: { filter: Filter }) {
  if (filter === "paused") {
    return (
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        No paused goals. Pausing a goal keeps its plan and notes until you resume it.
      </p>
    );
  }
  if (filter === "completed") {
    return (
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        No completed goals yet. Mark a goal Complete when you reach it.
      </p>
    );
  }
  return (
    <div className="space-y-2 text-sm" style={{ color: "var(--text-secondary)" }}>
      <p className="font-medium" style={{ color: "var(--text-primary)" }}>
        {filter === "all" ? "No goals yet." : "No active goals."}
      </p>
      <p>
        A goal is something you are working toward, like passing an exam, saving for a laptop or
        running a 10k. Give it a target date and a few milestones, tick them off as you go and keep
        notes on how it is going.
      </p>
      <p>Tell Crawler about a goal in chat and it can set one up with you.</p>
    </div>
  );
}

export default function GoalsPage() {
  const listHeadingId = useId();
  const formPanelId = useId();
  const [filter, setFilter] = useState<Filter>("active");
  const [goals, setGoals] = useState<Goal[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<Goal | null>(null);
  // The filter on screen now. A card's change can answer after the user picked another filter,
  // and its handler, made in an earlier render, must judge against the list shown now.
  const filterRef = useRef(filter);

  useEffect(() => {
    filterRef.current = filter;
  }, [filter]);

  useEffect(() => {
    let cancelled = false;
    listGoals(filter)
      .then((list) => {
        if (cancelled) return;
        setGoals(Array.isArray(list) ? list : []);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "Your goals could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [filter, attempt]);

  const reload = () => {
    setLoadError("");
    setGoals(null);
    setAttempt((n) => n + 1);
  };

  const chooseFilter = (next: Filter) => {
    if (next === filter) return;
    setNotice("");
    setLoadError("");
    setGoals(null);
    setFilter(next);
  };

  const shown = (goal: Goal) =>
    filterRef.current === "all" || goal.status === filterRef.current;

  const handleCreated = (goal: GoalDetail) => {
    setCreating(false);
    setNotice(`Saved “${goal.title}”.`);
    if (shown(goal)) {
      setGoals((prev) => [goal, ...(prev ?? []).filter((g) => g.id !== goal.id)]);
    } else {
      // A new goal is active; the filter showing something else would hide it.
      setLoadError("");
      setGoals(null);
      setFilter("active");
    }
  };

  const handleUpdated = (goal: Goal) => {
    if (!shown(goal)) {
      const where = goal.status === "archived" ? " Choose All to see archived goals." : "";
      const now = STATUS_STYLES[goal.status].label.toLowerCase();
      setNotice(`“${goal.title}” is now ${now}.${where}`);
    }
    setGoals((prev) => {
      if (!prev) return prev;
      if (!shown(goal)) return prev.filter((g) => g.id !== goal.id);
      return prev.map((g) => (g.id === goal.id ? goal : g));
    });
  };

  const handleGone = () => {
    setNotice("That goal no longer exists, so the list was read again.");
    reload();
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    const target = deleteTarget;
    try {
      await deleteGoal(target.id);
    } catch (err) {
      // Already gone (deleted from a chat or another tab): the outcome the user asked for.
      if (!isGone(err)) throw err;
    }
    setGoals((prev) => prev && prev.filter((g) => g.id !== target.id));
    setNotice(`Deleted “${target.title}”.`);
    setDeleteTarget(null);
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="eyebrow mb-2">Plans</div>
            <h1 className="flex items-center gap-2.5" style={{ color: "var(--text-primary)" }}>
              <Target className="w-6 h-6" aria-hidden style={{ color: "var(--accent-primary)" }} />
              Goals
            </h1>
          </div>
          <button
            type="button"
            onClick={() => setCreating((v) => !v)}
            aria-expanded={creating}
            aria-controls={creating ? formPanelId : undefined}
            className={primaryCls}
            style={primaryStyle}
          >
            <Plus className="w-4 h-4" aria-hidden />
            New goal
          </button>
        </div>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          What you are working toward, with milestones and a log of how it is going. A goal never
          runs anything by itself: Crawler reads and updates your goals only when you ask in a chat.
        </p>
      </div>

      {creating && (
        <NewGoalForm
          panelId={formPanelId}
          onCreated={handleCreated}
          onCancel={() => setCreating(false)}
        />
      )}

      <p
        role="status"
        className={notice ? "text-sm" : "sr-only"}
        style={{ color: "var(--text-secondary)" }}
      >
        {notice}
      </p>

      <section
        aria-labelledby={listHeadingId}
        className="rounded-[14px] p-4 sm:p-6"
        style={panelStyle}
      >
        <div className="flex items-center justify-between gap-3 flex-wrap mb-4">
          <h2 id={listHeadingId}>Your goals</h2>
          <div role="group" aria-label="Show goals" className="flex gap-1.5 flex-wrap">
            {FILTERS.map((f) => {
              const active = filter === f.value;
              return (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => chooseFilter(f.value)}
                  aria-pressed={active}
                  className="px-3 rounded-[8px] text-xs font-medium transition-colors"
                  style={{
                    minHeight: 44,
                    background: active ? "var(--accent-glow)" : "var(--claw-surface)",
                    border: `1px solid ${active ? "var(--border-accent)" : "var(--claw-border)"}`,
                    color: active ? "var(--accent-primary)" : "var(--text-secondary)",
                  }}
                >
                  {f.label}
                </button>
              );
            })}
          </div>
        </div>

        {loadError ? (
          <ErrorAlert>
            {loadError}{" "}
            <button type="button" className="underline font-medium" onClick={reload}>
              Try again
            </button>
          </ErrorAlert>
        ) : goals === null ? (
          <p
            role="status"
            className="text-sm flex items-center gap-2"
            style={{ color: "var(--text-muted)" }}
          >
            <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
            Loading goals…
          </p>
        ) : goals.length === 0 ? (
          <EmptyState filter={filter} />
        ) : (
          <ul className="space-y-3">
            {goals.map((goal) => (
              <li key={goal.id}>
                <GoalCard
                  goal={goal}
                  onUpdated={handleUpdated}
                  onDelete={setDeleteTarget}
                  onGone={handleGone}
                />
              </li>
            ))}
          </ul>
        )}
      </section>

      <ConfirmDialog
        open={deleteTarget !== null}
        danger
        title="Delete this goal?"
        message={
          deleteTarget
            ? `“${deleteTarget.title}”, its milestones and its progress log will be deleted. ` +
              "This cannot be undone."
            : ""
        }
        confirmLabel="Delete goal"
        onCancel={() => setDeleteTarget(null)}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
