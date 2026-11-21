/**
 * Automations page: the signed-in user's scheduled tasks (create, run now, pause or resume,
 * delete), reminders (add, cancel) and app triggers (pause or resume, delete).
 *
 * Why it exists: these run on the user's behalf while they are away, and until now they could only
 * be seen and changed from the chat. Triggers are still created in the chat, where the approval card
 * shows the whole rule. Every refusal (the switch is off, a rule, a taken name) is the server's own
 * sentence.
 */

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Bell, CalendarClock, Loader2, Pause, Play, Plus, RefreshCw, Trash2, Zap } from "lucide-react";
import type { Reminder, ScheduleFreq, ScheduledTask, ScheduleTool, TriggerItem } from "@/types";
import {
  browserTimeZone,
  cancelReminder,
  createReminder,
  createSchedule,
  deleteSchedule,
  deleteTrigger,
  listReminders,
  listScheduleTools,
  listSchedules,
  listTriggers,
  runScheduleNow,
  setSchedulePaused,
  setTriggerPaused,
} from "@/services/api";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
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

const FREQS: { value: ScheduleFreq; label: string }[] = [
  { value: "once", label: "Once" },
  { value: "daily", label: "Every day" },
  { value: "weekdays", label: "Every weekday" },
  { value: "weekly", label: "Every week" },
  { value: "monthly", label: "Every month" },
];
const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
// The server's limit on read tools per task (MAX_READ_TOOLS in services/tools/schedule.py).
const MAX_TOOLS = 8;

type Target = { kind: "task" | "reminder" | "trigger"; id: string; label: string };

const CONFIRM: Record<Target["kind"], { title: string; message: (label: string) => string; label: string }> = {
  task: {
    title: "Delete this task?",
    message: (label) => `"${label}" won't run again. Its past results stay in its conversation.`,
    label: "Delete",
  },
  trigger: {
    title: "Delete this trigger?",
    message: (label) => `"${label}" stops watching. Its past results stay in its conversation.`,
    label: "Delete",
  },
  reminder: {
    title: "Cancel this reminder?",
    message: (label) => `You won't be reminded about "${label}".`,
    label: "Cancel reminder",
  },
};

interface Data {
  tasks: ScheduledTask[];
  reminders: Reminder[];
  triggers: TriggerItem[];
}

function words(name: string): string {
  return name.replace(/_/g, " ");
}

function Loading() {
  return (
    <p role="status" className="text-sm" style={{ color: "var(--text-muted)" }}>
      Loading…
    </p>
  );
}

function Section({ icon, title, action, children }: { icon: ReactNode; title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-[14px] p-6" style={panelStyle}>
      <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
        <h2 className="flex items-center gap-2">
          {icon}
          {title}
        </h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function Row({ title, status, lines, actions }: { title: string; status?: string; lines: (string | null | undefined)[]; actions: ReactNode }) {
  return (
    <li
      className="rounded-[10px] px-4 py-3 flex items-start gap-3 flex-wrap"
      style={{ background: "var(--claw-surface)", border: "1px solid var(--claw-border)" }}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
            {title}
          </span>
          {status && (
            <span
              className="mono-tag px-2 py-0.5 rounded-[6px]"
              style={{
                color: status === "active" ? "var(--accent-success)" : status === "error" ? "var(--accent-danger)" : "var(--text-muted)",
                border: "1px solid currentColor",
              }}
            >
              {status}
            </span>
          )}
        </div>
        {lines.filter(Boolean).map((line, i) => (
          <p key={i} className="text-xs mt-1 break-words" style={{ color: "var(--text-secondary)" }}>
            {line}
          </p>
        ))}
      </div>
      <div className="flex items-center gap-1 shrink-0">{actions}</div>
    </li>
  );
}

function IconButton({ label, onClick, disabled, danger, children }: { label: string; onClick: () => void; disabled?: boolean; danger?: boolean; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
      className="tap-target p-1.5 rounded-[6px] disabled:opacity-50"
      style={{ color: danger ? "var(--accent-danger)" : "var(--text-muted)" }}
    >
      {children}
    </button>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return (
    <p className="text-sm py-4" style={{ color: "var(--text-muted)" }}>
      {children}
    </p>
  );
}

function NewTaskForm({ onDone }: { onDone: () => void }) {
  const zone = browserTimeZone();
  const [label, setLabel] = useState("");
  const [prompt, setPrompt] = useState("");
  const [freq, setFreq] = useState<ScheduleFreq>("weekdays");
  const [time, setTime] = useState("08:00");
  const [days, setDays] = useState<string[]>(["mon"]);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [date, setDate] = useState("");
  const [tools, setTools] = useState<ScheduleTool[] | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    listScheduleTools()
      .then(setTools)
      .catch((err) => setError(errorText(err, "Could not load what a task may read.")));
  }, []);

  const groups = new Map<string, ScheduleTool[]>();
  for (const tool of tools ?? []) {
    const app = tool.name.split(".")[0];
    groups.set(app, [...(groups.get(app) ?? []), tool]);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createSchedule({
        label: label.trim(),
        prompt: prompt.trim(),
        freq,
        time,
        tools: picked,
        ...(freq === "weekly" ? { days } : {}),
        ...(freq === "monthly" ? { day_of_month: dayOfMonth } : {}),
        ...(freq === "once" ? { date } : {}),
        ...(zone ? { timezone: zone } : {}),
      });
      onDone();
    } catch (err) {
      setError(errorText(err, "The task was not saved."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4 mb-5 rounded-[10px] p-4" style={{ border: "1px solid var(--claw-border)" }}>
      {error && <ErrorAlert>{error}</ErrorAlert>}
      <div>
        <label htmlFor="task-label" className={labelCls}>
          Name
        </label>
        <input id="task-label" required maxLength={80} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Canvas summary" className={inputCls} style={inputStyle} />
      </div>
      <div>
        <label htmlFor="task-prompt" className={labelCls}>
          What should Crawler do?
        </label>
        <textarea
          id="task-prompt"
          required
          maxLength={2000}
          rows={3}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          placeholder="List everything due on Canvas in the next 3 days, grouped by course."
          className={`${inputCls} resize-y`}
          style={inputStyle}
        />
      </div>
      <div className="flex gap-3 flex-wrap">
        <div>
          <label htmlFor="task-freq" className={labelCls}>
            Repeat
          </label>
          <select id="task-freq" value={freq} onChange={(e) => setFreq(e.target.value as ScheduleFreq)} className={inputCls} style={inputStyle}>
            {FREQS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </div>
        {freq === "once" && (
          <div>
            <label htmlFor="task-date" className={labelCls}>
              Date
            </label>
            <input id="task-date" type="date" required value={date} onChange={(e) => setDate(e.target.value)} className={inputCls} style={inputStyle} />
          </div>
        )}
        {freq === "monthly" && (
          <div>
            <label htmlFor="task-dom" className={labelCls}>
              Day of the month
            </label>
            <select id="task-dom" value={dayOfMonth} onChange={(e) => setDayOfMonth(Number(e.target.value))} className={inputCls} style={inputStyle}>
              {Array.from({ length: 31 }, (_, i) => i + 1).map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
              <option value={-1}>Last day</option>
            </select>
          </div>
        )}
        <div>
          <label htmlFor="task-time" className={labelCls}>
            Time{zone ? ` (${zone})` : ""}
          </label>
          <input id="task-time" type="time" required value={time} onChange={(e) => setTime(e.target.value)} className={inputCls} style={inputStyle} />
        </div>
      </div>
      {freq === "weekly" && (
        <fieldset>
          <legend className={labelCls}>Days</legend>
          <div className="flex gap-3 flex-wrap">
            {DAYS.map((day) => (
              <label key={day} className="flex items-center gap-1.5 text-sm capitalize" style={{ color: "var(--text-secondary)" }}>
                <input
                  type="checkbox"
                  checked={days.includes(day)}
                  onChange={(e) => setDays(e.target.checked ? [...days, day] : days.filter((d) => d !== day))}
                />
                {day}
              </label>
            ))}
          </div>
        </fieldset>
      )}
      <fieldset>
        <legend className={labelCls}>
          What it may read ({picked.length}/{MAX_TOOLS})
        </legend>
        <p className="text-xs mb-2" style={{ color: "var(--text-muted)" }}>
          Each run can only use what you tick here.
        </p>
        {tools === null && !error && <Loading />}
        <div className="max-h-64 overflow-y-auto space-y-3">
          {[...groups].map(([app, items]) => (
            <div key={app}>
              <div className="eyebrow mb-1">{words(app)}</div>
              {items.map((tool) => {
                const checked = picked.includes(tool.name);
                return (
                  <label key={tool.name} className="flex items-start gap-2 text-sm py-0.5" style={{ color: "var(--text-primary)" }}>
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={checked}
                      disabled={!checked && picked.length >= MAX_TOOLS}
                      onChange={(e) => setPicked(e.target.checked ? [...picked, tool.name] : picked.filter((n) => n !== tool.name))}
                    />
                    <span className="min-w-0">
                      {words(tool.name.split(".")[1] ?? tool.name)}
                      <span className="block text-xs truncate" style={{ color: "var(--text-muted)" }} title={tool.description}>
                        {tool.description}
                      </span>
                    </span>
                  </label>
                );
              })}
            </div>
          ))}
        </div>
      </fieldset>
      <div className="flex gap-2">
        <button type="submit" disabled={busy} className={primaryCls} style={primaryStyle}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          Save task
        </button>
        <button type="button" onClick={onDone} className={secondaryCls} style={secondaryStyle}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function NewReminderForm({ onDone }: { onDone: () => void }) {
  const [title, setTitle] = useState("");
  const [when, setWhen] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      // datetime-local is the browser's local time; the API takes an explicit instant.
      await createReminder({ title: title.trim(), due_at: new Date(when).toISOString() });
      setTitle("");
      setWhen("");
      onDone();
    } catch (err) {
      setError(errorText(err, "The reminder was not saved."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex gap-2 flex-wrap items-end mb-4">
      <div className="flex-1 min-w-[200px]">
        <label htmlFor="reminder-title" className={labelCls}>
          Remind me to
        </label>
        <input id="reminder-title" required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Submit the lab report" className={inputCls} style={inputStyle} />
      </div>
      <div>
        <label htmlFor="reminder-when" className={labelCls}>
          When
        </label>
        <input id="reminder-when" type="datetime-local" required value={when} onChange={(e) => setWhen(e.target.value)} className={inputCls} style={inputStyle} />
      </div>
      <button type="submit" disabled={busy} className={primaryCls} style={primaryStyle}>
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
        Add
      </button>
      {error && (
        <p role="alert" className="w-full text-xs" style={{ color: "var(--accent-danger)" }}>
          {error}
        </p>
      )}
    </form>
  );
}

export default function AutomationsPage() {
  const [data, setData] = useState<Data | null>(null);
  const [loadError, setLoadError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [creating, setCreating] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState("");
  const [notice, setNotice] = useState("");
  const [target, setTarget] = useState<Target | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([listSchedules(), listReminders(), listTriggers()])
      .then(([schedules, reminders, triggers]) => {
        if (cancelled) return;
        setData({ tasks: schedules.tasks, reminders, triggers });
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "Could not load your automations."));
      });
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  const reload = () => setReloadKey((k) => k + 1);

  async function act(id: string, action: () => Promise<void>, done = "") {
    setBusyId(id);
    setActionError("");
    setNotice("");
    try {
      await action();
      setNotice(done);
      reload();
    } catch (err) {
      setActionError(errorText(err, "That didn't work. Try again."));
    } finally {
      setBusyId(null);
    }
  }

  async function confirmDelete() {
    if (!target) return;
    const remove = { task: deleteSchedule, reminder: cancelReminder, trigger: deleteTrigger }[target.kind];
    await remove(target.id);
    setTarget(null);
    reload();
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <div className="eyebrow mb-2">While you're away</div>
        <h1 className="flex items-center gap-2.5" style={{ color: "var(--text-primary)" }}>
          <CalendarClock className="w-6 h-6" style={{ color: "var(--accent-primary)" }} />
          Automations
        </h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Tasks Crawler runs on a schedule, your reminders, and the app triggers you set up in chat. Results
          go to your Telegram and Slack and to a conversation here.
        </p>
      </div>

      {loadError && (
        <div role="alert" className="rounded-[10px] p-4 flex items-center justify-between gap-3 flex-wrap" style={{ background: "var(--fill-danger)", border: "1px solid var(--border-danger)" }}>
          <span className="text-sm" style={{ color: "var(--accent-danger)" }}>
            {loadError}
          </span>
          <button type="button" onClick={reload} className="inline-flex items-center gap-1.5 text-xs font-semibold" style={{ color: "var(--accent-danger)" }}>
            <RefreshCw className="w-3 h-3" /> Retry
          </button>
        </div>
      )}
      {actionError && <ErrorAlert>{actionError}</ErrorAlert>}
      {notice && <ResultLine ok>{notice}</ResultLine>}
      {!data && !loadError && <Loading />}

      {data && (
        <>
          <Section
            icon={<CalendarClock className="w-5 h-5" aria-hidden />}
            title="Scheduled tasks"
            action={
              !creating && (
                <button type="button" onClick={() => setCreating(true)} className={secondaryCls} style={secondaryStyle}>
                  <Plus className="w-4 h-4" /> New task
                </button>
              )
            }
          >
            {creating && (
              <NewTaskForm
                onDone={() => {
                  setCreating(false);
                  reload();
                }}
              />
            )}
            {data.tasks.length === 0 ? (
              <Empty>No scheduled tasks yet.</Empty>
            ) : (
              <ul className="space-y-2">
                {data.tasks.map((task) => (
                  <Row
                    key={task.id}
                    title={task.label}
                    status={task.status}
                    lines={[
                      `${task.schedule}${task.timezone ? ` (${task.timezone})` : ""}`,
                      task.next_run_local && `Next run: ${task.next_run_local}`,
                      task.last_run_local && `Last run: ${task.last_run_local}${task.last_status ? `, ${task.last_status}` : ""}`,
                      task.prompt,
                      task.last_error && `Problem: ${task.last_error}`,
                    ]}
                    actions={
                      <>
                        <IconButton
                          label={`Run ${task.label} now`}
                          disabled={busyId === task.id}
                          onClick={() =>
                            void act(task.id, () => runScheduleNow(task.id), `Started "${task.label}". The result arrives in your chats in a minute or two.`)
                          }
                        >
                          <Zap className="w-3.5 h-3.5" />
                        </IconButton>
                        <IconButton
                          label={task.status === "paused" ? `Resume ${task.label}` : `Pause ${task.label}`}
                          disabled={busyId === task.id}
                          onClick={() => void act(task.id, () => setSchedulePaused(task.id, task.status !== "paused"))}
                        >
                          {task.status === "paused" ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                        </IconButton>
                        <IconButton label={`Delete ${task.label}`} danger onClick={() => setTarget({ kind: "task", id: task.id, label: task.label })}>
                          <Trash2 className="w-3.5 h-3.5" />
                        </IconButton>
                      </>
                    }
                  />
                ))}
              </ul>
            )}
          </Section>

          <Section icon={<Bell className="w-5 h-5" aria-hidden />} title="Reminders">
            <NewReminderForm onDone={reload} />
            {data.reminders.length === 0 ? (
              <Empty>No reminders coming up.</Empty>
            ) : (
              <ul className="space-y-2">
                {data.reminders.map((reminder) => (
                  <Row
                    key={reminder.id}
                    title={reminder.title}
                    lines={[new Date(reminder.due_at).toLocaleString(), reminder.note]}
                    actions={
                      <IconButton label={`Cancel ${reminder.title}`} danger onClick={() => setTarget({ kind: "reminder", id: reminder.id, label: reminder.title })}>
                        <Trash2 className="w-3.5 h-3.5" />
                      </IconButton>
                    }
                  />
                ))}
              </ul>
            )}
          </Section>

          <Section icon={<Zap className="w-5 h-5" aria-hidden />} title="App triggers">
            {data.triggers.length === 0 ? (
              <Empty>No triggers yet. Ask Crawler in chat, for example: "Tell me when a new Canvas grade is posted."</Empty>
            ) : (
              <ul className="space-y-2">
                {data.triggers.map((trigger) => (
                  <Row
                    key={trigger.id}
                    title={trigger.label}
                    status={trigger.status}
                    lines={[
                      `When ${trigger.when}${trigger.account ? ` (${trigger.account})` : ""}: ${trigger.mode === "run_task" ? "runs a task" : "messages you"}`,
                      trigger.last_fired_at && `Last fired: ${new Date(trigger.last_fired_at).toLocaleString()}`,
                      trigger.last_error && `Problem: ${trigger.last_error}`,
                    ]}
                    actions={
                      <>
                        <IconButton
                          label={trigger.status === "paused" ? `Resume ${trigger.label}` : `Pause ${trigger.label}`}
                          disabled={busyId === trigger.id}
                          onClick={() => void act(trigger.id, () => setTriggerPaused(trigger.id, trigger.status !== "paused"))}
                        >
                          {trigger.status === "paused" ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                        </IconButton>
                        <IconButton label={`Delete ${trigger.label}`} danger onClick={() => setTarget({ kind: "trigger", id: trigger.id, label: trigger.label })}>
                          <Trash2 className="w-3.5 h-3.5" />
                        </IconButton>
                      </>
                    }
                  />
                ))}
              </ul>
            )}
          </Section>
        </>
      )}

      <ConfirmDialog
        open={target !== null}
        danger
        title={target ? CONFIRM[target.kind].title : ""}
        message={target ? CONFIRM[target.kind].message(target.label) : ""}
        confirmLabel={target ? CONFIRM[target.kind].label : "Delete"}
        cancelLabel="Keep it"
        onCancel={() => setTarget(null)}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
