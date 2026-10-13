/**
 * TutorLocks: Settings ▸ Permissions ▸ "Tutor locks" (owner only) — the locks that force tutor mode
 * on, for a Canvas course or a whole account, for one account or every account; each with Remove,
 * and a form to add one (a course picked from the owner's own Canvas courses, or typed).
 *
 * Why it exists: tutor mode makes a chat guide with hints instead of handing over answers, and the
 * owner can make that hold for a course whatever the student says. Locks are owner policy that no
 * chat, channel or tool can change, so this page is the one place they are made and removed. The
 * server checks every rule (a course named, no generic or too-short word, at most 100 locks) and its
 * reason is shown next to the form as is.
 */

import { useEffect, useId, useState, type FormEvent } from "react";
import { Loader2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, inputCls, inputStyle, labelCls } from "@/components/formStyles";
import {
  createTutorLock,
  deleteTutorLock,
  listTutorCanvasCourses,
  listTutorLocks,
} from "@/services/api";
import type { TutorCanvasCourse, TutorLock, TutorLockCreate } from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const OFF_NOTE = "Tutor mode is off, so these locks do nothing.";
const MAX_ALIASES = 5;

type Scope = TutorLockCreate["scope"];
type AppliesTo = TutorLockCreate["applies_to"];

/** What a row says it locks, from the owner's own words. */
function lockedWhat(lock: TutorLock): string {
  if (lock.scope === "account") return "Every chat";
  const parts = [lock.course_code, lock.course_name].filter(Boolean);
  if (lock.canvas_course_id) parts.push(`Canvas course ${lock.canvas_course_id}`);
  return parts.join(" · ") || lock.label;
}

function courseOption(course: TutorCanvasCourse): string {
  return [course.course_code, course.name].filter(Boolean).join(" — ") || `Course ${course.id}`;
}

export default function TutorLocks() {
  const headingId = useId();
  const formId = useId();
  const [locks, setLocks] = useState<TutorLock[] | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [courses, setCourses] = useState<TutorCanvasCourse[]>([]);
  const [removing, setRemoving] = useState<TutorLock | null>(null);

  const [scope, setScope] = useState<Scope>("course");
  const [appliesTo, setAppliesTo] = useState<AppliesTo>("all");
  const [email, setEmail] = useState("");
  const [picked, setPicked] = useState("");
  const [courseId, setCourseId] = useState("");
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [aliases, setAliases] = useState("");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    let cancelled = false;
    listTutorLocks()
      .then((data) => {
        if (cancelled) return;
        setLocks(data.locks);
        setEnabled(data.enabled);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "The tutor locks could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  useEffect(() => {
    let cancelled = false;
    // No Canvas (or it failed): the picker stays hidden and the course is typed.
    listTutorCanvasCourses()
      .then((data) => {
        if (!cancelled && data.available) setCourses(data.courses);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  const pickCourse = (id: string) => {
    setPicked(id);
    const course = courses.find((c) => c.id === id);
    if (!course) return;
    setCourseId(course.id);
    setCode(course.course_code);
    setName(course.name);
  };

  const resetForm = () => {
    setPicked("");
    setCourseId("");
    setCode("");
    setName("");
    setAliases("");
    setEmail("");
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setFormError("");
    const aliasList = aliases
      .split(",")
      .map((a) => a.trim())
      .filter(Boolean);
    if (aliasList.length > MAX_ALIASES) {
      setFormError(`A lock can have at most ${MAX_ALIASES} aliases.`);
      return;
    }
    const body: TutorLockCreate = { scope, applies_to: appliesTo };
    if (appliesTo === "email") body.email = email.trim();
    if (scope === "course") {
      if (courseId.trim()) body.canvas_course_id = courseId.trim();
      if (code.trim()) body.course_code = code.trim();
      if (name.trim()) body.course_name = name.trim();
      if (aliasList.length) body.aliases = aliasList;
    }
    setSaving(true);
    try {
      const created = await createTutorLock(body);
      setLocks((prev) => [...(prev ?? []), created]);
      resetForm();
    } catch (err) {
      setFormError(errorText(err, "The lock could not be saved. Try again."));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (target: TutorLock) => {
    // ConfirmDialog shows a failure inline and stays open.
    await deleteTutorLock(target.id);
    setLocks((prev) => prev && prev.filter((lock) => lock.id !== target.id));
    setRemoving(null);
  };

  return (
    <section
      aria-labelledby={headingId}
      className="mt-6 pt-5"
      style={{ borderTop: "1px solid var(--claw-border)" }}
    >
      <h3 id={headingId} className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
        Tutor locks
      </h3>
      <p className="text-xs mb-3" style={{ color: "var(--text-muted)" }}>
        A lock keeps tutor mode on (hints and questions instead of final answers) in every chat that
        names the course or opens it in Canvas, or in every chat of an account. Only you can remove a
        lock; nobody can lift one from a chat.
      </p>
      {!enabled && (
        <p role="status" className="text-sm mb-3" style={{ color: "var(--accent-warning, var(--text-secondary))" }}>
          {OFF_NOTE}
        </p>
      )}

      {loadError ? (
        <ErrorAlert>
          {loadError}{" "}
          <button
            type="button"
            className="underline font-medium"
            onClick={() => {
              setLoadError("");
              setLocks(null);
              setAttempt((n) => n + 1);
            }}
          >
            Try again
          </button>
        </ErrorAlert>
      ) : locks === null ? (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Loading tutor locks…
        </p>
      ) : locks.length === 0 ? (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          No tutor locks. Anyone can still turn tutor mode on in a chat with /tutor on.
        </p>
      ) : (
        <ul className="space-y-2">
          {locks.map((lock) => (
            <li key={lock.id} className="rounded-[10px] p-3" style={rowStyle}>
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <p className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
                    {lock.label}
                  </p>
                  <p className="text-xs mt-0.5 break-words" style={{ color: "var(--text-muted)" }}>
                    {lockedWhat(lock)} · applies to {lock.applies_to}
                    {lock.aliases.length > 0 && ` · also “${lock.aliases.join("”, “")}”`}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setRemoving(lock)}
                  aria-label={`Remove the ${lock.label} lock (${lock.applies_to})`}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[10px] text-xs font-semibold"
                  style={{
                    minHeight: 36,
                    background: "var(--claw-panel)",
                    border: "1px solid var(--border-danger)",
                    color: "var(--accent-danger)",
                  }}
                >
                  Remove
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <form id={formId} onSubmit={(e) => void submit(e)} className="mt-4 space-y-3" aria-label="Add a tutor lock">
        <div className="flex flex-wrap gap-3">
          <div className="min-w-[10rem] flex-1">
            <label className={labelCls} htmlFor={`${formId}-scope`}>
              Lock
            </label>
            <select
              id={`${formId}-scope`}
              className={inputCls}
              style={inputStyle}
              value={scope}
              onChange={(e) => setScope(e.target.value as Scope)}
            >
              <option value="course">A course</option>
              <option value="account">Every chat (whole account)</option>
            </select>
          </div>
          <div className="min-w-[10rem] flex-1">
            <label className={labelCls} htmlFor={`${formId}-applies`}>
              Applies to
            </label>
            <select
              id={`${formId}-applies`}
              className={inputCls}
              style={inputStyle}
              value={appliesTo}
              onChange={(e) => setAppliesTo(e.target.value as AppliesTo)}
            >
              <option value="all">Every account</option>
              <option value="me">Only me</option>
              <option value="email">One account (by email)</option>
            </select>
          </div>
        </div>
        {appliesTo === "email" && (
          <div>
            <label className={labelCls} htmlFor={`${formId}-email`}>
              Account email
            </label>
            <input
              id={`${formId}-email`}
              type="email"
              className={inputCls}
              style={inputStyle}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="off"
            />
          </div>
        )}
        {scope === "course" && (
          <>
            {courses.length > 0 && (
              <div>
                <label className={labelCls} htmlFor={`${formId}-pick`}>
                  Course from your Canvas
                </label>
                <select
                  id={`${formId}-pick`}
                  className={inputCls}
                  style={inputStyle}
                  value={picked}
                  onChange={(e) => pickCourse(e.target.value)}
                >
                  <option value="">Type the course below instead</option>
                  {courses.map((course) => (
                    <option key={course.id} value={course.id}>
                      {courseOption(course)}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <div className="flex flex-wrap gap-3">
              <div className="min-w-[8rem] flex-1">
                <label className={labelCls} htmlFor={`${formId}-code`}>
                  Course code
                </label>
                <input
                  id={`${formId}-code`}
                  className={inputCls}
                  style={inputStyle}
                  value={code}
                  maxLength={40}
                  placeholder="MATH 221"
                  onChange={(e) => setCode(e.target.value)}
                />
              </div>
              <div className="min-w-[10rem] flex-[2]">
                <label className={labelCls} htmlFor={`${formId}-name`}>
                  Course name
                </label>
                <input
                  id={`${formId}-name`}
                  className={inputCls}
                  style={inputStyle}
                  value={name}
                  maxLength={120}
                  placeholder="Calculus I"
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="min-w-[8rem] flex-1">
                <label className={labelCls} htmlFor={`${formId}-id`}>
                  Canvas course id
                </label>
                <input
                  id={`${formId}-id`}
                  className={inputCls}
                  style={inputStyle}
                  value={courseId}
                  inputMode="numeric"
                  maxLength={20}
                  placeholder="12345"
                  onChange={(e) => setCourseId(e.target.value)}
                />
              </div>
            </div>
            <div>
              <label className={labelCls} htmlFor={`${formId}-aliases`}>
                Other names (up to {MAX_ALIASES}, separated by commas)
              </label>
              <input
                id={`${formId}-aliases`}
                className={inputCls}
                style={inputStyle}
                value={aliases}
                placeholder="calc one, calculus 1"
                onChange={(e) => setAliases(e.target.value)}
              />
            </div>
          </>
        )}
        {formError && (
          <p role="alert" className="text-sm" style={{ color: "var(--accent-danger)" }}>
            {formError}
          </p>
        )}
        <button
          type="submit"
          disabled={saving}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
          style={{ minHeight: 40, background: "var(--accent-primary)", color: "var(--text-on-accent)" }}
        >
          {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
          Add lock
        </button>
      </form>

      <ConfirmDialog
        open={removing !== null}
        title="Remove this tutor lock?"
        message={
          removing
            ? `Chats locked for ${removing.label} go back to each person's own tutor mode switch.`
            : ""
        }
        confirmLabel="Remove"
        danger
        onConfirm={() => (removing ? remove(removing) : undefined)}
        onCancel={() => setRemoving(null)}
      />
    </section>
  );
}
