/**
 * ToolRulesTab: Security ▸ "Tool rules" (owner only) — the four built-in safety rules with a switch
 * each, the owner's own rules with Remove, and a form to add one (a tool pattern plus up to five
 * argument conditions) with a live preview of the tools the pattern covers.
 *
 * Why it exists: decisions.md item 3 lets the owner put rules on tool arguments, and a call that
 * breaks one waits for an approval card that names the rule. Rules only ever add a question, so
 * adding a rule or turning a built-in rule on happens at once, while turning a built-in rule off or
 * removing a rule (each makes Crawler less careful) asks first. The server checks every rule and its
 * reason is shown beside the form unchanged; the preview only informs and never blocks Save.
 *
 * Connects to: `listToolRules`, `getToolRuleCatalog`, `previewToolRule`, `createToolRule`,
 * `deleteToolRule` and `setBuiltinToolRule` in services/api.ts (the owner-only
 * /api/security/tool-rules routes). Nothing here reaches any other service.
 */

import { useEffect, useId, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Loader2, Plus, X } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, inputCls, inputStyle, labelCls } from "@/components/formStyles";
import {
  ApiError,
  createToolRule,
  deleteToolRule,
  getToolRuleCatalog,
  listToolRules,
  previewToolRule,
  setBuiltinToolRule,
} from "@/services/api";
import type {
  BuiltinToolRule,
  ToolRule,
  ToolRuleCatalog,
  ToolRuleCondition,
  ToolRuleDraft,
  ToolRuleOp,
  ToolRuleOperator,
  ToolRulePreview,
  ToolRulesView,
} from "@/types";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const mutedStyle = { color: "var(--text-muted)" };
const warnStyle = { color: "var(--accent-warning, var(--text-secondary))" };

const OFF_BANNER = "Tool rules are off in Settings → Permissions, so nothing here is applied.";
const STORE_BANNER =
  "Your rules could not be read just now. Until they can, Crawler asks before every change.";
const LOAD_FAILED = "The tool rules could not be loaded.";
const OUTSIDE_SHARE = "outside_share";
/** The preview waits this long after the last change before asking the server (S9 §6.1). */
const PREVIEW_DELAY_MS = 400;
/** How many matched tool names the preview spells out before "…". */
const PREVIEW_NAMES = 5;
/** Argument suggestions offered at most (a wide pattern can match many tools). */
const MAX_ARG_SUGGESTIONS = 100;

type ValueKind = ToolRuleOperator["value"];

/** One condition row as typed; the value stays text until it is sent. */
interface ConditionRow {
  id: number;
  arg: string;
  op: ToolRuleOp;
  value: string;
}

function valueKind(operators: ToolRuleOperator[], op: ToolRuleOp): ValueKind {
  return operators.find((o) => o.op === op)?.value ?? "text";
}

/** A row's value in the shape the server expects: a list of strings for the list operators (trimmed,
 *  empties dropped), a number for the number operators. A number box that holds no number is sent as
 *  typed, so the server's reason ("… needs a number.") is what the owner reads. */
function conditionValue(kind: ValueKind, text: string): ToolRuleCondition["value"] {
  if (kind === "list") {
    return text
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  if (kind === "number") {
    const trimmed = text.trim();
    const number = Number(trimmed);
    return trimmed !== "" && Number.isFinite(number) ? number : trimmed;
  }
  return text;
}

function buildDraft(tool: string, rows: ConditionRow[], operators: ToolRuleOperator[]): ToolRuleDraft {
  return {
    tool: tool.trim(),
    conditions: rows.map((row) => ({
      arg: row.arg.trim(),
      op: row.op,
      value: conditionValue(valueKind(operators, row.op), row.value),
    })),
  };
}

/** The tool glob as a RegExp: only `*` and `?` are special, as on the server (fnmatch). */
function globPattern(pattern: string): RegExp | null {
  const source = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  try {
    return new RegExp(`^${source}$`);
  } catch {
    return null;
  }
}

/** Argument names of the catalog tools the pattern covers, plus `*` (any argument). */
function suggestedArgs(catalog: ToolRuleCatalog["tools"], tool: string): string[] {
  const pattern = tool.trim().toLowerCase();
  const matcher = pattern ? globPattern(pattern) : null;
  if (!matcher) return [];
  const args = new Set<string>();
  for (const entry of catalog) {
    if (matcher.test(entry.tool.toLowerCase())) entry.args.forEach((arg) => args.add(arg));
  }
  return [...[...args].sort().slice(0, MAX_ARG_SUGGESTIONS), "*"];
}

/** "Crawler will no longer ask before …", from the rule's own "Ask before …" description. */
function turnOffMessage(rule: BuiltinToolRule): string {
  const description = rule.description.trim().replace(/[.\s]+$/, "");
  const what = /^ask\b/i.test(description)
    ? description.charAt(0).toLowerCase() + description.slice(1)
    : `check "${rule.name}"`;
  return `Crawler will no longer ${what}. This makes Crawler less careful.`;
}

function plural(count: number, one: string, many: string): string {
  return count === 1 ? one : many;
}

function PreviewLines({ preview }: { preview: ToolRulePreview }) {
  if (!preview.valid) {
    return (
      <p className="text-sm" style={warnStyle}>
        {preview.error || "This rule is not complete yet."}
      </p>
    );
  }
  const total = Math.max(preview.matches.length, preview.reads + preview.writes);
  const names = preview.matches.slice(0, PREVIEW_NAMES).map((m) => m.tool);
  const more = total > names.length || preview.truncated;
  return (
    <>
      {preview.summary && (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          {preview.summary}
        </p>
      )}
      <p className="text-xs break-words" style={mutedStyle}>
        {total === 0
          ? "Matches no tools in the catalog."
          : `Matches ${total} ${plural(total, "tool", "tools")}: ${names.join(", ")}${more ? "…" : ""}`}
      </p>
      {preview.reads > 0 && (
        <p className="text-xs font-medium" style={warnStyle}>
          {preview.reads === 1
            ? "1 of them is a read: Crawler will stop and ask in chat before that read."
            : `${preview.reads} of them are reads: Crawler will stop and ask in chat before those reads.`}
        </p>
      )}
      {preview.mcp && (
        <p className="text-xs" style={mutedStyle}>
          Also matches tools from MCP servers with that name.
        </p>
      )}
    </>
  );
}

export default function ToolRulesTab() {
  const headingId = useId();
  const builtinHeadingId = useId();
  const rulesHeadingId = useId();
  const formHeadingId = useId();
  const formId = useId();

  const [view, setView] = useState<ToolRulesView | null>(null);
  const [loadError, setLoadError] = useState("");
  const [forbidden, setForbidden] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [catalog, setCatalog] = useState<ToolRuleCatalog | null>(null);

  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [builtinErrors, setBuiltinErrors] = useState<Record<string, string>>({});
  const [turningOff, setTurningOff] = useState<BuiltinToolRule | null>(null);
  const [removing, setRemoving] = useState<ToolRule | null>(null);

  const [name, setName] = useState("");
  const [tool, setTool] = useState("");
  const [rows, setRows] = useState<ConditionRow[]>([]);
  const nextRowId = useRef(1);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");

  const [previewing, setPreviewing] = useState(false);
  const [preview, setPreview] = useState<ToolRulePreview | null>(null);
  const [previewError, setPreviewError] = useState("");
  // The pending debounce and a counter that makes a late answer to an older draft drop itself.
  const previewRun = useRef<{ timer: ReturnType<typeof setTimeout> | undefined; seq: number }>({
    timer: undefined,
    seq: 0,
  });

  useEffect(() => {
    let cancelled = false;
    listToolRules()
      .then((data) => {
        if (cancelled) return;
        setView(data);
        setLoadError("");
        setForbidden(false);
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 403) {
          setForbidden(true);
          return;
        }
        // The fixed sentence always; the server's own words after it when it sent any.
        setLoadError(err instanceof ApiError && err.message ? `${LOAD_FAILED} ${err.message}` : LOAD_FAILED);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const loaded = view !== null;
  useEffect(() => {
    if (!loaded) return;
    let cancelled = false;
    // Suggestions only: without the catalog the owner types the tool and argument names.
    getToolRuleCatalog()
      .then((data) => {
        if (!cancelled) setCatalog(data);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [loaded]);

  useEffect(() => {
    const run = previewRun.current;
    return () => {
      clearTimeout(run.timer);
      run.seq += 1;
    };
  }, []);

  const catalogTools = useMemo(() => catalog?.tools ?? [], [catalog]);
  const argOptions = useMemo(() => suggestedArgs(catalogTools, tool), [catalogTools, tool]);

  /** Ask the server what this draft covers, 400 ms after the last change to the tool or conditions. */
  const schedulePreview = (nextTool: string, nextRows: ConditionRow[]) => {
    const run = previewRun.current;
    clearTimeout(run.timer);
    run.seq += 1;
    const seq = run.seq;
    if (!view || !nextTool.trim()) {
      setPreview(null);
      setPreviewError("");
      setPreviewing(false);
      return;
    }
    const draft = buildDraft(nextTool, nextRows, view.operators);
    run.timer = setTimeout(() => {
      setPreviewing(true);
      previewToolRule(draft)
        .then((result) => {
          if (run.seq !== seq) return;
          setPreview(result);
          setPreviewError("");
        })
        .catch((err) => {
          if (run.seq !== seq) return;
          setPreview(null);
          setPreviewError(errorText(err, "The preview could not be loaded."));
        })
        .finally(() => {
          if (run.seq === seq) setPreviewing(false);
        });
    }, PREVIEW_DELAY_MS);
  };

  const changeTool = (value: string) => {
    setTool(value);
    schedulePreview(value, rows);
  };

  const changeRows = (next: ConditionRow[]) => {
    setRows(next);
    schedulePreview(tool, next);
  };

  const addCondition = () => {
    if (!view || view.operators.length === 0) return;
    const id = nextRowId.current;
    nextRowId.current += 1;
    changeRows([...rows, { id, arg: "", op: view.operators[0].op, value: "" }]);
  };

  const updateRow = (id: number, patch: Partial<Omit<ConditionRow, "id">>) => {
    if (!view) return;
    changeRows(
      rows.map((row) => {
        if (row.id !== id) return row;
        const next = { ...row, ...patch };
        // A list typed for "is one of" means nothing in a number box: start the value afresh.
        if (patch.op && valueKind(view.operators, patch.op) !== valueKind(view.operators, row.op)) {
          next.value = "";
        }
        return next;
      }),
    );
  };

  const removeRow = (id: number) => changeRows(rows.filter((row) => row.id !== id));

  const resetForm = () => {
    setName("");
    setTool("");
    setRows([]);
    schedulePreview("", []);
  };

  const replaceBuiltin = (key: string, saved: BuiltinToolRule) => {
    setView((prev) =>
      prev && {
        ...prev,
        builtins: prev.builtins.map((rule) => (rule.key === key ? { ...rule, ...saved, key } : rule)),
      },
    );
  };

  const clearBuiltinError = (key: string) => {
    setBuiltinErrors((prev) => {
      if (!(key in prev)) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });
  };

  /** Turning a rule on only narrows, so it is saved at once; off asks first (the dialog). */
  const toggleBuiltin = async (rule: BuiltinToolRule) => {
    clearBuiltinError(rule.key);
    if (rule.enabled) {
      setTurningOff(rule);
      return;
    }
    setPendingKey(rule.key);
    try {
      replaceBuiltin(rule.key, await setBuiltinToolRule(rule.key, true));
    } catch (err) {
      setBuiltinErrors((prev) => ({
        ...prev,
        [rule.key]: errorText(err, "The rule could not be turned on. Try again."),
      }));
    } finally {
      setPendingKey(null);
    }
  };

  const turnOff = async (rule: BuiltinToolRule) => {
    // ConfirmDialog shows a failure inline and stays open, so the rule stays on.
    replaceBuiltin(rule.key, await setBuiltinToolRule(rule.key, false));
    setTurningOff(null);
  };

  const remove = async (rule: ToolRule) => {
    // ConfirmDialog shows a failure inline and stays open.
    await deleteToolRule(rule.id);
    setView((prev) => prev && { ...prev, rules: prev.rules.filter((r) => r.id !== rule.id) });
    setRemoving(null);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!view) return;
    setFormError("");
    setSaving(true);
    try {
      const created = await createToolRule({ name: name.trim(), ...buildDraft(tool, rows, view.operators) });
      setView((prev) => prev && { ...prev, rules: [...prev.rules, created] });
      resetForm();
    } catch (err) {
      setFormError(errorText(err, "The rule could not be saved. Try again."));
    } finally {
      setSaving(false);
    }
  };

  const retry = () => {
    setLoadError("");
    setView(null);
    setAttempt((n) => n + 1);
  };

  let body: ReactNode;
  if (forbidden) {
    body = (
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        Only the owner can see tool rules.
      </p>
    );
  } else if (loadError) {
    body = (
      <ErrorAlert>
        {loadError}{" "}
        <button type="button" className="underline font-medium" onClick={retry}>
          Try again
        </button>
      </ErrorAlert>
    );
  } else if (view === null) {
    body = (
      <p role="status" className="inline-flex items-center gap-2 text-sm" style={mutedStyle}>
        <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
        Loading tool rules…
      </p>
    );
  } else {
    const maxConditions = view.limits.max_conditions;
    const canAddCondition = rows.length < maxConditions && view.operators.length > 0;
    body = (
      <>
        {!view.enabled ? (
          <p role="status" className="text-sm mb-3 font-medium" style={warnStyle}>
            {OFF_BANNER}
          </p>
        ) : (
          <p className="text-xs mb-3" style={mutedStyle}>
            The switch is on in Settings → Permissions.
          </p>
        )}
        {!view.store_ok && (
          <p role="status" className="text-sm mb-3 font-medium" style={warnStyle}>
            {STORE_BANNER}
          </p>
        )}

        <section aria-labelledby={builtinHeadingId} className="mt-4">
          <div className="flex items-baseline justify-between gap-3 mb-2">
            <h3 id={builtinHeadingId} className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
              Built-in rules
            </h3>
            <span className="text-xs" style={mutedStyle}>
              on by default
            </span>
          </div>
          <ul className="space-y-2">
            {view.builtins.map((rule) => {
              const nameId = `${formId}-builtin-${rule.key}`;
              const busy = pendingKey === rule.key;
              return (
                <li key={rule.key} className="rounded-[10px] p-3" style={rowStyle}>
                  <div className="flex items-start gap-3">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={rule.enabled}
                      aria-labelledby={nameId}
                      disabled={busy}
                      onClick={() => void toggleBuiltin(rule)}
                      className="inline-flex items-center justify-center shrink-0 w-14 rounded-[10px] text-sm font-medium transition-colors disabled:opacity-50"
                      style={{
                        minHeight: 36,
                        background: rule.enabled ? "var(--fill-success)" : "var(--claw-panel)",
                        border: rule.enabled ? "1px solid var(--border-success)" : "1px solid var(--claw-border)",
                        color: rule.enabled ? "var(--accent-success)" : "var(--text-muted)",
                      }}
                    >
                      {busy ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : rule.enabled ? "On" : "Off"}
                    </button>
                    <div className="min-w-0">
                      <p id={nameId} className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
                        {rule.name}
                      </p>
                      <p className="text-xs mt-0.5 break-words" style={{ color: "var(--text-secondary)" }}>
                        {rule.description}
                        {rule.key === OUTSIDE_SHARE &&
                          (view.org_domains.length > 0
                            ? ` Your organisation: ${view.org_domains.join(", ")}`
                            : " No organisation domains are known yet, so this rule stays quiet.")}
                      </p>
                      {builtinErrors[rule.key] && (
                        <p role="alert" className="text-xs mt-1" style={{ color: "var(--accent-danger)" }}>
                          {builtinErrors[rule.key]}
                        </p>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </section>

        <section aria-labelledby={rulesHeadingId} className="mt-6">
          <h3 id={rulesHeadingId} className="text-sm font-semibold mb-2" style={{ color: "var(--text-primary)" }}>
            Your rules ({view.rules.length} of {view.limits.max_rules})
          </h3>
          {view.rules.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              No rules of your own yet. Built-in rules still apply.
            </p>
          ) : (
            <ul className="space-y-2">
              {view.rules.map((rule) => (
                <li key={rule.id} className="rounded-[10px] p-3" style={rowStyle}>
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold break-words" style={{ color: "var(--text-primary)" }}>
                        {rule.name}
                      </p>
                      <p className="text-xs mt-0.5 break-words" style={mutedStyle}>
                        {rule.summary}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setRemoving(rule)}
                      aria-label={`Remove the rule ${rule.name}`}
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
        </section>

        <section aria-labelledby={formHeadingId} className="mt-6">
          <h3 id={formHeadingId} className="text-sm font-semibold mb-2" style={{ color: "var(--text-primary)" }}>
            Add a rule
          </h3>
          <form id={formId} onSubmit={(e) => void submit(e)} className="space-y-3" aria-label="Add a tool rule">
            <div className="flex flex-wrap gap-3">
              <div className="min-w-[10rem] flex-1">
                <label className={labelCls} htmlFor={`${formId}-name`}>
                  Name
                </label>
                <input
                  id={`${formId}-name`}
                  className={inputCls}
                  style={inputStyle}
                  value={name}
                  maxLength={60}
                  placeholder="Big mailings to the press"
                  autoComplete="off"
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="min-w-[12rem] flex-[2]">
                <label className={labelCls} htmlFor={`${formId}-tool`}>
                  Tool
                </label>
                <input
                  id={`${formId}-tool`}
                  className={inputCls}
                  style={inputStyle}
                  value={tool}
                  list={`${formId}-tools`}
                  placeholder="google_workspace.send_email"
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby={`${formId}-tool-hint`}
                  onChange={(e) => changeTool(e.target.value)}
                />
                <datalist id={`${formId}-tools`}>
                  {catalogTools.map((entry) => (
                    <option key={entry.tool} value={entry.tool} />
                  ))}
                </datalist>
                <p id={`${formId}-tool-hint`} className="text-xs mt-1" style={mutedStyle}>
                  Suggestions come from the catalog; * matches anything.
                  {catalog?.mcp_hint ? ` MCP tools are named ${catalog.mcp_hint}.` : ""}
                </p>
              </div>
            </div>

            <fieldset className="space-y-2">
              <legend className={labelCls}>When</legend>
              <datalist id={`${formId}-args`}>
                {argOptions.map((arg) => (
                  <option key={arg} value={arg} />
                ))}
              </datalist>
              {rows.map((row, index) => {
                const n = index + 1;
                const kind = valueKind(view.operators, row.op);
                return (
                  <div key={row.id} className="flex flex-wrap items-center gap-2">
                    <input
                      aria-label={`Condition ${n}: argument`}
                      className={`${inputCls} flex-1 min-w-[7rem]`}
                      style={inputStyle}
                      value={row.arg}
                      list={`${formId}-args`}
                      placeholder="to"
                      autoComplete="off"
                      spellCheck={false}
                      onChange={(e) => updateRow(row.id, { arg: e.target.value })}
                    />
                    <select
                      aria-label={`Condition ${n}: check`}
                      className={`${inputCls} flex-1 min-w-[9rem]`}
                      style={inputStyle}
                      value={row.op}
                      onChange={(e) => updateRow(row.id, { op: e.target.value as ToolRuleOp })}
                    >
                      {view.operators.map((operator) => (
                        <option key={operator.op} value={operator.op}>
                          {operator.label}
                        </option>
                      ))}
                    </select>
                    <input
                      aria-label={`Condition ${n}: value`}
                      type={kind === "number" ? "number" : "text"}
                      className={`${inputCls} flex-[2] min-w-[9rem]`}
                      style={inputStyle}
                      value={row.value}
                      placeholder={
                        kind === "list"
                          ? "Separate values with commas"
                          : kind === "number"
                            ? "500"
                            : kind === "pattern"
                              ? "A pattern, such as ^INV-[0-9]{1,10}$"
                              : ""
                      }
                      autoComplete="off"
                      spellCheck={false}
                      onChange={(e) => updateRow(row.id, { value: e.target.value })}
                    />
                    <button
                      type="button"
                      aria-label={`Remove condition ${n}`}
                      onClick={() => removeRow(row.id)}
                      className="inline-flex items-center justify-center rounded-[10px] shrink-0"
                      style={{
                        minHeight: 36,
                        minWidth: 36,
                        background: "var(--claw-panel)",
                        border: "1px solid var(--claw-border)",
                        color: "var(--text-secondary)",
                      }}
                    >
                      <X className="w-4 h-4" aria-hidden />
                    </button>
                  </div>
                );
              })}
              {canAddCondition && (
                <button
                  type="button"
                  onClick={addCondition}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs font-semibold"
                  style={{
                    minHeight: 36,
                    background: "transparent",
                    border: "1px solid var(--claw-border)",
                    color: "var(--text-primary)",
                  }}
                >
                  <Plus className="w-3.5 h-3.5" aria-hidden />
                  Add a condition
                </button>
              )}
              <p className="text-xs" style={mutedStyle}>
                Up to {maxConditions} conditions, and all of them must hold. Leave none to ask before every
                call of this tool.
              </p>
            </fieldset>

            <div aria-live="polite" className="space-y-1">
              {previewing ? (
                <p className="inline-flex items-center gap-2 text-xs" style={mutedStyle}>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />
                  Checking which tools this covers…
                </p>
              ) : previewError ? (
                <p className="text-xs" style={warnStyle}>
                  {previewError}
                </p>
              ) : preview ? (
                <PreviewLines preview={preview} />
              ) : null}
            </div>

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
              Save rule
            </button>
          </form>
        </section>
      </>
    );
  }

  return (
    <section aria-labelledby={headingId}>
      <h2 id={headingId} className="mb-1">
        Tool rules
      </h2>
      <p className="text-sm mb-2" style={{ color: "var(--text-secondary)" }}>
        Crawler asks before any call that breaks one of these rules. Rules only ever add a question;
        nothing here can make Crawler skip one.
      </p>
      {body}

      <ConfirmDialog
        open={turningOff !== null}
        title={turningOff ? `Turn off '${turningOff.name}'?` : ""}
        message={turningOff ? turnOffMessage(turningOff) : ""}
        confirmLabel="Turn off"
        danger
        onConfirm={() => (turningOff ? turnOff(turningOff) : undefined)}
        onCancel={() => setTurningOff(null)}
      />
      <ConfirmDialog
        open={removing !== null}
        title={removing ? `Remove the rule '${removing.name}'?` : ""}
        message="Crawler will stop asking before the calls it matched."
        confirmLabel="Remove"
        danger
        onConfirm={() => (removing ? remove(removing) : undefined)}
        onCancel={() => setRemoving(null)}
      />
    </section>
  );
}
