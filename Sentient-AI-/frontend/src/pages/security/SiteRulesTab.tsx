/**
 * SiteRulesTab: Security ▸ "Site rules" (owner only) — how Crawler's own browser and its web reads
 * treat particular sites. Blocked (never opened, never acted on), Always ask (every action there
 * needs a card that warns "sensitive site") or Trusted (no extra warning; cards still apply). It
 * checks which rule applies to a site, adds and changes the owner's own rules, sets the four
 * built-in sensitive-site categories (with a one-click Trust / Block for any listed site), and lists
 * what was stopped or flagged since Crawler last started.
 *
 * Why it exists: rules are owner policy that no chat, forwarded message or tool may change, so this
 * tab is the one place they are made. The server checks every rule (a real site, not a whole
 * top-level domain, never Blocked over a sign-in or payment host, never Trusted on a look-alike
 * address, at most 500) and its reason is shown next to the control that asked, as written. Only
 * the owner sees this tab (the Security page's registry marks it ownerOnly), so it takes no props
 * and never checks who is looking. Nothing here is secret and nothing leaves the backend's routes.
 */

import { useEffect, useId, useState, type FormEvent } from "react";
import { ChevronRight, Loader2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert } from "@/components/FormFeedback";
import { errorText, inputCls, inputStyle, labelCls } from "@/components/formStyles";
import {
  ApiError,
  checkSite,
  createSiteRule,
  deleteSiteRule,
  getSiteRules,
  setSiteCategory,
  updateSiteRule,
} from "@/services/api";
import type { SiteCategory, SiteCheck, SiteHit, SiteRule, SiteRuleKind, SiteRulesView } from "@/types";
import {
  SITE_RULE_KINDS,
  kindLabel,
  relativeTime,
  ruleTarget,
  timesText,
  whereLabel,
} from "@/pages/security/siteRulesFormat";

const rowStyle = { background: "var(--claw-surface)", border: "1px solid var(--claw-border)" };
const subsectionStyle = { borderTop: "1px solid var(--claw-border)" };
const headingStyle = { color: "var(--text-primary)" };
const mutedStyle = { color: "var(--text-muted)" };
const errorStyle = { color: "var(--accent-danger)" };
const smallSelectCls = "px-2.5 py-1.5 rounded-[10px] text-xs outline-none disabled:opacity-50";
const smallButtonCls =
  "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs font-semibold disabled:opacity-50";
const smallButtonStyle = {
  minHeight: 36,
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};
const dangerButtonStyle = {
  ...smallButtonStyle,
  border: "1px solid var(--border-danger)",
  color: "var(--accent-danger)",
};
const primaryButtonCls =
  "inline-flex items-center gap-1.5 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50";
const primaryButtonStyle = { minHeight: 40, background: "var(--accent-primary)", color: "var(--text-on-accent)" };

// The server's own sentence for an empty site; said here too so an empty box never calls the API.
const EMPTY_SITE = "Type a site, like example.com.";

const OFF_NOTE =
  "Site rules are off (Settings → Permissions → “Site rules for Crawler's browser”), so nothing on this tab applies right now.";

/** The 404 a PATCH, PUT or DELETE gets when another tab or session already removed the row. */
function isGone(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

function sitesText(count: number): string {
  return count === 1 ? "1 site" : `${count} sites`;
}

export default function SiteRulesTab() {
  const headingId = useId();
  const [view, setView] = useState<SiteRulesView | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  // A list-level reason for a 404 (the row was already gone); the list is read again meanwhile.
  const [listNotice, setListNotice] = useState("");
  const [removing, setRemoving] = useState<SiteRule | null>(null);

  useEffect(() => {
    let cancelled = false;
    // A re-read (after a 404 or a quick Trust / Block) keeps the current view on screen until the
    // answer arrives; only Retry clears it back to the spinner.
    getSiteRules()
      .then((data) => {
        if (cancelled) return;
        setView(data);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "The site rules could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const reread = () => setAttempt((n) => n + 1);

  const ruleAdded = (rule: SiteRule) => {
    setListNotice("");
    setView((prev) => prev && { ...prev, rules: [...prev.rules, rule] });
  };

  const ruleChanged = (rule: SiteRule) => {
    setListNotice("");
    setView((prev) => prev && { ...prev, rules: prev.rules.map((r) => (r.id === rule.id ? rule : r)) });
  };

  const categoryChanged = (category: SiteCategory) => {
    setListNotice("");
    setView(
      (prev) =>
        prev && { ...prev, categories: prev.categories.map((c) => (c.key === category.key ? category : c)) },
    );
  };

  const gone = (message: string) => {
    setListNotice(message);
    reread();
  };

  const remove = async (target: SiteRule) => {
    try {
      await deleteSiteRule(target.id);
    } catch (err) {
      // Already removed elsewhere: what the owner wanted holds, so close and read the list again.
      if (isGone(err)) {
        setRemoving(null);
        reread();
        return;
      }
      throw err; // ConfirmDialog shows the reason and stays open.
    }
    setListNotice("");
    setView((prev) => prev && { ...prev, rules: prev.rules.filter((r) => r.id !== target.id) });
    setRemoving(null);
  };

  return (
    <section aria-labelledby={headingId} className="space-y-6">
      <div>
        <h2 id={headingId} className="text-base font-semibold mb-1" style={headingStyle}>
          Site rules
        </h2>
        <p className="text-sm mb-2" style={{ color: "var(--text-secondary)" }}>
          Choose how Crawler's own browser treats particular sites.
        </p>
        <dl className="text-xs space-y-1" style={mutedStyle}>
          <div>
            <dt className="inline font-semibold">Blocked</dt>
            <dd className="inline"> — Crawler never opens the site or acts on it.</dd>
          </div>
          <div>
            <dt className="inline font-semibold">Always ask</dt>
            <dd className="inline">
              {" "}
              — Crawler may read the site, but every action there needs your approval, and the card warns
              you it is a sensitive site.
            </dd>
          </div>
          <div>
            <dt className="inline font-semibold">Trusted</dt>
            <dd className="inline"> — no extra warnings (actions still need your approval).</dd>
          </div>
        </dl>
      </div>

      {loadError ? (
        <ErrorAlert>
          {loadError}{" "}
          <button
            type="button"
            className="underline font-medium"
            onClick={() => {
              setLoadError("");
              setView(null);
              reread();
            }}
          >
            Retry
          </button>
        </ErrorAlert>
      ) : view === null ? (
        <p role="status" className="inline-flex items-center gap-2 text-sm" style={mutedStyle}>
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
          Loading site rules…
        </p>
      ) : (
        <>
          {!view.enabled && (
            <p
              role="status"
              className="px-3 py-2.5 rounded-[8px] text-sm"
              style={{
                color: "var(--accent-warning, var(--text-secondary))",
                border: "1px solid var(--claw-border)",
                background: "var(--claw-surface)",
              }}
            >
              {OFF_NOTE}
            </p>
          )}
          <CheckSiteSection />
          <AddRuleSection rules={view.rules} maxRules={view.max_rules} onAdded={ruleAdded} />
          <section aria-labelledby={`${headingId}-rules`} className="pt-5" style={subsectionStyle}>
            <div className="flex items-baseline justify-between gap-3 mb-2">
              <h3 id={`${headingId}-rules`} className="text-sm font-semibold" style={headingStyle}>
                Your rules
              </h3>
              <span className="text-xs" style={mutedStyle}>
                {view.rules.length} of {view.max_rules}
              </span>
            </div>
            {listNotice && (
              <p role="alert" className="text-xs mb-2" style={errorStyle}>
                {listNotice}
              </p>
            )}
            {view.rules.length === 0 ? (
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                No rules yet. The built-in sensitive sites below still apply.
              </p>
            ) : (
              <ul className="space-y-2" aria-label="Your site rules">
                {view.rules.map((rule) => (
                  <RuleRow
                    key={rule.id}
                    rule={rule}
                    onChanged={ruleChanged}
                    onGone={gone}
                    onRemove={() => setRemoving(rule)}
                  />
                ))}
              </ul>
            )}
          </section>
          <section aria-labelledby={`${headingId}-builtin`} className="pt-5" style={subsectionStyle}>
            <h3 id={`${headingId}-builtin`} className="text-sm font-semibold mb-1" style={headingStyle}>
              Built-in sensitive sites
            </h3>
            <p className="text-xs mb-3" style={mutedStyle}>
              Each list is Always ask unless you change it. Your own rule for a site wins over its list.
            </p>
            <ul className="space-y-2" aria-label="Built-in sensitive site lists">
              {view.categories.map((category) => (
                <CategoryRow
                  key={category.key}
                  category={category}
                  onChanged={categoryChanged}
                  onGone={gone}
                  onRuleAdded={reread}
                />
              ))}
            </ul>
          </section>
          <RecentSection recent={view.recent} />
        </>
      )}

      <ConfirmDialog
        open={removing !== null}
        title="Remove this site rule?"
        message={
          removing
            ? `Crawler stops treating ${ruleTarget(removing)} as ${kindLabel(removing.kind)}. A built-in sensitive-site list that covers it applies again.`
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

/** "Check a site": which rule applies to a typed site, in the server's own sentence. */
function CheckSiteSection() {
  const headingId = useId();
  const inputId = useId();
  const [site, setSite] = useState("");
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<SiteCheck | null>(null);
  const [error, setError] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setResult(null);
    const typed = site.trim();
    if (!typed) {
      setError(EMPTY_SITE);
      return;
    }
    setError("");
    setChecking(true);
    try {
      setResult(await checkSite(typed));
    } catch (err) {
      setError(errorText(err, "The site could not be checked."));
    } finally {
      setChecking(false);
    }
  };

  return (
    <section aria-labelledby={headingId} className="pt-5" style={subsectionStyle}>
      <h3 id={headingId} className="text-sm font-semibold mb-2" style={headingStyle}>
        Check a site
      </h3>
      <form onSubmit={(e) => void submit(e)} className="flex flex-wrap items-end gap-2" aria-label="Check a site">
        <div className="min-w-[12rem] flex-1">
          <label className={labelCls} htmlFor={inputId}>
            Site to check
          </label>
          <input
            id={inputId}
            className={inputCls}
            style={inputStyle}
            value={site}
            maxLength={2048}
            placeholder="secure.chase.com"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setSite(e.target.value)}
          />
        </div>
        <button type="submit" disabled={checking} className={primaryButtonCls} style={primaryButtonStyle}>
          {checking && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
          Check
        </button>
      </form>
      {error && (
        <p role="alert" className="text-sm mt-2" style={errorStyle}>
          {error}
        </p>
      )}
      {result && (
        <p role="status" className="text-sm mt-2 break-words" style={{ color: "var(--text-secondary)" }}>
          {result.explanation}
        </p>
      )}
    </section>
  );
}

/** "Add a rule": a site, whether it covers subdomains, and its kind; the server's refusal as is. */
function AddRuleSection({
  rules,
  maxRules,
  onAdded,
}: {
  rules: SiteRule[];
  maxRules: number;
  onAdded: (rule: SiteRule) => void;
}) {
  const headingId = useId();
  const formId = useId();
  const [site, setSite] = useState("");
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [kind, setKind] = useState<SiteRuleKind>("blocked");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const atLimit = rules.length >= maxRules;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (atLimit || saving) return;
    const typed = site.trim();
    if (!typed) {
      setError(EMPTY_SITE);
      return;
    }
    setError("");
    setSaving(true);
    try {
      onAdded(await createSiteRule({ site: typed, include_subdomains: includeSubdomains, kind }));
      setSite("");
    } catch (err) {
      // 422 (not a site Crawler can have a rule for) and 409 (already a rule) carry the reason;
      // what was typed stays so the owner can fix it.
      setError(errorText(err, "The rule could not be saved."));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section aria-labelledby={headingId} className="pt-5" style={subsectionStyle}>
      <h3 id={headingId} className="text-sm font-semibold mb-2" style={headingStyle}>
        Add a rule
      </h3>
      {atLimit && (
        <p className="text-sm mb-2" style={{ color: "var(--text-secondary)" }}>
          You have {maxRules} site rules, the most Crawler keeps. Remove some first.
        </p>
      )}
      <form onSubmit={(e) => void submit(e)} aria-label="Add a site rule">
        <fieldset disabled={saving || atLimit} className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[12rem] flex-[2]">
              <label className={labelCls} htmlFor={`${formId}-site`}>
                Site
              </label>
              <input
                id={`${formId}-site`}
                className={inputCls}
                style={inputStyle}
                value={site}
                maxLength={2048}
                placeholder="example-casino.com"
                autoComplete="off"
                spellCheck={false}
                onChange={(e) => setSite(e.target.value)}
              />
            </div>
            <div className="min-w-[9rem] flex-1">
              <label className={labelCls} htmlFor={`${formId}-kind`}>
                Rule
              </label>
              <select
                id={`${formId}-kind`}
                className={inputCls}
                style={inputStyle}
                value={kind}
                onChange={(e) => setKind(e.target.value as SiteRuleKind)}
              >
                {SITE_RULE_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {kindLabel(k)}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <label htmlFor={`${formId}-subdomains`} className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              id={`${formId}-subdomains`}
              type="checkbox"
              checked={includeSubdomains}
              onChange={(e) => setIncludeSubdomains(e.target.checked)}
              className="w-4 h-4 shrink-0"
              style={{ accentColor: "var(--accent-primary)" }}
            />
            <span style={{ color: "var(--text-secondary)" }}>Include subdomains (www., login., …)</span>
          </label>
          {error && (
            <p role="alert" className="text-sm" style={errorStyle}>
              {error}
            </p>
          )}
          <button
            type="submit"
            disabled={saving || atLimit}
            className={primaryButtonCls}
            style={primaryButtonStyle}
          >
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden />}
            Add rule
          </button>
        </fieldset>
      </form>
    </section>
  );
}

/** One owner rule: what it covers, its kind (changed in place) and Remove. */
function RuleRow({
  rule,
  onChanged,
  onGone,
  onRemove,
}: {
  rule: SiteRule;
  onChanged: (rule: SiteRule) => void;
  onGone: (message: string) => void;
  onRemove: () => void;
}) {
  const target = ruleTarget(rule);
  // The kind being saved; null shows the rule's own kind (so a failed change puts the old one back).
  const [pending, setPending] = useState<SiteRuleKind | null>(null);
  const [error, setError] = useState("");
  const saving = pending !== null;

  const change = async (kind: SiteRuleKind) => {
    if (kind === rule.kind) return;
    setPending(kind);
    setError("");
    try {
      onChanged(await updateSiteRule(rule.id, kind));
    } catch (err) {
      const text = errorText(err, "The rule could not be changed.");
      if (isGone(err)) onGone(text);
      else setError(text);
    } finally {
      setPending(null);
    }
  };

  return (
    <li className="rounded-[10px] p-3" style={rowStyle}>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-semibold break-words" style={headingStyle}>
            {target}
          </p>
          {rule.overrides_builtin && (
            <p className="text-xs mt-0.5" style={mutedStyle}>
              Replaces the built-in sensitive-site list here
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden style={mutedStyle} />}
          <select
            aria-label={`Rule for ${target}`}
            className={smallSelectCls}
            style={inputStyle}
            value={pending ?? rule.kind}
            disabled={saving}
            onChange={(e) => void change(e.target.value as SiteRuleKind)}
          >
            {SITE_RULE_KINDS.map((k) => (
              <option key={k} value={k}>
                {kindLabel(k)}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={onRemove}
            disabled={saving}
            aria-label={`Remove the rule for ${target}`}
            className={smallButtonCls}
            style={dangerButtonStyle}
          >
            Remove
          </button>
        </div>
      </div>
      {error && (
        <p role="alert" className="text-xs mt-2" style={errorStyle}>
          {error}
        </p>
      )}
    </li>
  );
}

/** One built-in category: its kind, Reset when changed, and its sites with quick Trust / Block. */
function CategoryRow({
  category,
  onChanged,
  onGone,
  onRuleAdded,
}: {
  category: SiteCategory;
  onChanged: (category: SiteCategory) => void;
  onGone: (message: string) => void;
  onRuleAdded: () => void;
}) {
  const sitesId = useId();
  const [pending, setPending] = useState<SiteRuleKind | null>(null);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [adding, setAdding] = useState<string | null>(null);
  const [siteError, setSiteError] = useState("");
  const saving = pending !== null;
  const overridden = category.kind !== category.default_kind;

  const change = async (kind: SiteRuleKind) => {
    if (kind === category.kind) return;
    setPending(kind);
    setError("");
    try {
      onChanged(await setSiteCategory(category.key, kind));
    } catch (err) {
      const text = errorText(err, "The list could not be changed.");
      if (isGone(err)) onGone(text);
      else setError(text);
    } finally {
      setPending(null);
    }
  };

  const quickRule = async (site: string, kind: SiteRuleKind) => {
    setAdding(site);
    setSiteError("");
    try {
      await createSiteRule({ site, include_subdomains: true, kind });
      onRuleAdded();
    } catch (err) {
      setSiteError(errorText(err, "The rule could not be saved."));
    } finally {
      setAdding(null);
    }
  };

  return (
    <li className="rounded-[10px] p-3" style={rowStyle}>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-semibold break-words" style={headingStyle}>
            {category.label}
          </p>
          <p className="text-xs mt-0.5" style={mutedStyle}>
            {sitesText(category.site_count)}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden style={mutedStyle} />}
          <select
            aria-label={`Rule for ${category.label}`}
            className={smallSelectCls}
            style={inputStyle}
            value={pending ?? category.kind}
            disabled={saving}
            onChange={(e) => void change(e.target.value as SiteRuleKind)}
          >
            {SITE_RULE_KINDS.map((k) => (
              <option key={k} value={k}>
                {k === category.default_kind ? `${kindLabel(k)} (default)` : kindLabel(k)}
              </option>
            ))}
          </select>
          {overridden && (
            <button
              type="button"
              disabled={saving}
              onClick={() => void change(category.default_kind)}
              className={smallButtonCls}
              style={smallButtonStyle}
            >
              Reset to {kindLabel(category.default_kind)}
            </button>
          )}
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls={open ? sitesId : undefined}
            aria-label={`${open ? "Hide" : "Show"} sites in ${category.label}`}
            className={smallButtonCls}
            style={{ ...smallButtonStyle, color: "var(--accent-primary)" }}
          >
            <ChevronRight
              className={`w-3.5 h-3.5 transition-transform duration-200 ${open ? "rotate-90" : ""}`}
              aria-hidden
            />
            {open ? "Hide sites" : "Show sites"}
          </button>
        </div>
      </div>
      {error && (
        <p role="alert" className="text-xs mt-2" style={errorStyle}>
          {error}
        </p>
      )}
      {open && (
        <div id={sitesId} className="mt-3">
          <p className="text-xs mb-2" style={mutedStyle}>
            Trust or Block adds your own rule for that site and its subdomains.
          </p>
          {siteError && (
            <p role="alert" className="text-xs mb-2" style={errorStyle}>
              {siteError}
            </p>
          )}
          <ul className="space-y-1" aria-label={`${category.label} sites`}>
            {category.sites.map((site) => (
              <li key={site} className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-sm break-all" style={{ color: "var(--text-secondary)" }}>
                  {site}
                </span>
                <span className="flex items-center gap-2">
                  {adding === site && (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden style={mutedStyle} />
                  )}
                  <button
                    type="button"
                    disabled={adding !== null}
                    onClick={() => void quickRule(site, "trusted")}
                    aria-label={`Trust ${site}`}
                    className={smallButtonCls}
                    style={smallButtonStyle}
                  >
                    Trust
                  </button>
                  <button
                    type="button"
                    disabled={adding !== null}
                    onClick={() => void quickRule(site, "blocked")}
                    aria-label={`Block ${site}`}
                    className={smallButtonCls}
                    style={dangerButtonStyle}
                  >
                    Block
                  </button>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

/** "Recently stopped or flagged": the in-memory hits since Crawler last started, newest first. */
function RecentSection({ recent }: { recent: SiteHit[] }) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className="pt-5" style={subsectionStyle}>
      <h3 id={headingId} className="text-sm font-semibold mb-1" style={headingStyle}>
        Recently stopped or flagged
      </h3>
      <p className="text-xs mb-2" style={mutedStyle}>
        Since Crawler last started. The audit log keeps the full record.
      </p>
      {recent.length === 0 ? (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          Nothing since Crawler last started.
        </p>
      ) : (
        <ul className="space-y-1" aria-label="Recent site rule hits">
          {recent.map((hit, index) => (
            <li
              key={`${index}|${hit.host}|${hit.kind}|${hit.where}`}
              className="flex items-baseline justify-between gap-3 flex-wrap text-sm"
            >
              <span className="font-semibold break-all" style={headingStyle}>
                {hit.host}
              </span>
              <span className="text-xs" style={mutedStyle}>
                {kindLabel(hit.kind)} · {whereLabel(hit.where)} · {timesText(hit.count)} ·{" "}
                {relativeTime(hit.last_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
