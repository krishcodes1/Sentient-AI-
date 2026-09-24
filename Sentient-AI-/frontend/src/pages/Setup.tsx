import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, Navigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, CheckCircle2, Loader2, XCircle } from "lucide-react";
import CapabilityList from "@/components/CapabilityList";
import { Wordmark } from "@/components/Brand";
import ThemeToggle from "@/components/ThemeToggle";
import {
  completeSetup,
  createOwner,
  createTelegramLink,
  getCapabilities,
  getSetupProviders,
  getSetupStatus,
  installCapability,
  requestCapabilityAccess,
  saveProvider,
  saveTelegram,
  testProvider,
  testTelegram,
  updateCapabilities,
  type TelegramLink,
} from "@/services/api";
import type {
  CapabilityStatus,
  ProviderChoice,
  SetupProvider,
  SetupProviders,
  SetupStatus,
} from "@/types";

// First-run wizard. The app routes every page here while the server reports
// `needs_setup`, so this page must work with no session at all (the owner
// step) and resume mid-way after a reload (a session exists, so the owner
// step is already done).

const STEPS = [
  { id: "owner", label: "Owner account" },
  { id: "provider", label: "AI provider" },
  { id: "telegram", label: "Telegram" },
  { id: "permissions", label: "Permissions" },
  { id: "summary", label: "Summary" },
] as const;
type StepId = (typeof STEPS)[number]["id"];

// Same order as Settings > LLM provider, so the two screens read alike.
// Providers the server offers but this list does not know go last.
const PROVIDER_ORDER = ["anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"];

const panelStyle = {
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  boxShadow: "var(--shadow-card)",
};
const inputCls = "w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none";
const inputStyle = {
  background: "var(--bg-input)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};
const labelCls = "block text-sm font-medium mb-1.5 text-[var(--text-secondary)]";
const primaryCls =
  "inline-flex items-center justify-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50";
const primaryStyle = { minHeight: 44, background: "var(--accent-primary)", color: "var(--text-on-accent)" };
const secondaryCls =
  "inline-flex items-center justify-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50";
const secondaryStyle = {
  minHeight: 44,
  background: "transparent",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

/** Where to begin, given what the server says and whether we hold a session. */
function startFrom(status: SetupStatus, hasSession: boolean): StepId | "done" | "signin" {
  if (!status.needs_setup) return "done";
  if (!status.has_owner) return "owner";
  // An owner exists: this browser either created it (resume after a reload)
  // or must sign in as it — nobody else can finish the wizard.
  return hasSession ? "provider" : "signin";
}

export default function Setup() {
  const [view, setView] = useState<"loading" | "wizard" | "signin" | "done">("loading");
  const [step, setStep] = useState<StepId>("owner");
  const [provider, setProvider] = useState<ProviderChoice | null>(null);

  useEffect(() => {
    let cancelled = false;
    const hasSession = !!localStorage.getItem("auth_token");
    const begin = (start: StepId | "done" | "signin") => {
      if (cancelled) return;
      if (start === "done" || start === "signin") {
        setView(start);
      } else {
        setStep(start);
        setView("wizard");
      }
    };
    getSetupStatus()
      .then((status) => begin(startFrom(status, hasSession)))
      // Status unknown: fall back on the session. If an owner already
      // exists, the owner step's 409 says so in words.
      .catch(() => begin(hasSession ? "provider" : "owner"));
    return () => {
      cancelled = true;
    };
  }, []);

  if (view === "done") return <Navigate to="/" replace />;

  let content: ReactNode;
  if (view === "loading") {
    content = (
      <div className="flex justify-center py-16" role="status" aria-label="Loading setup">
        <Loader2 className="w-6 h-6 animate-spin" style={{ color: "var(--text-muted)" }} aria-hidden />
      </div>
    );
  } else if (view === "signin") {
    content = (
      <StepCard eyebrow="Owner account" title="Sign in to finish setup">
        <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
          This Crawler already has an owner account, but setup was not finished. Sign in as the
          owner to pick up where you left off.
        </p>
        <Link to="/login" className={primaryCls} style={primaryStyle}>
          Sign in
        </Link>
      </StepCard>
    );
  } else if (step === "owner") {
    content = <OwnerStep onDone={() => setStep("provider")} />;
  } else if (step === "provider") {
    content = (
      <ProviderStep
        onDone={(choice) => {
          setProvider(choice);
          setStep("telegram");
        }}
      />
    );
  } else if (step === "telegram") {
    content = <TelegramStep onBack={() => setStep("provider")} onDone={() => setStep("permissions")} />;
  } else if (step === "permissions") {
    content = <PermissionsStep onBack={() => setStep("telegram")} onNext={() => setStep("summary")} />;
  } else {
    content = <SummaryStep provider={provider} onBack={() => setStep("permissions")} />;
  }

  return (
    <div
      className="relative min-h-screen flex justify-center px-4 py-6 sm:p-6"
      style={{
        background: "radial-gradient(ellipse at 50% 0%, var(--accent-glow), transparent 55%), var(--bg-primary)",
      }}
    >
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <main className="w-full max-w-[640px] flex flex-col gap-5 pt-10">
        <div className="flex flex-col items-center gap-2 text-center">
          <Wordmark height={32} />
          <div className="eyebrow" style={{ letterSpacing: "0.18em" }}>
            First-run setup
          </div>
        </div>
        {view === "wizard" && (
          <>
            <Progress current={step} />
            {/* Visually hidden; announces the new step to screen readers each
                time `step` changes, since the visible content swap alone
                does not. */}
            <div aria-live="polite" className="sr-only">
              {stepAnnouncement(step)}
            </div>
          </>
        )}
        {content}
      </main>
    </div>
  );
}

function Progress({ current }: { current: StepId }) {
  const index = STEPS.findIndex((s) => s.id === current);
  return (
    <ol aria-label="Setup progress" className="grid grid-cols-5 gap-1.5">
      {STEPS.map((s, i) => {
        const reached = i <= index;
        const isCurrent = i === index;
        return (
          <li key={s.id} aria-current={isCurrent ? "step" : undefined} className="flex flex-col gap-1.5 min-w-0">
            <span
              aria-hidden
              className="h-1 rounded-full"
              style={{ background: reached ? "var(--accent-primary)" : "var(--claw-border)" }}
            />
            <span
              className={`text-xs truncate ${isCurrent ? "" : "sr-only sm:not-sr-only"}`}
              style={{ color: isCurrent ? "var(--text-primary)" : "var(--text-muted)" }}
            >
              {s.label}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function StepCard({
  stepId,
  eyebrow,
  title,
  intro,
  children,
  footer,
}: {
  // The active step's id, so focus moves here again on every step change
  // (see the effect below). Omitted for cards outside the wizard flow
  // (e.g. the sign-in prompt), which only ever mount once anyway.
  stepId?: StepId;
  eyebrow: string;
  title: string;
  intro?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Move focus to the new step's heading whenever the step changes, so
  // screen-reader and keyboard users land on the new content instead of
  // being left on a control that just disappeared. A step component with
  // its own preferred focus target (e.g. the owner step's first field) can
  // still take focus back afterwards, since its own effect runs after this
  // one (child effects flush before the parent's).
  useEffect(() => {
    headingRef.current?.focus();
  }, [stepId]);

  return (
    <section className="rounded-[14px] p-5 sm:p-7" style={panelStyle}>
      <div className="eyebrow mb-1">{eyebrow}</div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-2">
        {title}
      </h2>
      {intro && (
        <p className="text-sm mb-5" style={{ color: "var(--text-secondary)" }}>
          {intro}
        </p>
      )}
      {children}
      {footer && <div className="flex items-center justify-between gap-3 flex-wrap mt-6">{footer}</div>}
    </section>
  );
}

function ErrorAlert({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      className="mb-4 px-3 py-2.5 rounded-[8px] text-sm"
      style={{
        background: "var(--fill-danger)",
        color: "var(--accent-danger)",
        border: "1px solid var(--border-danger)",
      }}
    >
      {children}
    </div>
  );
}

function ResultLine({ ok, children }: { ok: boolean; children: ReactNode }) {
  const Icon = ok ? CheckCircle2 : XCircle;
  return (
    <p
      // A failure needs an assertive announcement (role="alert") since it
      // usually means the user must go fix something; a success is a
      // low-priority status update.
      role={ok ? "status" : "alert"}
      className="inline-flex items-start gap-1.5 text-sm"
      style={{ color: ok ? "var(--accent-success)" : "var(--accent-danger)" }}
    >
      <Icon className="w-4 h-4 mt-0.5 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  );
}

function BackButton({
  onClick,
  disabled,
  title,
}: {
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-disabled={disabled || undefined}
      title={title}
      className={secondaryCls}
      style={secondaryStyle}
    >
      <ArrowLeft className="w-4 h-4" aria-hidden />
      Back
    </button>
  );
}

function stepEyebrow(id: StepId): string {
  return `Step ${STEPS.findIndex((s) => s.id === id) + 1} of ${STEPS.length}`;
}

/** Text for the visually-hidden live region announcing a step change. */
function stepAnnouncement(id: StepId): string {
  const index = STEPS.findIndex((s) => s.id === id);
  return `${stepEyebrow(id)}: ${STEPS[index].label}`;
}

// ---------------------------------------------------------------- owner

function OwnerStep({ onDone }: { onDone: () => void }) {
  const nameId = useId();
  const emailId = useId();
  const passwordId = useId();
  const passwordHelpId = useId();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);

  // The owner step is the wizard's entry point, so send focus straight to
  // its first field instead of the card heading StepCard focuses by
  // default. This effect's cleanup-free mount-only run fires after
  // StepCard's own (child effects flush before the parent's), so this wins.
  useEffect(() => {
    nameRef.current?.focus();
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await createOwner({ name: name.trim(), email: email.trim(), password });
      onDone();
    } catch (err) {
      setError(errorText(err, "The owner account could not be created."));
      setBusy(false);
    }
  };

  return (
    <StepCard
      stepId="owner"
      eyebrow={stepEyebrow("owner")}
      title="Create the owner account"
      intro="The owner runs this Crawler: only this account can change permissions, the AI key and the Telegram bot."
    >
      {error && <ErrorAlert>{error}</ErrorAlert>}
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div>
          <label htmlFor={nameId} className={labelCls}>
            Your name
          </label>
          <input
            id={nameId}
            ref={nameRef}
            type="text"
            autoComplete="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className={inputCls}
            style={inputStyle}
            required
          />
        </div>
        <div>
          <label htmlFor={emailId} className={labelCls}>
            Email
          </label>
          <input
            id={emailId}
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={inputCls}
            style={inputStyle}
            placeholder="you@yourdomain.com"
            required
          />
        </div>
        <div>
          <label htmlFor={passwordId} className={labelCls}>
            Password
          </label>
          <input
            id={passwordId}
            type="password"
            autoComplete="new-password"
            aria-describedby={passwordHelpId}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={inputCls}
            style={inputStyle}
            minLength={8}
            required
          />
          <p id={passwordHelpId} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
            At least 8 characters.
          </p>
        </div>
        <div className="flex justify-end mt-2">
          <button type="submit" disabled={busy} className={primaryCls} style={primaryStyle}>
            {busy ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
            Create owner account
          </button>
        </div>
      </form>
    </StepCard>
  );
}

// ---------------------------------------------------------------- provider

type TestState =
  | { status: "idle" }
  | { status: "testing" | "passed" | "failed"; for: string; message: string };

function orderProviders(list: SetupProvider[]): SetupProvider[] {
  const rank = (name: string) => {
    const i = PROVIDER_ORDER.indexOf(name);
    return i === -1 ? PROVIDER_ORDER.length : i;
  };
  return [...list].sort((a, b) => rank(a.name) - rank(b.name));
}

function initialChoice(data: SetupProviders): { name: string; model: string } {
  const { providers, current } = data;
  const pick =
    providers.find((p) => p.name === current.provider) ??
    providers.find((p) => p.name === "gemini") ??
    providers[0];
  if (!pick) return { name: "", model: "" };
  const model = pick.name === current.provider && current.model ? current.model : pick.models[0] ?? "";
  return { name: pick.name, model };
}

function ProviderStep({ onDone }: { onDone: (choice: ProviderChoice) => void }) {
  const groupLabelId = useId();
  const modelId = useId();
  const modelListId = useId();
  const keyId = useId();
  const [data, setData] = useState<SetupProviders | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [name, setName] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [test, setTest] = useState<TestState>({ status: "idle" });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");

  useEffect(() => {
    let cancelled = false;
    getSetupProviders()
      .then((d) => {
        if (cancelled) return;
        const ordered = { ...d, providers: orderProviders(d.providers) };
        const first = initialChoice(ordered);
        setData(ordered);
        setName(first.name);
        setModel(first.model);
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "The provider list could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const selected = data?.providers.find((p) => p.name === name);
  // Ollama runs on the user's own machine and has no key at all.
  const takesKey = !!selected && !selected.key_from_env && selected.name !== "ollama";
  const keyRequired = takesKey && !selected?.key_stored;

  const choice: ProviderChoice = {
    provider: name,
    model: model.trim(),
    ...(takesKey && apiKey.trim() ? { api_key: apiKey.trim() } : {}),
  };
  // A test result only counts for the exact provider/model/key it ran
  // against; any edit afterwards means the saved settings would be untested.
  const fingerprint = JSON.stringify(choice);
  const result = test.status !== "idle" && test.for === fingerprint ? test : null;
  const passed = result?.status === "passed";
  const canTest =
    !!selected && !!choice.model && (!keyRequired || !!choice.api_key) && result?.status !== "testing";

  const choose = (p: SetupProvider) => {
    setName(p.name);
    setModel(p.models[0] ?? "");
    setApiKey("");
    setSaveError("");
  };

  const runTest = async () => {
    const body = choice;
    const key = fingerprint;
    setSaveError("");
    setTest({ status: "testing", for: key, message: "" });
    try {
      const r = await testProvider(body);
      setTest(
        r.ok
          ? { status: "passed", for: key, message: r.reply ?? "" }
          : { status: "failed", for: key, message: r.error || "The provider did not answer." },
      );
    } catch (err) {
      setTest({ status: "failed", for: key, message: errorText(err, "The test request failed.") });
    }
  };

  const save = async () => {
    setSaving(true);
    setSaveError("");
    try {
      await saveProvider(choice);
      onDone({ provider: choice.provider, model: choice.model });
    } catch (err) {
      setSaveError(errorText(err, "The provider could not be saved."));
      setSaving(false);
    }
  };

  return (
    <StepCard
      stepId="provider"
      eyebrow={stepEyebrow("provider")}
      title="AI provider"
      intro="Crawler needs one AI model to think with. Pick a provider, test it, then save. The key stays on this server."
      footer={
        <>
          {/* No real Back button here: the owner account was just created
              and cannot be re-created, so there is no earlier step to
              return to. A disabled one is rendered anyway so the footer's
              buttons line up with every other step. */}
          <BackButton disabled title="The owner account is already created" />
          <button type="button" onClick={() => void save()} disabled={!passed || saving} className={primaryCls} style={primaryStyle}>
            {saving ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
            Save & continue
            <ArrowRight className="w-4 h-4" aria-hidden />
          </button>
        </>
      }
    >
      {loadError && (
        <ErrorAlert>
          {loadError}{" "}
          <button
            type="button"
            className="underline font-medium"
            onClick={() => {
              setLoadError("");
              setAttempt((n) => n + 1);
            }}
          >
            Try again
          </button>
        </ErrorAlert>
      )}
      {saveError && <ErrorAlert>{saveError}</ErrorAlert>}
      {!data && !loadError ? (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Loading providers…
        </p>
      ) : data ? (
        <div className="space-y-4">
          <div>
            <span id={groupLabelId} className={labelCls}>
              Provider
            </span>
            <div role="radiogroup" aria-labelledby={groupLabelId} className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {data.providers.map((p) => {
                const active = p.name === name;
                return (
                  <button
                    key={p.name}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    onClick={() => choose(p)}
                    className="px-3 py-2.5 rounded-[10px] text-sm font-medium capitalize transition-colors"
                    style={{
                      minHeight: 44,
                      background: active ? "var(--accent-glow)" : "var(--claw-surface)",
                      border: active ? "1px solid var(--border-accent)" : "1px solid var(--claw-border)",
                      color: active ? "var(--accent-primary)" : "var(--text-secondary)",
                    }}
                  >
                    {p.name}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <label htmlFor={modelId} className={labelCls}>
              Model
            </label>
            <input
              id={modelId}
              type="text"
              list={modelListId}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className={inputCls}
              style={inputStyle}
              autoComplete="off"
              spellCheck={false}
            />
            <datalist id={modelListId}>
              {(selected?.models ?? []).map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
          </div>

          {selected?.key_from_env ? (
            <div
              className="rounded-[10px] px-3.5 py-3 text-sm"
              style={{ background: "var(--bg-input)", border: "1px solid var(--claw-border)" }}
            >
              <span className="inline-flex items-center gap-1.5 font-medium" style={{ color: "var(--accent-success)" }}>
                <CheckCircle2 className="w-4 h-4" aria-hidden />
                <span>Provided by server configuration</span>
              </span>
              <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                The server&apos;s <code>.env</code> file holds this key, and it always takes priority.
              </p>
            </div>
          ) : selected?.name === "ollama" ? (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Ollama runs on your own machine — no key needed.
            </p>
          ) : selected ? (
            <div>
              <label htmlFor={keyId} className={labelCls}>
                API key
              </label>
              <input
                id={keyId}
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className={inputCls}
                style={inputStyle}
                autoComplete="off"
                spellCheck={false}
                placeholder={selected.key_stored ? "A key is saved — leave blank to keep it" : "Paste your key"}
              />
            </div>
          ) : null}

          <div className="flex items-center gap-3 flex-wrap">
            <button type="button" onClick={() => void runTest()} disabled={!canTest} className={secondaryCls} style={secondaryStyle}>
              {result?.status === "testing" ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
              Test
            </button>
            {result?.status === "passed" && (
              <ResultLine ok>
                It works — the model replied{result.message ? ` “${result.message}”` : ""}.
              </ResultLine>
            )}
            {result?.status === "failed" && <ResultLine ok={false}>{result.message}</ResultLine>}
          </div>
        </div>
      ) : null}
    </StepCard>
  );
}

// ---------------------------------------------------------------- telegram

function TelegramStep({ onBack, onDone }: { onBack: () => void; onDone: () => void }) {
  const tokenId = useId();
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState<"test" | "save" | "link" | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [savedBot, setSavedBot] = useState<string | null>(null);
  const [link, setLink] = useState<TelegramLink | null>(null);

  const run = async (kind: "test" | "save" | "link", fn: () => Promise<void>) => {
    setBusy(kind);
    setFeedback(null);
    try {
      await fn();
    } catch (err) {
      setFeedback({ ok: false, text: errorText(err, "Telegram did not answer.") });
    } finally {
      setBusy(null);
    }
  };

  const onTest = () =>
    run("test", async () => {
      const r = await testTelegram(token.trim());
      setFeedback(
        r.ok
          ? { ok: true, text: `The token works — your bot is @${r.bot_username}.` }
          : { ok: false, text: r.error || "Telegram rejected that token." },
      );
    });

  const onSave = () =>
    run("save", async () => {
      const r = await saveTelegram(token.trim());
      setSavedBot(r.bot_username);
      setToken("");
      setFeedback({ ok: true, text: `Saved. Crawler now answers as @${r.bot_username}.` });
    });

  const onLink = () =>
    run("link", async () => {
      setLink(await createTelegramLink());
    });

  const hasToken = !!token.trim();

  return (
    <StepCard
      stepId="telegram"
      eyebrow={`${stepEyebrow("telegram")} · optional`}
      title="Telegram (optional)"
      intro="Chat with Crawler from your phone and approve its actions with one tap."
      footer={
        <>
          <BackButton onClick={onBack} />
          {savedBot ? (
            <button type="button" onClick={onDone} className={primaryCls} style={primaryStyle}>
              Continue
              <ArrowRight className="w-4 h-4" aria-hidden />
            </button>
          ) : (
            <button type="button" onClick={onDone} className={secondaryCls} style={secondaryStyle}>
              Skip
            </button>
          )}
        </>
      }
    >
      <ol className="list-decimal pl-5 space-y-1 text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
        <li>
          In Telegram, message{" "}
          <a href="https://t.me/BotFather" target="_blank" rel="noreferrer" style={{ color: "var(--accent-primary)" }}>
            @BotFather
          </a>{" "}
          and send <code>/newbot</code>.
        </li>
        <li>Pick any name. BotFather replies with a token.</li>
        <li>Paste the token below, test it, then save.</li>
      </ol>

      <label htmlFor={tokenId} className={labelCls}>
        Bot token
      </label>
      <input
        id={tokenId}
        type="password"
        value={token}
        onChange={(e) => setToken(e.target.value)}
        className={inputCls}
        style={inputStyle}
        autoComplete="off"
        spellCheck={false}
        placeholder={savedBot ? "Saved — paste a new token to replace it" : "123456789:AA…"}
      />

      <div className="flex items-center gap-3 flex-wrap mt-3">
        <button type="button" onClick={() => void onTest()} disabled={!hasToken || !!busy} className={secondaryCls} style={secondaryStyle}>
          {busy === "test" ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
          Test
        </button>
        <button type="button" onClick={() => void onSave()} disabled={!hasToken || !!busy} className={secondaryCls} style={secondaryStyle}>
          {busy === "save" ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
          Save
        </button>
        {feedback && <ResultLine ok={feedback.ok}>{feedback.text}</ResultLine>}
      </div>

      {savedBot && (
        <div className="mt-4 space-y-2">
          <button type="button" onClick={() => void onLink()} disabled={!!busy} className={primaryCls} style={primaryStyle}>
            {busy === "link" ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
            Link your chat
          </button>
          {link && (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Open{" "}
              <a href={link.link_url} target="_blank" rel="noreferrer" style={{ color: "var(--accent-primary)" }}>
                {link.link_url}
              </a>{" "}
              on your phone and tap Start (valid {link.expires_in_minutes} min).
            </p>
          )}
        </div>
      )}
    </StepCard>
  );
}

// ---------------------------------------------------------------- permissions

/** Load the capability report, with a retry the caller can trigger. */
function useCapabilities() {
  const [items, setItems] = useState<CapabilityStatus[] | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    getCapabilities()
      .then((caps) => {
        if (!cancelled) setItems(caps);
      })
      .catch((err) => {
        if (!cancelled) setError(errorText(err, "The permission list could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const retry = () => {
    setError("");
    setAttempt((n) => n + 1);
  };
  return { items, setItems, error, setError, retry };
}

function PermissionsStep({ onBack, onNext }: { onBack: () => void; onNext: () => void }) {
  const { items, setItems, error, setError, retry } = useCapabilities();
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const act = async (key: string, fn: () => Promise<CapabilityStatus[]>) => {
    setBusyKey(key);
    setError("");
    try {
      setItems(await fn());
    } catch (err) {
      setError(errorText(err, "That change could not be saved."));
    } finally {
      setBusyKey(null);
    }
  };

  return (
    <StepCard
      stepId="permissions"
      eyebrow={stepEyebrow("permissions")}
      title="Permissions"
      intro="Choose what Crawler may do. Anything you turn off, it tells you it cannot do instead of trying. You can change these later in Settings."
      footer={
        <>
          <BackButton onClick={onBack} />
          <button type="button" onClick={onNext} className={primaryCls} style={primaryStyle}>
            Next
            <ArrowRight className="w-4 h-4" aria-hidden />
          </button>
        </>
      }
    >
      {error && (
        <ErrorAlert>
          {error}
          {!items && (
            <>
              {" "}
              <button type="button" className="underline font-medium" onClick={retry}>
                Try again
              </button>
            </>
          )}
        </ErrorAlert>
      )}
      {items ? (
        <CapabilityList
          items={items}
          editable
          busyKey={busyKey}
          onToggle={(key, enabled) => void act(key, () => updateCapabilities({ [key]: enabled }))}
          onRequestAccess={(key) =>
            void act(key, async () => {
              await requestCapabilityAccess(key);
              return getCapabilities();
            })
          }
          onInstall={(key) =>
            void act(key, async () => {
              const r = await installCapability(key);
              if (!r.ok) throw new Error(r.error || "The install did not finish.");
              return getCapabilities();
            })
          }
        />
      ) : !error ? (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Checking what this computer allows…
        </p>
      ) : null}
    </StepCard>
  );
}

// ---------------------------------------------------------------- summary

type SummaryStatus = "Works" | "Not available" | "Off";

const STATUS_COLOR: Record<SummaryStatus, string> = {
  Works: "var(--accent-success)",
  "Not available": "var(--accent-danger)",
  Off: "var(--text-muted)",
};

function summaryRow(c: CapabilityStatus): { status: SummaryStatus; detail: string } {
  if (c.effective === "on") return { status: "Works", detail: c.description };
  if (c.effective === "blocked") return { status: "Not available", detail: c.reason };
  return { status: "Off", detail: c.when_denied };
}

const NEVER = [
  "buy anything or enter payment details",
  "move money or trade",
  "run as an administrator",
  "install skills from a marketplace",
];

function SummaryStep({ provider, onBack }: { provider: ProviderChoice | null; onBack: () => void }) {
  const tableLabelId = useId();
  const allowId = useId();
  const allowHelpId = useId();
  const { items, error: loadError, retry } = useCapabilities();
  const [allowRegistration, setAllowRegistration] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const finish = async () => {
    setBusy(true);
    setError("");
    try {
      await completeSetup({ allow_registration: allowRegistration });
      // A full load, not a client-side navigate: the app decides whether to
      // show /setup from a status it fetches once at start.
      window.location.assign("/");
    } catch (err) {
      setError(errorText(err, "Setup could not be completed."));
      setBusy(false);
    }
  };

  const rows: { key: string; label: string; status: SummaryStatus; detail: string }[] = [
    {
      key: "__provider",
      label: "AI provider",
      status: provider ? "Works" : "Not available",
      detail: provider ? `${provider.provider} · ${provider.model}` : "No provider was saved.",
    },
    ...(items ?? []).map((c) => ({ key: c.key, label: c.label, ...summaryRow(c) })),
  ];

  return (
    <StepCard
      stepId="summary"
      eyebrow={stepEyebrow("summary")}
      title="Summary"
      footer={
        <>
          <BackButton onClick={onBack} />
          <button type="button" onClick={() => void finish()} disabled={busy} className={primaryCls} style={primaryStyle}>
            {busy ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
            Finish
          </button>
        </>
      }
    >
      {error && <ErrorAlert>{error}</ErrorAlert>}

      <h3 id={tableLabelId} className="text-sm font-semibold mb-2">
        What works and what doesn&apos;t
      </h3>
      {loadError && (
        <ErrorAlert>
          {loadError}{" "}
          <button type="button" className="underline font-medium" onClick={retry}>
            Try again
          </button>
        </ErrorAlert>
      )}
      <table aria-labelledby={tableLabelId} className="w-full text-sm">
        <thead className="sr-only">
          <tr>
            <th scope="col">Feature</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} style={{ borderTop: "1px solid var(--claw-border)" }}>
              <td className="py-2.5 pr-3 align-top">
                <div className="font-medium" style={{ color: "var(--text-primary)" }}>
                  {r.label}
                </div>
                {r.detail && (
                  <div className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                    {r.detail}
                  </div>
                )}
              </td>
              <td className="py-2.5 align-top text-right whitespace-nowrap font-medium" style={{ color: STATUS_COLOR[r.status] }}>
                {r.status}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!items && !loadError && (
        <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
          Checking permissions…
        </p>
      )}

      <div
        className="mt-5 rounded-[10px] p-4"
        style={{ background: "var(--bg-input)", border: "1px solid var(--claw-border)" }}
      >
        {/* The whole row — title and description both — toggles the
            checkbox: it's all one <label>, not just the title text. */}
        <label htmlFor={allowId} className="flex items-start gap-3 cursor-pointer">
          <input
            id={allowId}
            type="checkbox"
            checked={allowRegistration}
            onChange={(e) => setAllowRegistration(e.target.checked)}
            aria-describedby={allowHelpId}
            className="mt-0.5 w-4 h-4 shrink-0"
            style={{ accentColor: "var(--accent-primary)" }}
          />
          <div>
            <span className="text-sm font-medium">Allow other people to create accounts on this Crawler</span>
            <p id={allowHelpId} className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
              Leave this off unless someone else on your network needs their own login.
            </p>
          </div>
        </label>
      </div>

      <div className="mt-5">
        <p className="text-sm font-semibold mb-1.5">Crawler never, whatever it is asked:</p>
        <ul className="list-disc pl-5 space-y-0.5 text-sm" style={{ color: "var(--text-secondary)" }}>
          {NEVER.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
    </StepCard>
  );
}
