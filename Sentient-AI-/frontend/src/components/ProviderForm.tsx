import { useEffect, useId, useState, type ReactNode } from "react";
import { ArrowRight, CheckCircle2, Loader2 } from "lucide-react";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
import {
  errorText,
  inputCls,
  inputStyle,
  labelCls,
  primaryCls,
  primaryStyle,
  secondaryCls,
  secondaryStyle,
} from "@/components/formStyles";
import { clearStoredSecrets, getSetupProviders, saveProvider, testProvider } from "@/services/api";
import type { ProviderChoice, SetupProvider, SetupProviders } from "@/types";

// Picks this Crawler's AI provider: the setup wizard's provider step, and
// the owner's Settings ▸ Server section afterwards. One form, so the rules
// hold in both places: a key the server's .env provides is never asked for,
// and nothing is saved until a test against the exact provider, model and
// key has passed.

// Same order as Settings > LLM provider, so the two screens read alike.
// Providers the server offers but this list does not know go last.
const PROVIDER_ORDER = ["anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"];

// The 409 PUT /setup/provider answers while stored keys cannot be
// decrypted. Its fix is the same "Clear stored keys" the status flag
// offers, so the notice appears even if the status was read before.
const UNDECRYPTABLE = /cannot be decrypted/i;

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

export interface ProviderFormProps {
  /** After a successful save, with what was saved (never the key). */
  onSaved?: (choice: ProviderChoice) => void;
  /**
   * Settings layout: the form stays put after saving and says so, with
   * "Test provider" / "Save provider" side by side. Without it (the
   * wizard), Save sits at the right of a footer row as "Save & continue".
   */
  compact?: boolean;
  /** GET /setup/status `secrets_unreadable`: offer "Clear stored keys". */
  secretsUnreadable?: boolean;
  /** After the stored keys were cleared, so the caller can re-read the status. */
  onSecretsCleared?: () => void;
  /** Wizard only: rendered at the left of the footer row (its Back button). */
  footerStart?: ReactNode;
}

export default function ProviderForm({
  onSaved,
  compact = false,
  secretsUnreadable = false,
  onSecretsCleared,
  footerStart,
}: ProviderFormProps) {
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
  const [savedNote, setSavedNote] = useState("");
  const [undecryptable, setUndecryptable] = useState(false);
  const [clearingSecrets, setClearingSecrets] = useState(false);
  const [clearSecretsError, setClearSecretsError] = useState("");

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
  const showSecretsNotice = secretsUnreadable || undecryptable;

  const choose = (p: SetupProvider) => {
    setName(p.name);
    setModel(p.models[0] ?? "");
    setApiKey("");
    setSaveError("");
    setSavedNote("");
  };

  const runTest = async () => {
    const body = choice;
    const key = fingerprint;
    setSaveError("");
    setSavedNote("");
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
    setSavedNote("");
    try {
      await saveProvider(choice);
      const saved = { provider: choice.provider, model: choice.model };
      if (compact) {
        // The form stays on screen: what was saved is now the install
        // default, and a key just sent is now held by the server — so the
        // field empties rather than keeping a secret around.
        setData((d) =>
          d && {
            ...d,
            current: saved,
            providers: d.providers.map((p) =>
              p.name === choice.provider && choice.api_key ? { ...p, key_stored: true } : p,
            ),
          },
        );
        setApiKey("");
        setSavedNote(`Saved. This Crawler now uses ${saved.provider} · ${saved.model}.`);
        setSaving(false);
      }
      onSaved?.(saved);
    } catch (err) {
      // 409s (a key .env provides, keys that cannot be decrypted) carry
      // the server's own sentence; show it as-is.
      const message = errorText(err, "The provider could not be saved.");
      if (UNDECRYPTABLE.test(message)) setUndecryptable(true);
      setSaveError(message);
      setSaving(false);
    }
  };

  const handleClearSecrets = async () => {
    setClearingSecrets(true);
    setClearSecretsError("");
    try {
      await clearStoredSecrets();
      setUndecryptable(false);
      setSaveError("");
      onSecretsCleared?.();
      // The keys just cleared are the same ones key_stored reflects, so
      // reload the provider list too rather than leaving it stale.
      setAttempt((n) => n + 1);
    } catch (err) {
      setClearSecretsError(errorText(err, "Could not clear the stored keys."));
    } finally {
      setClearingSecrets(false);
    }
  };

  const saveButton = (
    <button
      type="button"
      onClick={() => void save()}
      disabled={!passed || saving}
      className={primaryCls}
      style={primaryStyle}
    >
      {saving ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
      {compact ? (
        "Save provider"
      ) : (
        <>
          Save & continue
          <ArrowRight className="w-4 h-4" aria-hidden />
        </>
      )}
    </button>
  );

  return (
    <div>
      {showSecretsNotice && (
        <div
          role="alert"
          className="rounded-[10px] px-3.5 py-3 text-sm space-y-2 mb-4"
          style={{ background: "var(--fill-danger)", border: "1px solid var(--border-danger)" }}
        >
          <p style={{ color: "var(--accent-danger)" }}>
            Stored provider keys can&apos;t be read (the encryption key changed or was lost).
            Saving will keep failing until they are cleared.
          </p>
          <button
            type="button"
            onClick={() => void handleClearSecrets()}
            disabled={clearingSecrets}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
            style={{ background: "var(--accent-danger)", color: "var(--text-on-accent)" }}
          >
            {clearingSecrets ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : null}
            Clear stored keys
          </button>
          {clearSecretsError && <p style={{ color: "var(--accent-danger)" }}>{clearSecretsError}</p>}
        </div>
      )}
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
          {data.current.provider ? (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Current default:{" "}
              <span className="font-medium" style={{ color: "var(--text-primary)" }}>
                {data.current.provider} · {data.current.model}
              </span>
            </p>
          ) : compact ? (
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              No AI provider is set up yet.
            </p>
          ) : null}

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
              {compact ? "Test provider" : "Test"}
            </button>
            {compact && saveButton}
            {result?.status === "passed" && (
              <ResultLine ok>
                It works — the model replied{result.message ? ` “${result.message}”` : ""}.
              </ResultLine>
            )}
            {result?.status === "failed" && <ResultLine ok={false}>{result.message}</ResultLine>}
            {savedNote && <ResultLine ok>{savedNote}</ResultLine>}
          </div>
        </div>
      ) : null}
      {!compact && (
        <div
          className={`flex items-center gap-3 flex-wrap mt-6 ${footerStart ? "justify-between" : "justify-end"}`}
        >
          {footerStart}
          {saveButton}
        </div>
      )}
    </div>
  );
}
