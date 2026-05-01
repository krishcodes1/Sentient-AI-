import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Brain,
  ArrowRight,
  ArrowLeft,
  Check,
  Sparkles,
  Key,
  Server,
  MessageSquare,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ApiError,
  getAuditLogs,
  updateSettings,
} from "@/services/api";
import { ErrorBanner } from "@/components/ui/ErrorBanner";

type ProviderId =
  | "openai"
  | "anthropic"
  | "gemini"
  | "grok"
  | "deepseek"
  | "groq"
  | "mistral"
  | "ollama";

interface ProviderDef {
  id: ProviderId;
  name: string;
  models: string[];
  desc: string;
  /** Plain-English hint shown next to the API-key input. */
  keyHint?: string;
  /** Returns null on success, or an error message on failed format check. */
  validateKey?: (raw: string) => string | null;
}

function startsWithCheck(prefix: string, hint: string) {
  return (raw: string): string | null => {
    const v = raw.trim();
    if (!v.startsWith(prefix)) {
      return `Doesn't look like a valid key. ${hint}`;
    }
    return null;
  };
}

const PROVIDERS: ProviderDef[] = [
  {
    id: "openai",
    name: "OpenAI",
    models: ["gpt-4o", "gpt-4o-mini", "o1-preview", "o1"],
    desc: "GPT-4o and beyond",
    keyHint: "OpenAI keys start with sk-.",
    validateKey: startsWithCheck("sk-", "OpenAI keys start with sk-."),
  },
  {
    id: "anthropic",
    name: "Anthropic",
    models: [
      "claude-sonnet-4-20250514",
      "claude-opus-4-20250514",
      "claude-haiku-4-5-20251001",
    ],
    desc: "Claude models",
    keyHint: "Anthropic keys start with sk-ant-.",
    validateKey: startsWithCheck("sk-ant-", "Anthropic keys start with sk-ant-."),
  },
  {
    id: "gemini",
    name: "Google Gemini",
    models: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
    desc: "Gemini multimodal",
    keyHint: "Gemini keys start with AIza and are around 39 characters long.",
    validateKey: (raw: string): string | null => {
      const v = raw.trim();
      if (!v.startsWith("AIza")) {
        return "Doesn't look like a valid key. Gemini keys start with AIza.";
      }
      if (v.length < 35) {
        return "Doesn't look like a valid key. Gemini keys are around 39 characters long.";
      }
      return null;
    },
  },
  {
    id: "grok",
    name: "xAI Grok",
    models: ["grok-3", "grok-3-mini"],
    desc: "Grok reasoning",
    keyHint: "Paste the API key from your xAI console.",
  },
  {
    id: "deepseek",
    name: "Deepseek",
    models: ["deepseek-chat", "deepseek-reasoner"],
    desc: "Cost-effective AI",
    keyHint: "Paste the API key from your Deepseek dashboard.",
  },
  {
    id: "groq",
    name: "Groq",
    models: ["llama-3.3-70b-versatile", "mixtral-8x7b-32768"],
    desc: "Ultra-fast inference",
    keyHint: "Groq keys start with gsk_.",
    validateKey: startsWithCheck("gsk_", "Groq keys start with gsk_."),
  },
  {
    id: "mistral",
    name: "Mistral",
    models: ["mistral-large-latest", "mistral-small-latest"],
    desc: "European AI",
    keyHint: "Paste the API key from your Mistral console.",
  },
  {
    id: "ollama",
    name: "Ollama",
    models: ["llama3.2", "mistral", "codellama", "mixtral"],
    desc: "Local / self-hosted",
  },
];

interface Step {
  icon: LucideIcon;
  label: string;
}

const STEPS: Step[] = [
  { icon: Sparkles, label: "Welcome" },
  { icon: Brain, label: "Provider" },
  { icon: Key, label: "API Key" },
  { icon: Server, label: "Model" },
  { icon: MessageSquare, label: "Ready" },
];

function getErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  return fallback;
}

export default function Onboarding() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<ProviderId>("openai");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState<string>("gpt-4o");
  const [keyError, setKeyError] = useState<string | null>(null);

  const selectedProvider =
    PROVIDERS.find((p) => p.id === provider) ?? PROVIDERS[0];

  const finishMutation = useMutation({
    mutationFn: () =>
      updateSettings({
        name: name.trim(),
        llm_provider: provider,
        llm_model: model,
        llm_api_key: provider === "ollama" ? "ollama" : apiKey.trim(),
        onboarding_completed: true,
      }),
    onSuccess: () => {
      // Warm the dashboard cache so /gateway → /overview feels instant.
      void queryClient.prefetchQuery({
        queryKey: ["audit-recent"],
        queryFn: () => getAuditLogs({ limit: 10 }),
      });
      navigate("/gateway");
    },
  });

  const skipMutation = useMutation({
    mutationFn: () => updateSettings({ onboarding_completed: true }),
    onSuccess: () => navigate("/gateway"),
    onError: () => {
      // If the backend rejects (e.g. older deploy without that field),
      // still let the user out of the flow.
      navigate("/gateway");
    },
  });

  const error = finishMutation.error
    ? getErrorMessage(finishMutation.error, "Failed to save settings")
    : null;

  /** Validate the API key for the current provider; returns null when ok. */
  const validateApiKey = (): string | null => {
    if (provider === "ollama") return null;
    const trimmed = apiKey.trim();
    if (!trimmed) return "Please enter your API key.";
    const validator = selectedProvider.validateKey;
    if (validator) return validator(trimmed);
    return null;
  };

  const canNext = (): boolean => {
    if (step === 0) return name.trim().length >= 1;
    if (step === 1) return true;
    if (step === 2) return validateApiKey() === null;
    if (step === 3) return model.length > 0;
    return true;
  };

  const goNext = () => {
    if (step === 2) {
      const err = validateApiKey();
      if (err) {
        setKeyError(err);
        return;
      }
      setKeyError(null);
    }
    setStep(step + 1);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-[var(--bg-primary)]">
      <div className="w-full max-w-[560px]">
        {/* Progress dots */}
        <div className="flex items-center justify-center gap-3 mb-8">
          {STEPS.map((s, i) => {
            const Icon = s.icon;
            const active = i === step;
            const done = i < step;
            return (
              <div key={s.label} className="flex items-center gap-3">
                <div
                  className="w-9 h-9 rounded-full flex items-center justify-center transition-all duration-300"
                  style={{
                    backgroundColor: done
                      ? "var(--accent-success)"
                      : active
                        ? "var(--accent-primary)"
                        : "var(--bg-tertiary)",
                  }}
                >
                  {done ? (
                    <Check className="w-4 h-4 text-white" strokeWidth={2.5} />
                  ) : (
                    <Icon
                      className="w-4 h-4"
                      style={{ color: active ? "#fff" : "var(--text-muted)" }}
                      strokeWidth={1.75}
                    />
                  )}
                </div>
                {i < STEPS.length - 1 && (
                  <div
                    className="w-8 h-px"
                    style={{
                      backgroundColor: i < step ? "var(--accent-success)" : "var(--border-primary)",
                    }}
                  />
                )}
              </div>
            );
          })}
        </div>

        {/* Card */}
        <div
          className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-8 md:p-10"
          style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
        >
          {/* Step 0: Welcome */}
          {step === 0 && (
            <div className="space-y-6">
              <div className="text-center space-y-2">
                <div className="w-16 h-16 rounded-[16px] bg-[var(--accent-primary)] flex items-center justify-center mx-auto mb-4">
                  <Brain className="w-9 h-9 text-white" strokeWidth={1.75} />
                </div>
                <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)]">
                  Welcome to SentientAI
                </h1>
                <p className="text-[15px] text-[var(--text-secondary)] leading-relaxed max-w-sm mx-auto">
                  Let&apos;s get you set up. First, what should we call you?
                </p>
              </div>
              <div>
                <label
                  htmlFor="onboarding-name"
                  className="block text-[13px] font-medium text-[var(--text-secondary)] mb-2"
                >
                  Your name
                </label>
                <input
                  id="onboarding-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Enter your name"
                  autoFocus
                  className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors"
                />
              </div>
            </div>
          )}

          {/* Step 1: Choose Provider */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="text-center space-y-2">
                <h2 className="text-[24px] font-semibold tracking-tight text-[var(--text-primary)]">
                  Choose your AI provider
                </h2>
                <p className="text-[15px] text-[var(--text-secondary)] leading-relaxed">
                  Pick which LLM powers your assistant. You can change this later.
                </p>
              </div>
              <div role="radiogroup" aria-label="Provider" className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {PROVIDERS.map((p) => {
                  const isSelected = provider === p.id;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      role="radio"
                      aria-checked={isSelected}
                      aria-pressed={isSelected}
                      onClick={() => {
                        setProvider(p.id);
                        setModel(p.models[0]);
                      }}
                      className="text-left px-4 py-3.5 rounded-[14px] border transition-all duration-200"
                      style={{
                        backgroundColor: isSelected ? "rgba(10,132,255,0.14)" : "var(--bg-tertiary)",
                        borderColor: isSelected ? "var(--accent-primary)" : "var(--border-subtle)",
                      }}
                    >
                      <span
                        className="text-[15px] font-medium block"
                        style={{ color: isSelected ? "var(--text-primary)" : "var(--text-secondary)" }}
                      >
                        {p.name}
                      </span>
                      <span className="text-[12px] block mt-0.5 text-[var(--text-muted)]">
                        {p.desc}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Step 2: API Key */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="text-center space-y-2">
                <h2 className="text-[24px] font-semibold tracking-tight text-[var(--text-primary)]">
                  {provider === "ollama"
                    ? "Ollama connection"
                    : `Enter your ${selectedProvider.name} API key`}
                </h2>
                <p className="text-[15px] text-[var(--text-secondary)] leading-relaxed max-w-sm mx-auto">
                  {provider === "ollama"
                    ? "Make sure Ollama is running locally on port 11434."
                    : "Your API key is encrypted and stored securely. It never leaves the server."}
                </p>
              </div>
              {provider !== "ollama" && (
                <div>
                  <label
                    htmlFor="onboarding-api-key"
                    className="block text-[13px] font-medium text-[var(--text-secondary)] mb-2"
                  >
                    API Key
                  </label>
                  <input
                    id="onboarding-api-key"
                    type="password"
                    value={apiKey}
                    onChange={(e) => {
                      setApiKey(e.target.value);
                      if (keyError) setKeyError(null);
                    }}
                    placeholder="sk-..."
                    autoFocus
                    aria-invalid={Boolean(keyError) || undefined}
                    aria-describedby={
                      keyError ? "onboarding-api-key-error" : "onboarding-api-key-hint"
                    }
                    className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors font-mono"
                  />
                  {keyError ? (
                    <p
                      id="onboarding-api-key-error"
                      role="alert"
                      className="mt-2 text-[12px] text-[var(--accent-danger)] leading-relaxed"
                    >
                      {keyError}
                    </p>
                  ) : selectedProvider.keyHint ? (
                    <p
                      id="onboarding-api-key-hint"
                      className="mt-2 text-[12px] text-[var(--text-muted)] leading-relaxed"
                    >
                      {selectedProvider.keyHint}
                    </p>
                  ) : null}
                </div>
              )}
              {provider === "ollama" && (
                <div className="rounded-[14px] border border-[var(--border-subtle)] bg-[var(--bg-tertiary)] p-5 text-center">
                  <Server
                    className="w-10 h-10 text-[var(--accent-primary)] mx-auto mb-3"
                    strokeWidth={1.5}
                  />
                  <p className="text-[15px] text-[var(--text-primary)] font-medium">Local server</p>
                  <p className="text-[13px] text-[var(--text-muted)] mt-1">
                    No API key needed. Make sure{" "}
                    <code className="text-[var(--accent-primary)]">ollama serve</code> is running.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 3: Choose Model */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="text-center space-y-2">
                <h2 className="text-[24px] font-semibold tracking-tight text-[var(--text-primary)]">
                  Pick a model
                </h2>
                <p className="text-[15px] text-[var(--text-secondary)] leading-relaxed">
                  Choose the default model for {selectedProvider.name}.
                </p>
              </div>
              <div role="radiogroup" aria-label="Model" className="flex flex-col gap-2">
                {selectedProvider.models.map((m) => {
                  const isSelected = model === m;
                  return (
                    <button
                      key={m}
                      type="button"
                      role="radio"
                      aria-checked={isSelected}
                      aria-pressed={isSelected}
                      onClick={() => setModel(m)}
                      className="text-left px-4 py-3.5 rounded-[14px] border transition-all duration-200 flex items-center justify-between"
                      style={{
                        backgroundColor: isSelected ? "rgba(10,132,255,0.14)" : "var(--bg-tertiary)",
                        borderColor: isSelected ? "var(--accent-primary)" : "var(--border-subtle)",
                      }}
                    >
                      <span
                        className="text-[15px] font-mono"
                        style={{ color: isSelected ? "var(--text-primary)" : "var(--text-secondary)" }}
                      >
                        {m}
                      </span>
                      {isSelected && (
                        <Check className="w-5 h-5 text-[var(--accent-primary)]" strokeWidth={2.5} />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Step 4: Done */}
          {step === 4 && (
            <div className="space-y-6 text-center">
              <div className="w-16 h-16 rounded-full bg-[rgba(48,209,88,0.2)] flex items-center justify-center mx-auto">
                <Check className="w-8 h-8 text-[var(--accent-success)]" strokeWidth={2} />
              </div>
              <div className="space-y-2">
                <h2 className="text-[24px] font-semibold tracking-tight text-[var(--text-primary)]">
                  You're all set, {name}!
                </h2>
                <p className="text-[15px] text-[var(--text-secondary)] leading-relaxed max-w-sm mx-auto">
                  SentientAI is configured with{" "}
                  <strong className="text-[var(--text-primary)]">{selectedProvider.name}</strong>{" "}
                  using <code className="text-[var(--accent-primary)]">{model}</code>.
                </p>
              </div>
              <div className="rounded-[14px] border border-[var(--border-subtle)] bg-[var(--bg-tertiary)] p-4 text-left space-y-2 text-[13px]">
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Name</span>
                  <span className="text-[var(--text-primary)]">{name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Provider</span>
                  <span className="text-[var(--text-primary)]">{selectedProvider.name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Model</span>
                  <span className="text-[var(--text-primary)] font-mono">{model}</span>
                </div>
              </div>
            </div>
          )}

          {error && <div className="mt-4"><ErrorBanner message={error} /></div>}

          {/* Navigation */}
          <div className="flex items-center justify-between mt-8">
            {step > 0 ? (
              <button
                type="button"
                onClick={() => setStep(step - 1)}
                className="flex items-center gap-2 px-4 py-2.5 rounded-[12px] text-[15px] font-medium text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.06)] transition-colors"
              >
                <ArrowLeft className="w-4 h-4" /> Back
              </button>
            ) : (
              <div />
            )}

            {step < 4 ? (
              <button
                type="button"
                onClick={goNext}
                disabled={!canNext()}
                className="flex items-center gap-2 px-6 py-2.5 rounded-[12px] text-[15px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-40 transition-all hover:brightness-110"
              >
                Continue <ArrowRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={() => finishMutation.mutate()}
                disabled={finishMutation.isPending}
                className="flex items-center gap-2 px-6 py-2.5 rounded-[12px] text-[15px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-40 transition-all hover:brightness-110"
              >
                {finishMutation.isPending ? "Saving..." : "Start chatting"}{" "}
                <MessageSquare className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Skip onboarding — quietly available for users who hit it by mistake. */}
          {step < 4 && (
            <div className="mt-6 text-center">
              <button
                type="button"
                onClick={() => skipMutation.mutate()}
                disabled={skipMutation.isPending}
                className="text-[12px] text-[var(--text-muted)] hover:text-[var(--text-secondary)] underline underline-offset-2 transition-colors disabled:opacity-50"
              >
                {skipMutation.isPending ? "Skipping..." : "Skip onboarding"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
