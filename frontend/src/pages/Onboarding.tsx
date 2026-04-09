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
import { updateSettings } from "@/services/api";

const PROVIDERS = [
  { id: "openai", name: "OpenAI", models: ["gpt-4o", "gpt-4o-mini", "o1-preview", "o1"], desc: "GPT-4o and beyond" },
  { id: "anthropic", name: "Anthropic", models: ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-4-5-20251001"], desc: "Claude models" },
  { id: "gemini", name: "Google Gemini", models: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"], desc: "Gemini multimodal" },
  { id: "grok", name: "xAI Grok", models: ["grok-3", "grok-3-mini"], desc: "Grok reasoning" },
  { id: "deepseek", name: "Deepseek", models: ["deepseek-chat", "deepseek-reasoner"], desc: "Cost-effective AI" },
  { id: "groq", name: "Groq", models: ["llama-3.3-70b-versatile", "mixtral-8x7b-32768"], desc: "Ultra-fast inference" },
  { id: "mistral", name: "Mistral", models: ["mistral-large-latest", "mistral-small-latest"], desc: "European AI" },
  { id: "ollama", name: "Ollama", models: ["llama3.2", "mistral", "codellama", "mixtral"], desc: "Local / self-hosted" },
] as const;

type ProviderId = (typeof PROVIDERS)[number]["id"];

const STEPS = [
  { icon: Sparkles, label: "Welcome" },
  { icon: Brain, label: "Provider" },
  { icon: Key, label: "API Key" },
  { icon: Server, label: "Model" },
  { icon: MessageSquare, label: "Ready" },
];

export default function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<ProviderId>("openai");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("gpt-4o");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const selectedProvider = PROVIDERS.find((p) => p.id === provider)!;

  const canNext = () => {
    if (step === 0) return name.trim().length >= 1;
    if (step === 1) return true;
    if (step === 2) return provider === "ollama" || apiKey.trim().length > 0;
    if (step === 3) return model.length > 0;
    return true;
  };

  const handleFinish = async () => {
    setSaving(true);
    setError("");
    try {
      await updateSettings({
        name: name.trim(),
        llm_provider: provider,
        llm_model: model,
        llm_api_key: provider === "ollama" ? "ollama" : apiKey.trim(),
        onboarding_completed: true,
      });
      navigate("/gateway");
    } catch (err: any) {
      setError(err.message || "Failed to save settings");
    } finally {
      setSaving(false);
    }
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
                  Let's get you set up. First, what should we call you?
                </p>
              </div>
              <div>
                <label className="block text-[13px] font-medium text-[var(--text-secondary)] mb-2">
                  Your name
                </label>
                <input
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
              <div className="grid grid-cols-2 gap-3">
                {PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => {
                      setProvider(p.id);
                      setModel(p.models[0]);
                    }}
                    className="text-left px-4 py-3.5 rounded-[14px] border transition-all duration-200"
                    style={{
                      backgroundColor: provider === p.id ? "rgba(10,132,255,0.14)" : "var(--bg-tertiary)",
                      borderColor: provider === p.id ? "var(--accent-primary)" : "var(--border-subtle)",
                    }}
                  >
                    <span
                      className="text-[15px] font-medium block"
                      style={{
                        color: provider === p.id ? "var(--text-primary)" : "var(--text-secondary)",
                      }}
                    >
                      {p.name}
                    </span>
                    <span className="text-[12px] block mt-0.5 text-[var(--text-muted)]">
                      {p.desc}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 2: API Key */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="text-center space-y-2">
                <h2 className="text-[24px] font-semibold tracking-tight text-[var(--text-primary)]">
                  {provider === "ollama" ? "Ollama connection" : `Enter your ${selectedProvider.name} API key`}
                </h2>
                <p className="text-[15px] text-[var(--text-secondary)] leading-relaxed max-w-sm mx-auto">
                  {provider === "ollama"
                    ? "Make sure Ollama is running locally on port 11434."
                    : "Your API key is encrypted and stored securely. It never leaves the server."}
                </p>
              </div>
              {provider !== "ollama" && (
                <div>
                  <label className="block text-[13px] font-medium text-[var(--text-secondary)] mb-2">
                    API Key
                  </label>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={`sk-...`}
                    autoFocus
                    className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors font-mono"
                  />
                </div>
              )}
              {provider === "ollama" && (
                <div className="rounded-[14px] border border-[var(--border-subtle)] bg-[var(--bg-tertiary)] p-5 text-center">
                  <Server className="w-10 h-10 text-[var(--accent-primary)] mx-auto mb-3" strokeWidth={1.5} />
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
              <div className="flex flex-col gap-2">
                {selectedProvider.models.map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setModel(m)}
                    className="text-left px-4 py-3.5 rounded-[14px] border transition-all duration-200 flex items-center justify-between"
                    style={{
                      backgroundColor: model === m ? "rgba(10,132,255,0.14)" : "var(--bg-tertiary)",
                      borderColor: model === m ? "var(--accent-primary)" : "var(--border-subtle)",
                    }}
                  >
                    <span
                      className="text-[15px] font-mono"
                      style={{
                        color: model === m ? "var(--text-primary)" : "var(--text-secondary)",
                      }}
                    >
                      {m}
                    </span>
                    {model === m && <Check className="w-5 h-5 text-[var(--accent-primary)]" strokeWidth={2.5} />}
                  </button>
                ))}
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
                  SentientAI is configured with <strong className="text-[var(--text-primary)]">{selectedProvider.name}</strong> using{" "}
                  <code className="text-[var(--accent-primary)]">{model}</code>.
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

          {/* Error */}
          {error && (
            <div className="mt-4 p-3 rounded-[10px] text-[13px] bg-[rgba(255,69,58,0.12)] text-[var(--accent-danger)] border border-[rgba(255,69,58,0.25)]">
              {error}
            </div>
          )}

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
                onClick={() => setStep(step + 1)}
                disabled={!canNext()}
                className="flex items-center gap-2 px-6 py-2.5 rounded-[12px] text-[15px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-40 transition-all hover:brightness-110"
              >
                Continue <ArrowRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={handleFinish}
                disabled={saving}
                className="flex items-center gap-2 px-6 py-2.5 rounded-[12px] text-[15px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-40 transition-all hover:brightness-110"
              >
                {saving ? "Saving..." : "Start chatting"} <MessageSquare className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
