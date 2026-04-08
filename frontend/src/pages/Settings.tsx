import { useState, useEffect } from "react";
import { Save, AlertTriangle, Trash2, Check, Loader2 } from "lucide-react";
import { getMe, updateSettings, logout } from "@/services/api";
import type { User } from "@/types";

const models: Record<string, string[]> = {
  anthropic: ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-4-5-20251001"],
  openai: ["gpt-4o", "gpt-4o-mini", "o1-preview", "o1"],
  gemini: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
  grok: ["grok-3", "grok-3-mini"],
  deepseek: ["deepseek-chat", "deepseek-reasoner"],
  groq: ["llama-3.3-70b-versatile", "mixtral-8x7b-32768"],
  mistral: ["mistral-large-latest", "mistral-small-latest"],
  ollama: ["llama3.2", "mistral", "codellama", "mixtral"],
};

const PROVIDERS = ["anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"] as const;

export default function Settings() {
  const [user, setUser] = useState<User | null>(null);
  const [name, setName] = useState("");
  const [llmProvider, setLlmProvider] = useState("openai");
  const [llmModel, setLlmModel] = useState("gpt-4o");
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    getMe().then((u) => {
      setUser(u);
      setName(u.name || "");
      setLlmProvider(u.llm_provider);
      setLlmModel(u.llm_model);
    }).catch(() => {});
  }, []);

  const handleSaveProfile = async () => {
    setSaving("profile");
    setSuccess("");
    try {
      const updated = await updateSettings({ name: name.trim() });
      setUser(updated);
      setSuccess("Profile saved");
    } catch {}
    setSaving("");
  };

  const handleSaveLLM = async () => {
    setSaving("llm");
    setSuccess("");
    try {
      const data: Record<string, string> = { llm_provider: llmProvider, llm_model: llmModel };
      if (apiKey.trim()) data.llm_api_key = apiKey.trim();
      const updated = await updateSettings(data);
      setUser(updated);
      setApiKey("");
      setSuccess("LLM settings saved");
    } catch {}
    setSaving("");
  };

  const inputClass = "w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors";

  return (
    <div className="space-y-8 max-w-3xl min-w-0">
      <header>
        <h1 className="text-[28px] font-semibold tracking-tight text-[var(--text-primary)] md:text-[32px]">
          Settings
        </h1>
        <p className="text-[15px] text-[var(--text-secondary)] mt-1 leading-relaxed">
          Configure your account and LLM provider.
        </p>
      </header>

      {success && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-[12px] bg-[rgba(48,209,88,0.12)] border border-[rgba(48,209,88,0.25)] text-[14px] text-[var(--accent-success)]">
          <Check className="w-4 h-4" strokeWidth={2.5} /> {success}
        </div>
      )}

      {/* Profile */}
      <section
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)] mb-5">
          Profile
        </h2>
        <div className="space-y-4">
          <div>
            <label className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">Name</label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="Your name" />
          </div>
          <div>
            <label className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">Email</label>
            <input type="email" value={user?.email || ""} disabled className={inputClass + " opacity-60 cursor-not-allowed"} />
          </div>
          <button
            type="button"
            onClick={handleSaveProfile}
            disabled={saving === "profile"}
            className="flex items-center gap-2 px-5 py-2.5 rounded-[12px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-50 hover:brightness-110 transition-all"
          >
            {saving === "profile" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Save Profile
          </button>
        </div>
      </section>

      {/* LLM Provider */}
      <section
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)] mb-5">
          LLM Provider
        </h2>
        <div className="space-y-5">
          <div>
            <label className="block text-[13px] font-medium mb-3 text-[var(--text-secondary)]">Provider</label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {PROVIDERS.map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => {
                    setLlmProvider(p);
                    setLlmModel(models[p][0]);
                  }}
                  className="px-4 py-3 rounded-[12px] border text-[14px] font-medium capitalize transition-all"
                  style={{
                    backgroundColor: llmProvider === p ? "rgba(10,132,255,0.14)" : "var(--bg-tertiary)",
                    borderColor: llmProvider === p ? "var(--accent-primary)" : "var(--border-subtle)",
                    color: llmProvider === p ? "var(--text-primary)" : "var(--text-secondary)",
                  }}
                >
                  {p}
                  {p === "ollama" && (
                    <span className="block text-[11px] mt-0.5 text-[var(--text-muted)]">Local</span>
                  )}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">Model</label>
            <select
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              className={inputClass}
            >
              {(models[llmProvider] || []).map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>

          {llmProvider !== "ollama" && (
            <div>
              <label className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">
                API Key <span className="text-[var(--text-muted)]">(leave empty to keep current)</span>
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className={inputClass + " font-mono"}
                placeholder="sk-..."
              />
            </div>
          )}

          <button
            type="button"
            onClick={handleSaveLLM}
            disabled={saving === "llm"}
            className="flex items-center gap-2 px-5 py-2.5 rounded-[12px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-50 hover:brightness-110 transition-all"
          >
            {saving === "llm" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Save LLM Settings
          </button>
        </div>
      </section>

      {/* Danger Zone */}
      <section
        className="rounded-[var(--radius-xl)] border border-[rgba(255,69,58,0.35)] p-6 md:p-7"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <h2 className="text-[20px] font-semibold tracking-tight text-[var(--accent-danger)] mb-1 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5" strokeWidth={2} /> Danger Zone
        </h2>
        <p className="text-[14px] text-[var(--text-muted)] mb-5">
          These actions are irreversible. Proceed with caution.
        </p>
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            className="flex items-center gap-2 px-4 py-2.5 rounded-[12px] border border-[var(--accent-danger)] text-[14px] font-medium text-[var(--accent-danger)] hover:bg-[rgba(255,69,58,0.08)] transition-colors"
          >
            <Trash2 className="w-4 h-4" /> Reset All Connectors
          </button>
          <button
            type="button"
            onClick={logout}
            className="flex items-center gap-2 px-4 py-2.5 rounded-[12px] text-[14px] font-medium text-white bg-[var(--accent-danger)] hover:brightness-110 transition-all"
          >
            <Trash2 className="w-4 h-4" /> Sign Out
          </button>
        </div>
      </section>
    </div>
  );
}
