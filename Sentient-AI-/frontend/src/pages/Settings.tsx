import { useEffect, useState } from "react";
import { Save, AlertTriangle, Trash2, Info, Loader2 } from "lucide-react";
import type { User } from "@/types";
import { getMe, logout } from "@/services/api";

// Backend uses the canonical enum from the permission engine. Keeping
// these in sync with PermissionTier in backend/services/agent/permissions.py
// and the User model.
const PERMISSION_TIERS = [
  { value: "auto_approve", label: "Auto Approve", help: "Low-risk read actions run immediately." },
  { value: "user_confirm", label: "User Confirm", help: "Write actions require explicit approval." },
  { value: "admin_only", label: "Admin Only", help: "Only admins can authorize." },
  { value: "hard_blocked", label: "Hard Blocked", help: "Cannot be enabled by anyone." },
];

const LLM_MODELS: Record<string, string[]> = {
  anthropic: ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-4-5-20251001"],
  openai: ["gpt-4o", "gpt-4o-mini", "o1-preview", "o1"],
  gemini: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
  grok: ["grok-3", "grok-3-mini"],
  deepseek: ["deepseek-chat", "deepseek-reasoner"],
  groq: ["llama-3.3-70b-versatile", "mixtral-8x7b-32768"],
  mistral: ["mistral-large-latest", "mistral-small-latest"],
  ollama: ["llama3.2", "llama3.2:1b", "mistral", "codellama", "mixtral"],
};

export default function Settings() {
  const [me, setMe] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [permissionTier, setPermissionTier] = useState("user_confirm");
  const [rateLimit, setRateLimit] = useState(60);
  const [llmProvider, setLlmProvider] = useState("anthropic");
  const [llmModel, setLlmModel] = useState("claude-sonnet-4-20250514");

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((u) => {
        if (cancelled) return;
        setMe(u);
        // Seed editable fields from whatever the backend already knows
        // about the user (these fields may not exist yet; this is
        // defensive).
        const tier = (u as unknown as { default_permission_tier?: string })
          .default_permission_tier;
        if (tier) setPermissionTier(tier);
        const rl = (u as unknown as { rate_limit?: number }).rate_limit;
        if (typeof rl === "number") setRateLimit(rl);
        const prov = (u as unknown as { llm_provider?: string }).llm_provider;
        if (prov) setLlmProvider(prov);
        const model = (u as unknown as { llm_model?: string }).llm_model;
        if (model) setLlmModel(model);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const inputStyle = {
    backgroundColor: "var(--bg-input)",
    borderColor: "var(--border-primary)",
    color: "var(--text-primary)",
  };

  // Every Save button on this page targets a backend endpoint that
  // does not exist yet (see backend/api/routes/auth.py — only register,
  // login, me are implemented). Rather than wiring buttons to dead
  // routes, disable them with a clear tooltip until those endpoints
  // land.
  const disabledTooltip =
    "Saving settings is not yet supported by the backend (see /auth routes).";

  const DisabledSaveButton = ({ label }: { label: string }) => (
    <button
      type="button"
      disabled
      title={disabledTooltip}
      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white opacity-50 cursor-not-allowed"
      style={{ backgroundColor: "var(--accent-primary)" }}
    >
      <Save className="w-4 h-4" /> {label}
    </button>
  );

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>
          Settings
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Configure your account, security policies, and LLM provider.
        </p>
      </div>

      <div
        className="flex items-start gap-3 rounded-xl border p-4"
        style={{
          backgroundColor: "rgba(99,102,241,0.05)",
          borderColor: "rgba(99,102,241,0.25)",
        }}
      >
        <Info className="w-4 h-4 mt-0.5 shrink-0" style={{ color: "var(--accent-primary)" }} />
        <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
          Most fields below are read-only until the corresponding backend
          routes land. The data shown reflects what the server currently
          knows about your account.
        </p>
      </div>

      {error && (
        <div
          className="rounded-xl border p-4 text-sm"
          style={{
            backgroundColor: "rgba(239,68,68,0.05)",
            borderColor: "rgba(239,68,68,0.25)",
            color: "var(--accent-danger)",
          }}
        >
          {error}
        </div>
      )}

      {/* Profile */}
      <section
        className="rounded-xl border p-6"
        style={{ backgroundColor: "var(--bg-secondary)", borderColor: "var(--border-primary)" }}
      >
        <h2 className="text-lg font-semibold mb-4" style={{ color: "var(--text-primary)" }}>
          Profile
        </h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Name
            </label>
            <input
              type="text"
              value={loading ? "" : me?.name ?? ""}
              readOnly
              className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none opacity-80"
              style={inputStyle}
              placeholder={loading ? "Loading..." : "No name set"}
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Email
            </label>
            <input
              type="email"
              value={loading ? "" : me?.email ?? ""}
              readOnly
              className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none opacity-80"
              style={inputStyle}
              placeholder={loading ? "Loading..." : ""}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
                Current Password
              </label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                disabled
                className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                style={inputStyle}
                placeholder="Enter current password"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
                New Password
              </label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                disabled
                className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                style={inputStyle}
                placeholder="Min. 8 characters"
              />
            </div>
          </div>
          <DisabledSaveButton label="Save Profile" />
        </div>
      </section>

      {/* Security */}
      <section
        className="rounded-xl border p-6"
        style={{ backgroundColor: "var(--bg-secondary)", borderColor: "var(--border-primary)" }}
      >
        <h2 className="text-lg font-semibold mb-4" style={{ color: "var(--text-primary)" }}>
          Security Settings
        </h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Default Permission Tier
            </label>
            <select
              value={permissionTier}
              onChange={(e) => setPermissionTier(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none"
              style={inputStyle}
            >
              {PERMISSION_TIERS.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
            <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
              {PERMISSION_TIERS.find((t) => t.value === permissionTier)?.help}
              {" "}Hard-blocked scopes (like Robinhood trade execution) are
              enforced at the platform layer regardless of this setting.
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Rate Limit (requests/minute)
            </label>
            <input
              type="number"
              value={rateLimit}
              onChange={(e) => setRateLimit(Number(e.target.value))}
              min={10}
              max={200}
              className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none"
              style={inputStyle}
            />
          </div>
          <DisabledSaveButton label="Save Security Settings" />
        </div>
      </section>

      {/* LLM Provider */}
      <section
        className="rounded-xl border p-6"
        style={{ backgroundColor: "var(--bg-secondary)", borderColor: "var(--border-primary)" }}
      >
        <h2 className="text-lg font-semibold mb-4" style={{ color: "var(--text-primary)" }}>
          LLM Provider
        </h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Provider
            </label>
            <div className="grid grid-cols-4 gap-3">
              {(["anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"] as const).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => {
                    setLlmProvider(p);
                    setLlmModel(LLM_MODELS[p][0]);
                  }}
                  className="px-4 py-3 rounded-lg border text-sm font-medium capitalize transition-colors"
                  style={{
                    backgroundColor: llmProvider === p ? "rgba(99,102,241,0.15)" : "var(--bg-input)",
                    borderColor: llmProvider === p ? "var(--accent-primary)" : "var(--border-primary)",
                    color: llmProvider === p ? "var(--accent-primary)" : "var(--text-secondary)",
                  }}
                >
                  {p}
                  {p === "ollama" && (
                    <span className="block text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                      Local / Self-hosted
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Model
            </label>
            <select
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none"
              style={inputStyle}
            >
              {LLM_MODELS[llmProvider].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
              Active provider is configured at server startup via{" "}
              <code style={{ color: "var(--accent-primary)" }}>LLM_PROVIDER</code> and{" "}
              <code style={{ color: "var(--accent-primary)" }}>LLM_MODEL</code> in{" "}
              <code style={{ color: "var(--accent-primary)" }}>backend/.env</code>.
            </p>
          </div>
          <DisabledSaveButton label="Save LLM Settings" />
        </div>
      </section>

      {/* Account actions */}
      <section
        className="rounded-xl border p-6"
        style={{
          backgroundColor: "var(--bg-secondary)",
          borderColor: "var(--border-primary)",
        }}
      >
        <h2 className="text-lg font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
          Account
        </h2>
        <p className="text-sm mb-4" style={{ color: "var(--text-muted)" }}>
          Sign out of this device. Your data is preserved on the server.
        </p>
        <button
          type="button"
          onClick={() => logout()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium"
          style={{
            borderColor: "var(--border-primary)",
            color: "var(--text-primary)",
          }}
        >
          Sign out
        </button>
      </section>

      {/* Danger Zone */}
      <section
        className="rounded-xl border p-6"
        style={{
          backgroundColor: "var(--bg-secondary)",
          borderColor: "rgba(239,68,68,0.3)",
        }}
      >
        <h2 className="text-lg font-semibold mb-1 flex items-center gap-2" style={{ color: "var(--accent-danger)" }}>
          <AlertTriangle className="w-5 h-5" /> Danger Zone
        </h2>
        <p className="text-sm mb-4" style={{ color: "var(--text-muted)" }}>
          Account deletion requires a backend route that has not been
          implemented yet. The button below is disabled to prevent calls
          that would return a 404.
        </p>
        <button
          type="button"
          disabled
          title="Account deletion is not yet supported by the backend."
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white opacity-50 cursor-not-allowed"
          style={{ backgroundColor: "var(--accent-danger)" }}
        >
          <Trash2 className="w-4 h-4" /> Delete Account
        </button>
      </section>

      {loading && (
        <div
          className="flex items-center gap-2 text-xs"
          style={{ color: "var(--text-muted)" }}
        >
          <Loader2 className="w-3 h-3 animate-spin" />
          Loading account...
        </div>
      )}
    </div>
  );
}
