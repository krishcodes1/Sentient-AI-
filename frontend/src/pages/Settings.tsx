import { useState } from "react";
import { Save, AlertTriangle, Trash2 } from "lucide-react";

export default function Settings() {
  const [email, setEmail] = useState("krishshroff91@gmail.com");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [permissionTier, setPermissionTier] = useState("supervised");
  const [rateLimit, setRateLimit] = useState(60);
  const [llmProvider, setLlmProvider] = useState("anthropic");
  const [llmModel, setLlmModel] = useState("claude-sonnet-4-20250514");

  const models: Record<string, string[]> = {
    anthropic: ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-4-5-20251001"],
    openai: ["gpt-4o", "gpt-4o-mini", "o1-preview"],
    ollama: ["llama3.2", "mistral", "codellama", "mixtral"],
  };

  const inputStyle = {
    backgroundColor: "var(--bg-input)",
    borderColor: "var(--border-primary)",
    color: "var(--text-primary)",
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>
          Settings
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Configure your account, security policies, and LLM provider
        </p>
      </div>

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
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none"
              style={inputStyle}
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
                className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none"
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
                className="w-full px-4 py-2.5 rounded-lg border text-sm outline-none"
                style={inputStyle}
                placeholder="Min. 8 characters"
              />
            </div>
          </div>
          <button
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: "var(--accent-primary)" }}
          >
            <Save className="w-4 h-4" /> Save Profile
          </button>
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
              <option value="open">Open - Auto-approve most actions</option>
              <option value="supervised">Supervised - Confirm write actions</option>
              <option value="restricted">Restricted - Confirm all actions</option>
              <option value="locked">Locked - Admin approval required</option>
            </select>
            <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
              Financial transactions are always blocked regardless of this setting.
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
          <button
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: "var(--accent-primary)" }}
          >
            <Save className="w-4 h-4" /> Save Security Settings
          </button>
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
            <div className="grid grid-cols-3 gap-3">
              {(["anthropic", "openai", "ollama"] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => {
                    setLlmProvider(p);
                    setLlmModel(models[p][0]);
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
              {models[llmProvider].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>
          <button
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: "var(--accent-primary)" }}
          >
            <Save className="w-4 h-4" /> Save LLM Settings
          </button>
        </div>
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
          These actions are irreversible. Proceed with caution.
        </p>
        <div className="flex gap-3">
          <button
            className="flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium"
            style={{ borderColor: "var(--accent-danger)", color: "var(--accent-danger)" }}
          >
            <Trash2 className="w-4 h-4" /> Reset All Connectors
          </button>
          <button
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ backgroundColor: "var(--accent-danger)" }}
          >
            <Trash2 className="w-4 h-4" /> Delete Account
          </button>
        </div>
      </section>
    </div>
  );
}
