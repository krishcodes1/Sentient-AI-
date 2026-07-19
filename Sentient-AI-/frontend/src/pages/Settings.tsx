import { useEffect, useState } from "react";
import { Save, AlertTriangle, Trash2, Loader2, CheckCircle2, XCircle } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import type { User } from "@/types";
import {
  changePassword,
  deleteAccount,
  getMe,
  logout,
  updateProfile,
  updateSettings,
} from "@/services/api";

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

const panelStyle = {
  background: "var(--claw-panel)",
  border: "1px solid var(--claw-border)",
  boxShadow: "var(--shadow-card)",
};

const inputStyle = {
  background: "var(--bg-input)",
  border: "1px solid var(--claw-border)",
  color: "var(--text-primary)",
};

type Feedback = { ok: boolean; text: string } | null;

function FeedbackLine({ feedback }: { feedback: Feedback }) {
  if (!feedback) return null;
  const color = feedback.ok ? "var(--accent-success)" : "var(--accent-danger)";
  const Icon = feedback.ok ? CheckCircle2 : XCircle;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" style={{ color }}>
      <Icon className="w-3.5 h-3.5" />
      {feedback.text}
    </span>
  );
}

function SaveButton({
  label,
  onClick,
  saving,
}: {
  label: string;
  onClick: () => void;
  saving: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={saving}
      className="flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
      style={{ background: "var(--accent-primary)", color: "#0a0a0b" }}
    >
      {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
      {label}
    </button>
  );
}

export default function Settings() {
  const [, setMe] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Editable fields
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [permissionTier, setPermissionTier] = useState("user_confirm");
  const [rateLimit, setRateLimit] = useState(60);
  const [llmProvider, setLlmProvider] = useState("anthropic");
  const [llmModel, setLlmModel] = useState("claude-sonnet-4-20250514");

  // Per-section saving + feedback
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [savingSecurity, setSavingSecurity] = useState(false);
  const [savingLlm, setSavingLlm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);
  const [profileFeedback, setProfileFeedback] = useState<Feedback>(null);
  const [passwordFeedback, setPasswordFeedback] = useState<Feedback>(null);
  const [securityFeedback, setSecurityFeedback] = useState<Feedback>(null);
  const [llmFeedback, setLlmFeedback] = useState<Feedback>(null);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((u) => {
        if (cancelled) return;
        setMe(u);
        setName(u.name ?? "");
        setEmail(u.email ?? "");
        if (u.default_permission_tier) setPermissionTier(u.default_permission_tier);
        if (typeof u.rate_limit === "number") setRateLimit(u.rate_limit);
        if (u.llm_provider) setLlmProvider(u.llm_provider);
        if (u.llm_model) setLlmModel(u.llm_model);
      })
      .catch((err: Error) => {
        if (!cancelled) setLoadError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSaveProfile = async () => {
    setSavingProfile(true);
    setProfileFeedback(null);
    try {
      const updated = await updateProfile({ name, email });
      setMe(updated);
      setProfileFeedback({ ok: true, text: "Profile saved" });
    } catch (err) {
      setProfileFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setSavingProfile(false);
    }
  };

  const handleChangePassword = async () => {
    if (!currentPassword || !newPassword) {
      setPasswordFeedback({ ok: false, text: "Both password fields are required" });
      return;
    }
    setSavingPassword(true);
    setPasswordFeedback(null);
    try {
      await changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setCurrentPassword("");
      setNewPassword("");
      setPasswordFeedback({ ok: true, text: "Password changed" });
    } catch (err) {
      setPasswordFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setSavingPassword(false);
    }
  };

  const handleSaveSecurity = async () => {
    setSavingSecurity(true);
    setSecurityFeedback(null);
    try {
      const updated = await updateSettings({
        default_permission_tier: permissionTier,
        rate_limit: rateLimit,
      });
      setMe(updated);
      setSecurityFeedback({ ok: true, text: "Security settings saved" });
    } catch (err) {
      setSecurityFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setSavingSecurity(false);
    }
  };

  const handleSaveLlm = async () => {
    setSavingLlm(true);
    setLlmFeedback(null);
    try {
      const updated = await updateSettings({
        llm_provider: llmProvider,
        llm_model: llmModel,
      });
      setMe(updated);
      setLlmFeedback({ ok: true, text: "LLM settings saved" });
    } catch (err) {
      setLlmFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setSavingLlm(false);
    }
  };

  const handleDeleteAccount = async () => {
    setDeleting(true);
    try {
      await deleteAccount();
      logout();
    } catch (err) {
      setDeleting(false);
      throw err; // ConfirmDialog surfaces the failure inline
    }
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <div className="eyebrow mb-2">Account</div>
        <h1 style={{ color: "var(--text-primary)" }}>Settings</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Configure your account, security policies, and LLM provider.
        </p>
      </div>

      {loadError && (
        <div
          className="rounded-[12px] p-4 text-sm"
          style={{
            background: "var(--fill-danger)",
            border: "1px solid var(--border-danger)",
            color: "var(--accent-danger)",
          }}
        >
          {loadError}
        </div>
      )}

      {/* Profile */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Profile</div>
        <h2 className="mb-4">Account details</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
              style={inputStyle}
              placeholder={loading ? "Loading..." : "Your name"}
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
              style={inputStyle}
              placeholder={loading ? "Loading..." : ""}
            />
          </div>
          <div className="flex items-center gap-3">
            <SaveButton label="Save Profile" onClick={handleSaveProfile} saving={savingProfile} />
            <FeedbackLine feedback={profileFeedback} />
          </div>
        </div>
      </section>

      {/* Password */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Security</div>
        <h2 className="mb-4">Change password</h2>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
                Current Password
              </label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
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
                className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
                style={inputStyle}
                placeholder="Min. 8 characters"
              />
            </div>
          </div>
          <div className="flex items-center gap-3">
            <SaveButton label="Change Password" onClick={handleChangePassword} saving={savingPassword} />
            <FeedbackLine feedback={passwordFeedback} />
          </div>
        </div>
      </section>

      {/* Security policy */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Policy</div>
        <h2 className="mb-4">Security settings</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Default Permission Tier
            </label>
            <select
              value={permissionTier}
              onChange={(e) => setPermissionTier(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
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
              max={600}
              className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none mono-num"
              style={inputStyle}
            />
          </div>
          <div className="flex items-center gap-3">
            <SaveButton label="Save Security Settings" onClick={handleSaveSecurity} saving={savingSecurity} />
            <FeedbackLine feedback={securityFeedback} />
          </div>
        </div>
      </section>

      {/* LLM Provider */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Runtime</div>
        <h2 className="mb-4">LLM provider</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Provider
            </label>
            <div className="grid grid-cols-4 gap-3">
              {(["anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"] as const).map((p) => {
                const isActive = llmProvider === p;
                return (
                  <button
                    key={p}
                    type="button"
                    onClick={() => {
                      setLlmProvider(p);
                      setLlmModel(LLM_MODELS[p][0]);
                    }}
                    className="px-4 py-3 rounded-[10px] text-sm font-medium capitalize transition-colors"
                    style={{
                      background: isActive ? "var(--accent-glow)" : "var(--claw-surface)",
                      border: isActive
                        ? "1px solid rgba(34,211,238,0.35)"
                        : "1px solid var(--claw-border)",
                      color: isActive ? "var(--accent-primary)" : "var(--text-secondary)",
                    }}
                  >
                    {p}
                    {p === "ollama" && (
                      <span className="block text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                        Local / Self-hosted
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: "var(--text-secondary)" }}>
              Model
            </label>
            <select
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
              style={inputStyle}
            >
              {LLM_MODELS[llmProvider].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
              Takes effect on your next message. The server must have this
              provider's API key configured in{" "}
              <code style={{ color: "var(--accent-primary)" }}>backend/.env</code>{" "}
              — if the key is missing, chat returns a clear error instead of
              silently falling back to another provider.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <SaveButton label="Save LLM Settings" onClick={handleSaveLlm} saving={savingLlm} />
            <FeedbackLine feedback={llmFeedback} />
          </div>
        </div>
      </section>

      {/* Account actions */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Session</div>
        <h2 className="mb-1">Sign out</h2>
        <p className="text-sm mb-4" style={{ color: "var(--text-muted)" }}>
          Sign out of this device. Your data is preserved on the server.
        </p>
        <button
          type="button"
          onClick={() => logout()}
          className="flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-medium"
          style={inputStyle}
        >
          Sign out
        </button>
      </section>

      {/* Danger Zone */}
      <section
        className="rounded-[14px] p-6"
        style={{
          background: "var(--claw-panel)",
          border: "1px solid var(--border-danger)",
          boxShadow: "var(--shadow-card)",
        }}
      >
        <div className="eyebrow mb-1" style={{ color: "var(--accent-danger)" }}>
          Danger zone
        </div>
        <h2 className="mb-1 flex items-center gap-2" style={{ color: "var(--accent-danger)" }}>
          <AlertTriangle className="w-5 h-5" /> Delete account
        </h2>
        <p className="text-sm mb-4" style={{ color: "var(--text-muted)" }}>
          Permanently delete your account and all associated conversations,
          connectors, and audit logs. This cannot be undone.
        </p>
        <button
          type="button"
          onClick={() => setConfirmDeleteOpen(true)}
          disabled={deleting}
          className="flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
          style={{ background: "var(--accent-danger)", color: "#0a0a0b" }}
        >
          {deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
          Delete Account
        </button>
      </section>

      <ConfirmDialog
        open={confirmDeleteOpen}
        danger
        title="Delete your account?"
        message="This permanently removes your account, conversations, connectors (including their encrypted credentials), pending approvals, and audit logs. This cannot be undone."
        confirmLabel="Delete everything"
        onCancel={() => setConfirmDeleteOpen(false)}
        onConfirm={handleDeleteAccount}
      />

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
