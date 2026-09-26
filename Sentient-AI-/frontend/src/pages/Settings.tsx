/**
 * Settings page: profile, password, permission tier and rate limit, LLM provider choice, Telegram
 * linking and bot token, capability permissions, data export and account deletion, plus the
 * owner's Server section.
 *
 * Why it exists: Every per-account setting the backend exposes is edited here, each section saving
 * and reporting on its own.
 */

import { useEffect, useId, useState } from "react";
import {
  Save,
  AlertTriangle,
  Trash2,
  Loader2,
  CheckCircle2,
  XCircle,
  Download,
  Send,
} from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import AppApprovals from "@/components/AppApprovals";
import CapabilityList, { CapabilityListError } from "@/components/CapabilityList";
import PaymentCardSettings from "@/components/PaymentCardSettings";
import ServerSettings from "@/components/ServerSettings";
import type { CapabilityStatus, User } from "@/types";
import {
  ApiError,
  changePassword,
  createTelegramLink,
  deleteAccount,
  exportAccount,
  getCapabilities,
  getMe,
  getTelegramStatus,
  installCapability,
  login,
  logout,
  removeTelegramToken,
  requestCapabilityAccess,
  saveTelegram,
  testTelegram,
  unlinkTelegram,
  updateCapabilities,
  updateCapabilitySettings,
  updateProfile,
  updateSettings,
  type TelegramLink,
  type TelegramStatus,
} from "@/services/api";

// Backend uses the canonical enum from the permission engine. Keeping
// these in sync with PermissionTier in backend/services/agent/permissions.py
// and the User model.
const PERMISSION_TIERS = [
  { value: "auto_approve", label: "Auto Approve", help: "Low-risk read actions run immediately." },
  { value: "user_confirm", label: "User Confirm", help: "Write actions require explicit approval." },
  {
    value: "admin_only",
    label: "Admin Only",
    help: "Usable only by this deployment's admin (the first account registered).",
  },
  { value: "hard_blocked", label: "Hard Blocked", help: "Cannot be enabled by anyone." },
];

// Current model ids per provider, checked 2026-09-23. Offering a retired id
// here means a user can save a model the provider rejects on every turn.
// Keep in step with backend/services/usage/pricing.py so what can be
// picked can also be priced.
const LLM_MODELS: Record<string, string[]> = {
  anthropic: ["claude-sonnet-5", "claude-opus-5-5", "claude-haiku-4-5"],
  openai: ["gpt-5.4-nano", "gpt-5-mini", "gpt-6-luna"],
  gemini: ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-3.7-flash", "gemini-3.8-flash"],
  grok: ["grok-4.3"],
  deepseek: ["deepseek-flash"],
  groq: ["openai/gpt-oss-120b"],
  mistral: ["mistral-large-latest", "mistral-small-latest"],
  ollama: ["llama3.2", "llama3.2:1b", "mistral", "codellama", "mixtral"],
};

// The provider radio group. `null` comes first and is what every account
// starts on: follow the owner's setup, including any provider they switch
// to later. Picking a provider pins the account to it.
const PROVIDER_CHOICES: { value: string | null; label: string; hint?: string }[] = [
  { value: null, label: "Use this Crawler's default", hint: "Whatever the owner set up" },
  ...["anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral"].map((p) => ({
    value: p,
    label: p,
  })),
  { value: "ollama", label: "ollama", hint: "Local / Self-hosted" },
];

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

const labelCls = "block text-sm font-medium mb-1.5 text-[var(--text-secondary)]";

type Feedback = { ok: boolean; text: string } | null;

function FeedbackLine({ feedback }: { feedback: Feedback }) {
  if (!feedback) return null;
  const color = feedback.ok ? "var(--accent-success)" : "var(--accent-danger)";
  const Icon = feedback.ok ? CheckCircle2 : XCircle;
  return (
    // Saving is asynchronous and the only signal that it worked; without a
    // live region the outcome lands silently for anyone not watching this
    // corner of the form.
    <span
      role="status"
      className="inline-flex items-center gap-1.5 text-xs"
      style={{ color }}
    >
      <Icon className="w-3.5 h-3.5" aria-hidden />
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
      className="flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50"
      style={{
        minHeight: 44,
        background: "var(--accent-primary)",
        color: "var(--text-on-accent)",
      }}
    >
      {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
      {label}
    </button>
  );
}

export default function Settings() {
  const ids = {
    name: useId(),
    email: useId(),
    currentPassword: useId(),
    newPassword: useId(),
    tier: useId(),
    tierHelp: useId(),
    rateLimit: useId(),
    provider: useId(),
    model: useId(),
    modelHelp: useId(),
    deletePassword: useId(),
  };
  const [me, setMe] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // The account's saved email (as opposed to the editable form field):
  // needed to re-authenticate after a password change revokes every token.
  const [accountEmail, setAccountEmail] = useState("");

  // Editable fields
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [permissionTier, setPermissionTier] = useState("user_confirm");
  const [rateLimit, setRateLimit] = useState(60);
  // null = "Use this Crawler's default": the account follows whatever
  // provider/model the owner set up, now and after any later change.
  const [llmProvider, setLlmProvider] = useState<string | null>(null);
  const [llmModel, setLlmModel] = useState("");

  // Per-section saving + feedback
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [savingSecurity, setSavingSecurity] = useState(false);
  const [savingLlm, setSavingLlm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);
  const [deletePassword, setDeletePassword] = useState("");
  const [profileFeedback, setProfileFeedback] = useState<Feedback>(null);
  const [passwordFeedback, setPasswordFeedback] = useState<Feedback>(null);
  const [securityFeedback, setSecurityFeedback] = useState<Feedback>(null);
  const [llmFeedback, setLlmFeedback] = useState<Feedback>(null);
  const [exporting, setExporting] = useState(false);
  const [exportFeedback, setExportFeedback] = useState<Feedback>(null);

  // Telegram approvals
  const [tgStatus, setTgStatus] = useState<TelegramStatus | null>(null);
  const [tgLink, setTgLink] = useState<TelegramLink | null>(null);
  const [tgBusy, setTgBusy] = useState(false);
  const [tgFeedback, setTgFeedback] = useState<Feedback>(null);

  // Telegram bot token (admin only): the setup wizard's own token step,
  // repeated here so an owner can rotate or add it without re-running
  // setup. Env-managed (TELEGRAM_BOT_TOKEN) always wins server-side; a 409
  // from test/save is how that surfaces, since there is no status field
  // for it the way SetupProvider.key_from_env exists for LLM keys.
  const [tgToken, setTgToken] = useState("");
  const [tgTokenBusy, setTgTokenBusy] = useState<"test" | "save" | "remove" | null>(null);
  const [tgTokenFeedback, setTgTokenFeedback] = useState<Feedback>(null);
  const [tgTokenEnvManaged, setTgTokenEnvManaged] = useState(false);

  // Permissions (capabilities)
  const [capabilities, setCapabilities] = useState<CapabilityStatus[] | null>(null);
  const [capabilitiesBusyKey, setCapabilitiesBusyKey] = useState<string | null>(null);
  const [capabilitiesFeedback, setCapabilitiesFeedback] = useState<Feedback>(null);
  const [capabilitiesLoadError, setCapabilitiesLoadError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((u) => {
        if (cancelled) return;
        setMe(u);
        setName(u.name ?? "");
        setEmail(u.email ?? "");
        setAccountEmail(u.email ?? "");
        if (u.default_permission_tier) setPermissionTier(u.default_permission_tier);
        if (typeof u.rate_limit === "number") setRateLimit(u.rate_limit);
        setLlmProvider(u.llm_provider || null);
        setLlmModel(u.llm_provider ? (u.llm_model ?? "") : "");
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
      // The change revokes every outstanding token (token_epoch bump), so
      // without re-authenticating the very next API call — a poll, a
      // navigation — hard-logs the user out with no explanation.
      try {
        await login({ email: accountEmail, password: newPassword });
        setPasswordFeedback({ ok: true, text: "Password changed" });
      } catch {
        setPasswordFeedback({
          ok: true,
          text: "Password changed — please sign in again with the new password",
        });
      }
      setCurrentPassword("");
      setNewPassword("");
    } catch (err) {
      setPasswordFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setSavingPassword(false);
    }
  };

  // Load Telegram status once; while a connect link is outstanding, poll
  // every 3s so the page flips to "connected" the moment the user taps
  // /start on their phone.
  useEffect(() => {
    let cancelled = false;
    getTelegramStatus()
      .then((s) => {
        if (!cancelled) setTgStatus(s);
      })
      .catch(() => {
        /* section renders the not-configured state */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!tgLink || tgStatus?.linked) return;
    const id = window.setInterval(() => {
      getTelegramStatus()
        .then((s) => {
          setTgStatus(s);
          if (s.linked) {
            setTgLink(null);
            setTgFeedback({ ok: true, text: "Telegram connected" });
          }
        })
        .catch(() => {});
    }, 3000);
    return () => window.clearInterval(id);
  }, [tgLink, tgStatus?.linked]);

  const handleTgConnect = async () => {
    setTgBusy(true);
    setTgFeedback(null);
    try {
      const link = await createTelegramLink();
      setTgLink(link);
      window.open(link.link_url, "_blank", "noopener");
    } catch (err) {
      setTgFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setTgBusy(false);
    }
  };

  const handleTgDisconnect = async () => {
    setTgBusy(true);
    setTgFeedback(null);
    try {
      await unlinkTelegram();
      setTgLink(null);
      setTgStatus((s) => (s ? { ...s, linked: false } : s));
      setTgFeedback({ ok: true, text: "Disconnected" });
    } catch (err) {
      setTgFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setTgBusy(false);
    }
  };

  /** A 409 here always means the same thing: TELEGRAM_BOT_TOKEN in the
   * server's .env provides the token, so the stored one this form would
   * write is never used. Surface that and stop offering to overwrite it. */
  const reportTgTokenError = (err: unknown) => {
    if (err instanceof ApiError && err.status === 409) setTgTokenEnvManaged(true);
    setTgTokenFeedback({ ok: false, text: (err as Error).message });
  };

  const handleTgTokenTest = async () => {
    setTgTokenBusy("test");
    setTgTokenFeedback(null);
    try {
      const r = await testTelegram(tgToken.trim());
      setTgTokenFeedback(
        r.ok
          ? { ok: true, text: `The token works — your bot is @${r.bot_username}.` }
          : { ok: false, text: r.error || "Telegram rejected that token." },
      );
    } catch (err) {
      reportTgTokenError(err);
    } finally {
      setTgTokenBusy(null);
    }
  };

  const handleTgTokenSave = async () => {
    setTgTokenBusy("save");
    setTgTokenFeedback(null);
    try {
      const r = await saveTelegram(tgToken.trim());
      setTgToken("");
      setTgTokenFeedback(
        r.running
          ? { ok: true, text: `Saved. Crawler now answers as @${r.bot_username}.` }
          : { ok: false, text: "Saved. The bot could not start yet — check the token or try again." },
      );
      setTgStatus(await getTelegramStatus());
    } catch (err) {
      reportTgTokenError(err);
    } finally {
      setTgTokenBusy(null);
    }
  };

  const handleTgTokenRemove = async () => {
    setTgTokenBusy("remove");
    setTgTokenFeedback(null);
    try {
      await removeTelegramToken();
      setTgTokenFeedback({ ok: true, text: "Bot token removed." });
      setTgStatus(await getTelegramStatus());
    } catch (err) {
      setTgTokenFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setTgTokenBusy(null);
    }
  };

  // Load the capability list once; every account can see it (read-only for
  // a non-admin), so this does not wait on `me` — the section itself gates
  // editability once `me` resolves.
  useEffect(() => {
    let cancelled = false;
    getCapabilities()
      .then((caps) => {
        if (!cancelled) {
          setCapabilities(caps);
          setCapabilitiesLoadError(null);
        }
      })
      .catch((err: Error) => {
        if (!cancelled) setCapabilitiesLoadError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleRetryLoadCapabilities = () => {
    setCapabilitiesLoadError(null);
    getCapabilities()
      .then((caps) => {
        setCapabilities(caps);
        setCapabilitiesLoadError(null);
      })
      .catch((err: Error) => setCapabilitiesLoadError(err.message));
  };

  const handleToggleCapability = async (key: string, enabled: boolean) => {
    setCapabilitiesBusyKey(key);
    setCapabilitiesFeedback(null);
    try {
      const updated = await updateCapabilities({ [key]: enabled });
      setCapabilities(updated);
    } catch (err) {
      setCapabilitiesFeedback({ ok: false, text: (err as Error).message });
    } finally {
      // Only clear the busy flag if it still points at this request — an
      // earlier, slower request finishing after a newer one started must
      // not un-busy the newer one.
      setCapabilitiesBusyKey((k) => (k === key ? null : k));
    }
  };

  const handleRequestCapabilityAccess = async (key: string) => {
    setCapabilitiesBusyKey(key);
    setCapabilitiesFeedback(null);
    try {
      const status = await requestCapabilityAccess(key);
      setCapabilities((prev) =>
        prev ? prev.map((c) => (c.key === key ? status : c)) : prev
      );
    } catch (err) {
      setCapabilitiesFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setCapabilitiesBusyKey((k) => (k === key ? null : k));
    }
  };

  // One changed field of a capability's settings (a purchase cap). The
  // server answers with the whole list, so a refused value simply shows the
  // stored one again once the row is no longer busy.
  const handleCapabilitySettingsChange = async (key: string, patch: Record<string, number>) => {
    setCapabilitiesBusyKey(key);
    setCapabilitiesFeedback(null);
    try {
      const updated = await updateCapabilitySettings(key, patch);
      setCapabilities(updated);
    } catch (err) {
      setCapabilitiesFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setCapabilitiesBusyKey((k) => (k === key ? null : k));
    }
  };

  const handleInstallCapability = async (key: string) => {
    setCapabilitiesBusyKey(key);
    setCapabilitiesFeedback(null);
    try {
      const result = await installCapability(key);
      if (!result.ok && result.error) {
        setCapabilitiesFeedback({ ok: false, text: result.error });
      }
      const refreshed = await getCapabilities();
      setCapabilities(refreshed);
    } catch (err) {
      setCapabilitiesFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setCapabilitiesBusyKey((k) => (k === key ? null : k));
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
      const updated = await updateSettings(
        llmProvider === null
          ? { llm_provider: null, llm_model: null }
          : { llm_provider: llmProvider, llm_model: llmModel },
      );
      setMe(updated);
      setLlmProvider(updated.llm_provider || null);
      setLlmModel(updated.llm_provider ? (updated.llm_model ?? "") : "");
      setLlmFeedback({ ok: true, text: "LLM settings saved" });
    } catch (err) {
      setLlmFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setSavingLlm(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    setExportFeedback(null);
    try {
      await exportAccount();
      setExportFeedback({ ok: true, text: "Export downloaded" });
    } catch (err) {
      setExportFeedback({ ok: false, text: (err as Error).message });
    } finally {
      setExporting(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (!deletePassword) {
      // Thrown (not just set as feedback) so ConfirmDialog's own inline
      // error banner shows it — the dialog has no separate feedback slot.
      throw new Error("Enter your current password to continue.");
    }
    setDeleting(true);
    try {
      await deleteAccount({ current_password: deletePassword });
      logout();
    } catch (err) {
      setDeleting(false);
      throw err; // ConfirmDialog surfaces the failure inline (incl. the
      // 409 "last owner" message the backend sends verbatim)
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
          role="alert"
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
            <label htmlFor={ids.name} className={labelCls}>
              Name
            </label>
            <input
              id={ids.name}
              type="text"
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
              style={inputStyle}
              placeholder={loading ? "Loading..." : "Your name"}
            />
          </div>
          <div>
            <label htmlFor={ids.email} className={labelCls}>
              Email
            </label>
            <input
              id={ids.email}
              type="email"
              autoComplete="email"
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
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor={ids.currentPassword} className={labelCls}>
                Current Password
              </label>
              <input
                id={ids.currentPassword}
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
                style={inputStyle}
                placeholder="Enter current password"
              />
            </div>
            <div>
              <label htmlFor={ids.newPassword} className={labelCls}>
                New Password
              </label>
              <input
                id={ids.newPassword}
                type="password"
                autoComplete="new-password"
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
            <label htmlFor={ids.tier} className={labelCls}>
              Default Permission Tier
            </label>
            <select
              id={ids.tier}
              aria-describedby={ids.tierHelp}
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
            <p id={ids.tierHelp} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
              {PERMISSION_TIERS.find((t) => t.value === permissionTier)?.help}
              {" "}Hard-blocked scopes (like Robinhood trade execution) are
              enforced at the platform layer regardless of this setting.
            </p>
          </div>
          <div>
            <label htmlFor={ids.rateLimit} className={labelCls}>
              Rate Limit (requests/minute)
            </label>
            <input
              id={ids.rateLimit}
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

      {/* Permissions */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Policy</div>
        <h2 className="mb-1">Permissions</h2>
        <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
          Control what the agent is allowed to do. Some capabilities also
          depend on OS permission or a one-time install — those are shown
          even when they can't be turned on yet.
        </p>
        {capabilitiesFeedback && !capabilitiesFeedback.ok && (
          <div
            className="rounded-[10px] p-3 text-sm mb-4"
            role="alert"
            style={{
              background: "var(--fill-danger)",
              border: "1px solid var(--border-danger)",
              color: "var(--accent-danger)",
            }}
          >
            {capabilitiesFeedback.text}
          </div>
        )}
        {capabilitiesLoadError ? (
          <CapabilityListError message={capabilitiesLoadError} onRetry={handleRetryLoadCapabilities} />
        ) : capabilities === null ? (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Loading permissions…
          </p>
        ) : (
          <CapabilityList
            items={capabilities}
            editable={!!me?.is_admin}
            onToggle={(key, enabled) => void handleToggleCapability(key, enabled)}
            onRequestAccess={(key) => void handleRequestCapabilityAccess(key)}
            onInstall={(key) => void handleInstallCapability(key)}
            busyKey={capabilitiesBusyKey}
            onSettingsChange={(key, patch) => void handleCapabilitySettingsChange(key, patch)}
          />
        )}
        {/* Each account lists and revokes its own weekly approvals: not gated on is_admin. */}
        <AppApprovals />
      </section>

      {/* Payment card (owner only): the card "Buy things for me" pays with.
          Entered here and nowhere else; the vault route refuses anyone
          else, so the section is not rendered for them at all. */}
      {me?.is_admin && <PaymentCardSettings />}

      {/* Server (owner only): the install-wide AI provider and sign-ups,
          as set up by the wizard. Not rendered at all for anyone else. */}
      {me?.is_admin && <ServerSettings />}

      {/* Telegram approvals */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Approvals</div>
        <h2 className="mb-4">Telegram approvals</h2>
        <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
          Get approval requests on your phone with Approve / Deny buttons —
          no need to be at a computer when the assistant asks for permission.
        </p>

        {me?.is_admin && (
          <div
            className="rounded-[10px] p-4 mb-4 space-y-3"
            style={{ background: "var(--bg-input)", border: "1px solid var(--claw-border)" }}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                Bot token
              </span>
              {tgStatus?.configured && (
                <button
                  type="button"
                  onClick={() => void handleTgTokenRemove()}
                  disabled={tgTokenBusy !== null}
                  className="text-xs font-medium underline disabled:opacity-50"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Remove
                </button>
              )}
            </div>
            {tgTokenEnvManaged ? (
              // The 409 from test/save said TELEGRAM_BOT_TOKEN in .env
              // provides it; a stored one here would never be used.
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                {tgTokenFeedback?.text}
              </p>
            ) : (
              <>
                <input
                  type="password"
                  value={tgToken}
                  onChange={(e) => setTgToken(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={
                    tgStatus?.configured ? "A token is saved — paste a new one to replace it" : "123456789:AA…"
                  }
                  className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
                  style={inputStyle}
                />
                <div className="flex items-center gap-3 flex-wrap">
                  <button
                    type="button"
                    onClick={() => void handleTgTokenTest()}
                    disabled={!tgToken.trim() || tgTokenBusy !== null}
                    className="px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
                    style={{
                      background: "transparent",
                      border: "1px solid var(--claw-border)",
                      color: "var(--text-primary)",
                    }}
                  >
                    {tgTokenBusy === "test" ? (
                      <Loader2 className="w-4 h-4 animate-spin inline-block mr-1.5" />
                    ) : null}
                    Test
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleTgTokenSave()}
                    disabled={!tgToken.trim() || tgTokenBusy !== null}
                    className="px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
                    style={{ background: "var(--accent-primary)", color: "#0a0a0b" }}
                  >
                    {tgTokenBusy === "save" ? (
                      <Loader2 className="w-4 h-4 animate-spin inline-block mr-1.5" />
                    ) : null}
                    Save
                  </button>
                  <FeedbackLine feedback={tgTokenFeedback} />
                </div>
              </>
            )}
          </div>
        )}

        {tgStatus === null ? (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Checking status…
          </p>
        ) : !tgStatus.configured ? (
          me?.is_admin ? (
            <div
              className="rounded-[10px] p-4 text-sm space-y-2"
              style={{ background: "var(--bg-input)", border: "1px solid var(--claw-border)" }}
            >
              <p style={{ color: "var(--text-primary)" }}>One-time setup (about a minute):</p>
              <ol className="list-decimal pl-5 space-y-1" style={{ color: "var(--text-secondary)" }}>
                <li>
                  In Telegram, message{" "}
                  <a
                    href="https://t.me/BotFather"
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: "var(--accent-primary)" }}
                  >
                    @BotFather
                  </a>
                  , send <code>/newbot</code>, and pick any name.
                </li>
                <li>Paste the token it replies with into Bot token above, and Save.</li>
                <li>Tap Connect below to link your own chat.</li>
              </ol>
            </div>
          ) : (
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Ask the owner to add a bot token.
            </p>
          )
        ) : tgStatus.linked ? (
          <div className="flex items-center gap-3 flex-wrap">
            <span
              className="inline-flex items-center gap-1.5 text-sm"
              style={{ color: "var(--accent-success)" }}
            >
              <CheckCircle2 className="w-4 h-4" />
              Connected
              {tgStatus.bot_username ? ` to @${tgStatus.bot_username}` : ""} —
              approvals reach your Telegram.
            </span>
            <button
              type="button"
              onClick={() => void handleTgDisconnect()}
              disabled={tgBusy}
              className="px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
              style={{
                background: "transparent",
                border: "1px solid var(--claw-border)",
                color: "var(--text-secondary)",
              }}
            >
              Disconnect
            </button>
            <FeedbackLine feedback={tgFeedback} />
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <button
                type="button"
                onClick={() => void handleTgConnect()}
                disabled={tgBusy}
                className="flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-semibold disabled:opacity-50"
                style={{ background: "var(--accent-primary)", color: "#0a0a0b" }}
              >
                {tgBusy ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
                Connect Telegram
              </button>
              <FeedbackLine feedback={tgFeedback} />
            </div>
            {tgLink && (
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Waiting for you to tap the link on your phone… If it didn&apos;t
                open, use{" "}
                <a
                  href={tgLink.link_url}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: "var(--accent-primary)" }}
                >
                  {tgLink.link_url}
                </a>{" "}
                (valid {tgLink.expires_in_minutes} min).
              </p>
            )}
          </div>
        )}
      </section>

      {/* LLM Provider */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Runtime</div>
        <h2 className="mb-4">LLM provider</h2>
        <div className="space-y-4">
          <div>
            <span id={ids.provider} className={labelCls}>
              Provider
            </span>
            <div
              role="radiogroup"
              aria-labelledby={ids.provider}
              className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3"
            >
              {PROVIDER_CHOICES.map(({ value, label, hint }) => {
                const isActive = llmProvider === value;
                return (
                  <button
                    key={value ?? "default"}
                    type="button"
                    role="radio"
                    aria-checked={isActive}
                    onClick={() => {
                      setLlmProvider(value);
                      setLlmModel(value === null ? "" : (LLM_MODELS[value]?.[0] ?? ""));
                    }}
                    className={`px-4 py-3 rounded-[10px] text-sm font-medium transition-colors${
                      value === null ? "" : " capitalize"
                    }`}
                    style={{
                      minHeight: 44,
                      background: isActive ? "var(--accent-glow)" : "var(--claw-surface)",
                      border: isActive
                        ? "1px solid var(--border-accent)"
                        : "1px solid var(--claw-border)",
                      color: isActive ? "var(--accent-primary)" : "var(--text-secondary)",
                    }}
                  >
                    {label}
                    {hint && (
                      <span className="block text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                        {hint}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
          {llmProvider === null ? (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Your messages use the provider and model this Crawler was set up
              with, and follow it if the owner changes it. Pick a provider
              above to choose your own.
            </p>
          ) : (
            <div>
              <label htmlFor={ids.model} className={labelCls}>
                Model
              </label>
              <select
                id={ids.model}
                aria-describedby={ids.modelHelp}
                value={llmModel}
                onChange={(e) => setLlmModel(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
                style={inputStyle}
              >
                {(() => {
                  // The hardcoded list is a convenience, not a contract: the
                  // account's current model (set server-side or by an older
                  // build) must stay selectable even when it isn't listed,
                  // and an unknown provider must not crash the page.
                  const known = LLM_MODELS[llmProvider] ?? [];
                  const options =
                    llmModel && !known.includes(llmModel)
                      ? [llmModel, ...known]
                      : known;
                  return options.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ));
                })()}
              </select>
              <p id={ids.modelHelp} className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                Takes effect on your next message. This Crawler must have an
                API key for this provider (added during setup or in{" "}
                <code style={{ color: "var(--accent-primary)" }}>backend/.env</code>)
                — if it doesn't, chat says so instead of silently falling back
                to another provider.
              </p>
            </div>
          )}
          <div className="flex items-center gap-3">
            <SaveButton label="Save LLM Settings" onClick={handleSaveLlm} saving={savingLlm} />
            <FeedbackLine feedback={llmFeedback} />
          </div>
        </div>
      </section>

      {/* Data export */}
      <section className="rounded-[14px] p-6" style={panelStyle}>
        <div className="eyebrow mb-1">Your data</div>
        <h2 className="mb-1">Export everything</h2>
        <p className="text-sm mb-4" style={{ color: "var(--text-muted)" }}>
          Download every conversation, memory, connector setting, and audit
          record on this account as a single JSON file. Connector credentials
          are excluded — they stay encrypted on the server.
        </p>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleExport}
            disabled={exporting}
            className="flex items-center gap-2 px-4 py-2 rounded-[10px] text-sm font-medium disabled:opacity-50"
            style={inputStyle}
          >
            {exporting ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            {exporting ? "Preparing…" : "Export my data"}
          </button>
          <FeedbackLine feedback={exportFeedback} />
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
          className="flex items-center gap-2 px-4 rounded-[10px] text-sm font-semibold disabled:opacity-50"
          style={{
            minHeight: 44,
            background: "var(--accent-danger)",
            color: "var(--text-on-accent)",
          }}
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
        onCancel={() => {
          setConfirmDeleteOpen(false);
          setDeletePassword("");
        }}
        onConfirm={handleDeleteAccount}
      >
        <label
          htmlFor={ids.deletePassword}
          className="block text-xs font-medium mb-1.5"
          style={{ color: "var(--text-secondary)" }}
        >
          Current password
        </label>
        <input
          id={ids.deletePassword}
          type="password"
          value={deletePassword}
          onChange={(e) => setDeletePassword(e.target.value)}
          autoComplete="current-password"
          placeholder="Required to delete your account"
          className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none"
          style={{
            background: "var(--bg-input)",
            border: "1px solid var(--claw-border)",
            color: "var(--text-primary)",
          }}
        />
      </ConfirmDialog>


      {loading && (
        <div
          role="status"
          className="flex items-center gap-2 text-xs"
          style={{ color: "var(--text-muted)" }}
        >
          <Loader2 className="w-3 h-3 animate-spin" aria-hidden />
          Loading account...
        </div>
      )}
    </div>
  );
}
