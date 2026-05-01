import { useEffect, useState } from "react";
import {
  Save,
  Loader2,
  LogOut,
  Mail,
  Lock,
  CheckCircle2,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ApiError,
  getMe,
  logout,
  resendVerification,
  updateSettings,
} from "@/services/api";
import type { User } from "@/types";
import { toast } from "@/hooks/useToast";
import { Skeleton } from "@/components/ui/Skeleton";
import { ErrorBanner } from "@/components/ui/ErrorBanner";

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

const PROVIDERS = [
  "anthropic",
  "openai",
  "gemini",
  "grok",
  "deepseek",
  "groq",
  "mistral",
  "ollama",
] as const;

// User extended with optional verification fields the backend may return.
interface UserExtended extends User {
  email_verified_at?: string | null;
}

function getErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  return fallback;
}

export default function Settings() {
  const queryClient = useQueryClient();

  const meQuery = useQuery({
    queryKey: ["me"],
    queryFn: () => getMe() as Promise<UserExtended>,
  });

  const user = meQuery.data;
  const [name, setName] = useState("");
  const [llmProvider, setLlmProvider] = useState<string>("openai");
  const [llmModel, setLlmModel] = useState<string>("gpt-4o");
  const [apiKey, setApiKey] = useState("");

  // Sync state once user loads.
  useEffect(() => {
    if (user) {
      setName(user.name ?? "");
      setLlmProvider(user.llm_provider);
      setLlmModel(user.llm_model);
    }
  }, [user]);

  const profileMutation = useMutation({
    mutationFn: () => updateSettings({ name: name.trim() }),
    onSuccess: (updated) => {
      queryClient.setQueryData(["me"], updated);
      toast.success({ title: "Settings saved", description: "Profile updated." });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't save profile",
        description: getErrorMessage(err, "Try again in a moment."),
      });
    },
  });

  const llmMutation = useMutation({
    mutationFn: () => {
      const data: Record<string, string> = {
        llm_provider: llmProvider,
        llm_model: llmModel,
      };
      if (apiKey.trim()) data.llm_api_key = apiKey.trim();
      return updateSettings(data);
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(["me"], updated);
      setApiKey("");
      toast.success({ title: "Settings saved", description: "LLM configuration updated." });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't save LLM settings",
        description: getErrorMessage(err, "Try again in a moment."),
      });
    },
  });

  const resendVerificationMutation = useMutation({
    mutationFn: () => {
      if (!user?.email) {
        throw new Error("No email address on file.");
      }
      return resendVerification({ email: user.email });
    },
    onSuccess: () => {
      toast.success({
        title: "Verification email sent",
        description: "Check your inbox for the link.",
      });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't send verification email",
        description: getErrorMessage(err, "Try again in a moment."),
      });
    },
  });

  const logoutAllMutation = useMutation({
    mutationFn: async () => {
      // logout() may be sync or async depending on the foundation impl; await
      // the resolved value either way so this works for both.
      const result = await Promise.resolve(logout());
      return result as void;
    },
    onSuccess: () => {
      toast.info({
        title: "Signed out",
        description: "You've been logged out of all sessions.",
      });
    },
    onError: (err: unknown) => {
      toast.error({
        title: "Couldn't sign out",
        description: getErrorMessage(err, "Try again in a moment."),
      });
    },
  });

  const inputClass =
    "w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors";

  if (meQuery.isLoading) {
    return (
      <div className="space-y-8 max-w-3xl">
        <header>
          <Skeleton width="w-40" height="h-9" className="mb-2" />
          <Skeleton width="w-64" height="h-4" />
        </header>
        <Skeleton width="w-full" height="h-48" className="rounded-[var(--radius-xl)]" />
        <Skeleton width="w-full" height="h-72" className="rounded-[var(--radius-xl)]" />
      </div>
    );
  }

  if (meQuery.isError) {
    return (
      <div className="max-w-3xl">
        <ErrorBanner
          title="Couldn't load your profile"
          error={meQuery.error}
          onRetry={() => meQuery.refetch()}
          retrying={meQuery.isFetching}
        />
      </div>
    );
  }

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
            <label
              htmlFor="profile-name"
              className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]"
            >
              Name
            </label>
            <input
              id="profile-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={inputClass}
              placeholder="Your name"
            />
          </div>
          <div>
            <label
              htmlFor="profile-email"
              className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]"
            >
              Email
            </label>
            <input
              id="profile-email"
              type="email"
              value={user?.email ?? ""}
              disabled
              className={inputClass + " opacity-60 cursor-not-allowed"}
            />
          </div>
          <button
            type="button"
            onClick={() => profileMutation.mutate()}
            disabled={profileMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 rounded-[12px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-50 hover:brightness-110 transition-all"
          >
            {profileMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            Save Profile
          </button>
        </div>
      </section>

      {/* Email verification (only when unverified) */}
      {user && user.email_verified_at == null && (
        <section
          className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7"
          style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
        >
          <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)] mb-2 flex items-center gap-2">
            <Mail className="w-5 h-5 text-[var(--accent-warning)]" strokeWidth={2} />
            Verify your email
          </h2>
          <p className="text-[14px] text-[var(--text-muted)] mb-5">
            Confirm your email to unlock all features. We'll send a verification
            link to <span className="text-[var(--text-primary)]">{user.email}</span>.
          </p>
          <button
            type="button"
            onClick={() => resendVerificationMutation.mutate()}
            disabled={resendVerificationMutation.isPending}
            className="flex items-center gap-2 px-4 py-2.5 rounded-[12px] text-[14px] font-medium border border-[var(--border-primary)] text-[var(--text-primary)] hover:bg-[rgba(255,255,255,0.06)] transition-colors disabled:opacity-50"
          >
            {resendVerificationMutation.isPending && (
              <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
            )}
            Resend verification email
          </button>
        </section>
      )}

      {user?.email_verified_at && (
        <p className="flex items-center gap-2 text-[13px] text-[var(--accent-success)]">
          <CheckCircle2 className="w-4 h-4" strokeWidth={2.5} aria-hidden="true" />
          Email verified
        </p>
      )}

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
            <span
              id="provider-label"
              className="block text-[13px] font-medium mb-3 text-[var(--text-secondary)]"
            >
              Provider
            </span>
            <div
              role="radiogroup"
              aria-labelledby="provider-label"
              className="grid grid-cols-2 sm:grid-cols-4 gap-2.5"
            >
              {PROVIDERS.map((p) => {
                const isSelected = llmProvider === p;
                return (
                  <button
                    key={p}
                    type="button"
                    role="radio"
                    aria-checked={isSelected}
                    aria-pressed={isSelected}
                    onClick={() => {
                      setLlmProvider(p);
                      setLlmModel(models[p][0]);
                    }}
                    className="px-4 py-3 rounded-[12px] border text-[14px] font-medium capitalize transition-all"
                    style={{
                      backgroundColor: isSelected ? "rgba(10,132,255,0.14)" : "var(--bg-tertiary)",
                      borderColor: isSelected ? "var(--accent-primary)" : "var(--border-subtle)",
                      color: isSelected ? "var(--text-primary)" : "var(--text-secondary)",
                    }}
                  >
                    {p}
                    {p === "ollama" && (
                      <span className="block text-[11px] mt-0.5 text-[var(--text-muted)]">Local</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <label
              htmlFor="llm-model"
              className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]"
            >
              Model
            </label>
            <select
              id="llm-model"
              value={llmModel}
              onChange={(e) => setLlmModel(e.target.value)}
              className={inputClass}
            >
              {(models[llmProvider] || []).map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          {llmProvider !== "ollama" && (
            <div>
              <label
                htmlFor="llm-api-key"
                className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]"
              >
                API Key{" "}
                <span className="text-[var(--text-muted)]">(leave empty to keep current)</span>
              </label>
              <input
                id="llm-api-key"
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
            onClick={() => llmMutation.mutate()}
            disabled={llmMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 rounded-[12px] text-[14px] font-semibold text-white bg-[var(--accent-primary)] disabled:opacity-50 hover:brightness-110 transition-all"
          >
            {llmMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            Save LLM Settings
          </button>
        </div>
      </section>

      {/* Change password */}
      <section
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)] mb-2 flex items-center gap-2">
          <Lock className="w-5 h-5 text-[var(--text-secondary)]" strokeWidth={2} />
          Change password
        </h2>
        <p className="text-[14px] text-[var(--text-muted)] mb-4">
          Same-session password changes aren't yet wired. Use the password reset
          flow from the login screen for now.
        </p>
        <Link
          to="/login"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-[10px] text-[13px] font-medium border border-[var(--border-primary)] text-[var(--text-primary)] hover:bg-[rgba(255,255,255,0.06)] transition-colors"
        >
          Go to "Forgot password"
        </Link>
      </section>

      {/* Account / sessions */}
      <section
        className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-6 md:p-7"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text-primary)] mb-2 flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-[var(--text-secondary)]" strokeWidth={2} />
          Sessions
        </h2>
        <p className="text-[14px] text-[var(--text-muted)] mb-5">
          Sign out of every device using your account.
        </p>
        <button
          type="button"
          onClick={() => logoutAllMutation.mutate()}
          disabled={logoutAllMutation.isPending}
          className="flex items-center gap-2 px-4 py-2.5 rounded-[12px] text-[14px] font-medium text-white bg-[var(--accent-danger)] hover:brightness-110 transition-all disabled:opacity-50"
        >
          {logoutAllMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <LogOut className="w-4 h-4" />
          )}
          Logout all sessions
        </button>
      </section>
    </div>
  );
}
