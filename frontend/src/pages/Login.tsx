import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Brain, Eye, EyeOff } from "lucide-react";
import { login, register, getStoredUser, AccountLocked } from "@/services/api";
import { useToast } from "@/hooks/useToast";

function formatLockoutTime(d: Date): string {
  try {
    return d.toLocaleString(undefined, { hour: "numeric", minute: "2-digit" });
  } catch {
    return d.toISOString();
  }
}

export default function Login() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { toast } = useToast();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [lockoutBanner, setLockoutBanner] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Show a toast (and clear the param) when redirected here after a session expiry.
  useEffect(() => {
    if (searchParams.get("expired") === "1") {
      toast({
        variant: "warning",
        title: "Your session expired",
        description: "Please log in again.",
      });
      const next = new URLSearchParams(searchParams);
      next.delete("expired");
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams, toast]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLockoutBanner(null);
    setLoading(true);

    try {
      if (isRegister) {
        await register({ email, password, name });
      } else {
        await login({ email, password });
      }
      const user = getStoredUser();
      if (user && !user.onboarding_completed) {
        navigate("/onboarding");
      } else {
        navigate("/gateway");
      }
    } catch (err: unknown) {
      if (err instanceof AccountLocked) {
        const when = err.lockoutUntil ? formatLockoutTime(err.lockoutUntil) : null;
        const msg = when
          ? `Account locked. Try again after ${when}.`
          : "Account locked. Please try again later.";
        setLockoutBanner(msg);
        toast({ variant: "error", title: "Account locked", description: msg });
      } else {
        const msg = (err as Error)?.message || "Authentication failed";
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-5 bg-[var(--bg-primary)]">
      <div
        className="w-full max-w-[420px] rounded-[var(--radius-xl)] border border-[var(--border-subtle)] p-8 md:p-10"
        style={{ backgroundColor: "var(--bg-secondary)", boxShadow: "var(--shadow-card)" }}
      >
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-[16px] bg-[var(--accent-primary)] flex items-center justify-center mb-5 shadow-sm">
            <Brain className="w-9 h-9 text-white" strokeWidth={1.75} />
          </div>
          <h1 className="text-[24px] font-semibold tracking-tight text-[var(--text-primary)]">
            SentientAI
          </h1>
          <p className="text-[14px] mt-1 text-[var(--text-secondary)]">
            Secure-by-Design Agentic AI
          </p>
        </div>

        {/* Lockout banner (separate from generic error so it stays visible) */}
        {lockoutBanner && (
          <div
            role="alert"
            className="mb-5 p-3 rounded-[10px] text-[13px] bg-[rgba(251,191,36,0.12)] text-[var(--accent-warning)] border border-[rgba(251,191,36,0.3)]"
          >
            {lockoutBanner}
          </div>
        )}

        {/* Error */}
        {error && (
          <div
            id="login-error"
            role="alert"
            className="mb-5 p-3 rounded-[10px] text-[13px] bg-[rgba(255,69,58,0.12)] text-[var(--accent-danger)] border border-[rgba(255,69,58,0.25)]"
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5" noValidate>
          {isRegister && (
            <div>
              <label htmlFor="name" className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">
                Full Name
              </label>
              <input
                id="name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors"
                placeholder="Krish Shroff"
                autoComplete="name"
                required
              />
            </div>
          )}

          <div>
            <label htmlFor="email" className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-invalid={Boolean(error) || undefined}
              aria-describedby={error ? "login-error" : undefined}
              autoComplete="email"
              className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors"
              placeholder="you@example.com"
              required
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">
              Password
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={Boolean(error) || undefined}
                aria-describedby={error ? "login-error" : undefined}
                autoComplete={isRegister ? "new-password" : "current-password"}
                className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors pr-12"
                placeholder="Min. 8 characters"
                minLength={8}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? "Hide password" : "Show password"}
                aria-pressed={showPassword}
                className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors"
              >
                {showPassword ? <EyeOff className="w-[18px] h-[18px]" aria-hidden /> : <Eye className="w-[18px] h-[18px]" aria-hidden />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-[12px] text-[15px] font-semibold text-white bg-[var(--accent-primary)] transition-all disabled:opacity-50 hover:brightness-110"
          >
            {loading ? "Please wait..." : isRegister ? "Create Account" : "Sign In"}
          </button>
        </form>

        <p className="text-center text-[14px] mt-6 text-[var(--text-secondary)]">
          {isRegister ? "Already have an account?" : "Don't have an account?"}{" "}
          <button
            onClick={() => {
              setIsRegister(!isRegister);
              setError("");
              setLockoutBanner(null);
            }}
            className="font-medium text-[var(--accent-primary)] hover:underline"
          >
            {isRegister ? "Sign in" : "Create one"}
          </button>
        </p>
      </div>
    </div>
  );
}
