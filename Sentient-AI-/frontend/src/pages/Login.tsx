import { useEffect, useId, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, Eye, EyeOff, HardDrive, Server } from "lucide-react";
import { getSetupStatus, login, register } from "@/services/api";
import Brand, { Wordmark } from "@/components/Brand";
import ThemeToggle from "@/components/ThemeToggle";
import type { SetupStatus } from "@/types";

const labelCls = "block text-sm font-medium mb-1.5";

export default function Login() {
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const nameId = useId();
  const emailId = useId();
  const passwordId = useId();

  // Registration is closed server-side until setup finishes (see
  // /api/auth/register), so while that's true the "Create one" link would
  // just lead to a 403. Ask once and swap it for a more honest hint.
  useEffect(() => {
    let cancelled = false;
    getSetupStatus()
      .then((s) => {
        if (!cancelled) setSetupStatus(s);
      })
      .catch(() => {
        // Status unknown: fail open, like SetupGate does, and keep the
        // ordinary sign-in/register toggle below.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const setupInProgress = !!setupStatus && !setupStatus.setup_completed;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (isRegister) {
        await register({ email, password, name });
      } else {
        await login({ email, password });
      }
      navigate("/");
    } catch (err) {
      setError((err as Error).message || "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="relative min-h-screen flex items-center justify-center p-4 sm:p-6"
      style={{
        background:
          "radial-gradient(ellipse at 50% 30%, var(--accent-glow), transparent 55%), var(--bg-primary)",
      }}
    >
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>

      <div className="flex flex-col items-center gap-5 w-full max-w-[440px]">
        {/* Brand mark. "animated" currently renders the still mark — see
            the TODO(brand) note in components/Brand.tsx. */}
        <div className="relative w-[150px] h-[150px] flex items-center justify-center">
          <div
            aria-hidden
            style={{
              position: "absolute",
              inset: -20,
              background:
                "radial-gradient(circle, var(--accent-glow), transparent 65%)",
              filter: "blur(12px)",
              pointerEvents: "none",
            }}
          />
          <div
            className="relative w-full h-full rounded-full overflow-hidden"
            style={{
              boxShadow:
                "0 0 0 1px var(--border-accent), var(--shadow-modal)",
            }}
          >
            <Brand variant="animated" size={150} rounded={999} alt="" />
          </div>
        </div>

        {/* Wordmark + tagline */}
        <div className="flex flex-col items-center gap-2 mt-1 text-center">
          <Wordmark height={40} />
          <div className="eyebrow" style={{ letterSpacing: "0.18em" }}>
            Self-hosted · control UI
          </div>
        </div>

        {/* Panel */}
        <div
          className="w-full mt-1 p-5 sm:p-7 rounded-[14px]"
          style={{
            background: "var(--claw-panel)",
            border: "1px solid var(--claw-border)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div className="flex items-baseline justify-between mb-[18px]">
            <h1 className="h3 m-0">{isRegister ? "Create account" : "Sign in"}</h1>
            <span className="eyebrow" style={{ letterSpacing: "0.14em" }}>
              local only
            </span>
          </div>

          {error && (
            <div
              role="alert"
              className="mb-4 px-3 py-2.5 rounded-[8px] text-sm"
              style={{
                background: "var(--fill-danger)",
                color: "var(--accent-danger)",
                border: "1px solid var(--border-danger)",
              }}
            >
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-3.5">
            {isRegister && (
              <div>
                <label htmlFor={nameId} className={labelCls}>
                  Full name
                </label>
                <input
                  id={nameId}
                  type="text"
                  autoComplete="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none transition-colors"
                  style={{
                    background: "var(--bg-input)",
                    border: "1px solid var(--claw-border)",
                    color: "var(--text-primary)",
                  }}
                  placeholder="Krish Shroff"
                  required
                />
              </div>
            )}

            <div>
              <label htmlFor={emailId} className={labelCls}>
                Email
              </label>
              <input
                id={emailId}
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none transition-colors"
                style={{
                  background: "var(--bg-input)",
                  border: "1px solid var(--claw-border)",
                  color: "var(--text-primary)",
                }}
                placeholder="you@yourdomain.com"
                required
              />
            </div>

            <div>
              <label htmlFor={passwordId} className={labelCls}>
                Password
              </label>
              <div className="relative">
                <input
                  id={passwordId}
                  type={showPassword ? "text" : "password"}
                  autoComplete={isRegister ? "new-password" : "current-password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none transition-colors pr-12"
                  style={{
                    background: "var(--bg-input)",
                    border: "1px solid var(--claw-border)",
                    color: "var(--text-primary)",
                  }}
                  placeholder="Min. 8 characters"
                  minLength={8}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  aria-pressed={showPassword}
                  className="absolute right-1 top-1/2 -translate-y-1/2 inline-flex items-center justify-center rounded-[8px]"
                  style={{ width: 40, height: 40, color: "var(--text-muted)" }}
                >
                  {showPassword ? (
                    <EyeOff size={16} aria-hidden />
                  ) : (
                    <Eye size={16} aria-hidden />
                  )}
                </button>
              </div>
            </div>

            {/* Deployment badges — static descriptions of how Crawler AI is
                deployed, not live status checks. */}
            <div className="flex items-center gap-2 mt-1">
              <StatusPill tone="ok">
                <Server size={11} strokeWidth={2.5} aria-hidden /> self-hosted
              </StatusPill>
              <StatusPill tone="accent">
                <HardDrive size={11} strokeWidth={2.5} aria-hidden /> local first
              </StatusPill>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="mt-2 w-full flex items-center justify-center gap-2 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
              style={{
                minHeight: 44,
                background: "var(--accent-primary)",
                color: "var(--text-on-accent)",
              }}
              onMouseOver={(e) =>
                (e.currentTarget.style.filter = "brightness(1.1)")
              }
              onMouseOut={(e) => (e.currentTarget.style.filter = "none")}
            >
              {loading
                ? "Please wait..."
                : isRegister
                ? "Create account"
                : "Continue to gateway"}
              {!loading && <ArrowRight size={15} strokeWidth={2} aria-hidden />}
            </button>
          </form>

          {setupInProgress ? (
            <p
              className="text-center text-sm mt-5"
              style={{ color: "var(--text-secondary)" }}
            >
              {setupStatus?.has_owner ? (
                "Setup is in progress — sign in as the owner to finish it."
              ) : (
                <>
                  Don't have an account?{" "}
                  <Link
                    to="/setup"
                    className="font-medium hover:underline"
                    style={{ color: "var(--accent-primary)" }}
                  >
                    Set up this Crawler
                  </Link>
                </>
              )}
            </p>
          ) : (
            <p
              className="text-center text-sm mt-5"
              style={{ color: "var(--text-secondary)" }}
            >
              {isRegister
                ? "Already have an account?"
                : "Don't have an account?"}{" "}
              <button
                type="button"
                onClick={() => {
                  setIsRegister(!isRegister);
                  setError("");
                }}
                className="font-medium hover:underline"
                style={{ color: "var(--accent-primary)" }}
              >
                {isRegister ? "Sign in" : "Create one"}
              </button>
            </p>
          )}
        </div>

        <div className="mono-tag text-center" style={{ color: "var(--text-muted)" }}>
          self-hosted · krishcodes1/sentient-ai-
        </div>
      </div>
    </div>
  );
}

function StatusPill({
  tone,
  children,
}: {
  tone: "ok" | "accent";
  children: React.ReactNode;
}) {
  const toneStyles =
    tone === "ok"
      ? {
          background: "var(--fill-success)",
          color: "var(--accent-success)",
          border: "1px solid var(--border-success)",
        }
      : {
          background: "var(--accent-glow)",
          color: "var(--accent-primary)",
          border: "1px solid var(--border-accent)",
        };
  return (
    <span
      className="mono-tag inline-flex items-center gap-1.5 px-2 py-1 rounded-[6px]"
      style={toneStyles}
    >
      {children}
    </span>
  );
}
