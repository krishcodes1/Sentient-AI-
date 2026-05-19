import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Eye, EyeOff, Check, Lock } from "lucide-react";
import { login, register } from "@/services/api";
import { Wordmark } from "@/components/Brand";

export default function Login() {
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

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
    } catch (err: any) {
      setError(err.message || "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center p-6"
      style={{
        background:
          "radial-gradient(ellipse at 50% 30%, rgba(34,211,238,0.10), transparent 55%), var(--bg-primary)",
      }}
    >
      <div className="flex flex-col items-center gap-5 w-full max-w-[440px]">
        {/* Animated brand mark */}
        <div className="relative w-[168px] h-[168px] flex items-center justify-center">
          <div
            aria-hidden
            style={{
              position: "absolute",
              inset: -20,
              background:
                "radial-gradient(circle, rgba(34,211,238,0.28), transparent 65%)",
              filter: "blur(12px)",
              pointerEvents: "none",
            }}
          />
          <div
            className="relative w-[168px] h-[168px] rounded-full overflow-hidden"
            style={{
              background: "#000",
              boxShadow:
                "0 0 0 1px rgba(34,211,238,0.25), 0 20px 60px rgba(0,0,0,0.6)",
            }}
          >
            <video
              src="/brand/sentientai-logo.mp4"
              autoPlay
              loop
              muted
              playsInline
              className="w-full h-full block"
              style={{ objectFit: "cover" }}
            />
          </div>
        </div>

        {/* Wordmark + tagline */}
        <div className="flex flex-col items-center gap-2 mt-1 text-center">
          <Wordmark height={44} />
          <div
            className="eyebrow"
            style={{ letterSpacing: "0.18em" }}
          >
            Self-hosted · control UI
          </div>
        </div>

        {/* Panel */}
        <div
          className="w-full mt-1 p-7 rounded-[14px]"
          style={{
            background: "var(--claw-panel)",
            border: "1px solid var(--claw-border)",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div className="flex items-baseline justify-between mb-[18px]">
            <h3 className="m-0">{isRegister ? "Create account" : "Sign in"}</h3>
            <span
              className="eyebrow"
              style={{ letterSpacing: "0.14em" }}
            >
              local only
            </span>
          </div>

          {error && (
            <div
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
                <label className="block mb-1.5">Full name</label>
                <input
                  type="text"
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
              <label className="block mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none transition-colors"
                style={{
                  background: "var(--bg-input)",
                  border: "1px solid var(--claw-border)",
                  color: "var(--text-primary)",
                }}
                placeholder="you@self-hosted.local"
                required
              />
            </div>

            <div>
              <label className="block mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-[10px] text-sm outline-none transition-colors pr-10"
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
                  className="absolute right-3 top-1/2 -translate-y-1/2"
                  style={{ color: "var(--text-muted)" }}
                >
                  {showPassword ? (
                    <EyeOff size={16} />
                  ) : (
                    <Eye size={16} />
                  )}
                </button>
              </div>
            </div>

            {/* Status pills */}
            <div className="flex items-center gap-2 mt-1">
              <StatusPill tone="ok">
                <Check size={11} strokeWidth={2.5} /> host verified
              </StatusPill>
              <StatusPill tone="accent">
                <Lock size={11} strokeWidth={2.5} /> e2ee session
              </StatusPill>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="mt-2 w-full flex items-center justify-center gap-2 py-2.5 rounded-[10px] text-sm font-semibold transition-all disabled:opacity-50"
              style={{
                background: "var(--accent-primary)",
                color: "#0a0a0b",
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
              {!loading && <ArrowRight size={15} strokeWidth={2} />}
            </button>
          </form>

          <p
            className="text-center text-sm mt-5"
            style={{ color: "var(--text-secondary)" }}
          >
            {isRegister
              ? "Already have an account?"
              : "Don't have an account?"}{" "}
            <button
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
        </div>

        <div
          className="mono-tag text-center"
          style={{ color: "var(--text-muted)" }}
        >
          v0.4.2 · self-hosted · krishcodes1/sentient-ai-
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
          border: "1px solid rgba(34,211,238,0.35)",
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