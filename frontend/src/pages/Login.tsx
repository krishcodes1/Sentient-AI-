import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Brain, Eye, EyeOff } from "lucide-react";
import { login, register, getStoredUser } from "@/services/api";

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
      const user = getStoredUser();
      if (user && !user.onboarding_completed) {
        navigate("/onboarding");
      } else {
        navigate("/gateway");
      }
    } catch (err: any) {
      setError(err.message || "Authentication failed");
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

        {/* Error */}
        {error && (
          <div className="mb-5 p-3 rounded-[10px] text-[13px] bg-[rgba(255,69,58,0.12)] text-[var(--accent-danger)] border border-[rgba(255,69,58,0.25)]">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          {isRegister && (
            <div>
              <label className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">
                Full Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors"
                placeholder="Krish Shroff"
                required
              />
            </div>
          )}

          <div>
            <label className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors"
              placeholder="you@example.com"
              required
            />
          </div>

          <div>
            <label className="block text-[13px] font-medium mb-2 text-[var(--text-secondary)]">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-[12px] border border-[var(--border-primary)] bg-[var(--bg-input)] text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] transition-colors pr-12"
                placeholder="Min. 8 characters"
                minLength={8}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors"
              >
                {showPassword ? <EyeOff className="w-[18px] h-[18px]" /> : <Eye className="w-[18px] h-[18px]" />}
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
