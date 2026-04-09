import { useState, useEffect } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Radio,
  Shield,
  Settings,
  LogOut,
  ExternalLink,
  Terminal,
} from "lucide-react";
import clsx from "clsx";
import { getStoredUser } from "@/services/api";

const GATEWAY_UI = "http://localhost:18789/";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Overview" },
  { to: "/chat", icon: MessageSquare, label: "Chat" },
  { to: "/channels", icon: Radio, label: "Channels" },
  { to: "/audit", icon: Shield, label: "Audit" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--text-muted)]">
      {children}
    </p>
  );
}

export default function Sidebar() {
  const navigate = useNavigate();
  const [user, setUser] = useState(getStoredUser());

  useEffect(() => {
    const onStorage = () => setUser(getStoredUser());
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const initials = user?.name
    ? user.name.split(" ").map((w) => w[0]).join("").slice(0, 2).toUpperCase()
    : user?.email?.[0]?.toUpperCase() || "U";

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("user");
    navigate("/login");
  };

  return (
    <aside
      className="sticky top-0 z-30 h-screen w-[248px] shrink-0 flex flex-col border-r border-[var(--claw-border)] bg-[var(--claw-sidebar)]"
    >
      {/* Brand — OpenClaw-style compact header */}
      <div className="flex items-start gap-3 px-4 pt-5 pb-4 border-b border-[var(--claw-border)]">
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 font-mono text-[18px] leading-none"
          style={{
            background: "var(--claw-surface)",
            border: "1px solid var(--claw-border)",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)",
          }}
          aria-hidden
        >
          🦞
        </div>
        <div className="min-w-0 pt-0.5">
          <h1 className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)] leading-tight font-mono">
            SentientAI
          </h1>
          <p className="text-[11px] text-[var(--text-muted)] mt-0.5 font-mono leading-snug">
            OpenClaw wrapper
          </p>
        </div>
      </div>

      <nav className="flex-1 min-h-0 overflow-y-auto px-3 py-4">
        <SectionLabel>Workspace</SectionLabel>
        <div className="space-y-0.5 mb-6">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                clsx(
                  "group flex items-center gap-2.5 px-2.5 py-2 rounded-md text-[13px] font-medium transition-colors duration-150 border border-transparent",
                  isActive
                    ? "bg-[var(--claw-surface-active)] text-[var(--text-primary)] border-[var(--claw-border)] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
                    : "text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.04)] hover:text-[var(--text-primary)]"
                )
              }
            >
              {({ isActive }) => (
                <>
                  <item.icon
                    className="w-[17px] h-[17px] shrink-0"
                    strokeWidth={isActive ? 2.25 : 1.65}
                    style={{
                      color: isActive ? "var(--claw-accent)" : "var(--text-muted)",
                    }}
                  />
                  <span className="flex-1 truncate">{item.label}</span>
                  {isActive && (
                    <span
                      className="w-1 h-1 rounded-full shrink-0"
                      style={{ background: "var(--claw-accent)" }}
                    />
                  )}
                </>
              )}
            </NavLink>
          ))}
        </div>

        <SectionLabel>Gateway</SectionLabel>
        <div className="rounded-md border border-[var(--claw-border)] bg-[var(--claw-surface)] p-2.5 space-y-2">
          <div className="flex items-center gap-2 text-[11px] text-[var(--text-muted)] font-mono">
            <Terminal className="w-3.5 h-3.5 shrink-0 text-[var(--claw-accent)]" strokeWidth={2} />
            <span className="truncate">Control UI</span>
          </div>
          <a
            href={GATEWAY_UI}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-1.5 w-full py-2 rounded-md text-[12px] font-medium font-mono text-[var(--claw-accent-bright)] bg-[rgba(34,211,238,0.08)] border border-[rgba(34,211,238,0.22)] hover:bg-[rgba(34,211,238,0.14)] transition-colors"
          >
            Open Gateway
            <ExternalLink className="w-3 h-3 opacity-80" strokeWidth={2} />
          </a>
          <p className="text-[10px] text-[var(--text-muted)] leading-relaxed px-0.5">
            Sessions, config, WebChat — same surface as native OpenClaw (port 18789).
          </p>
        </div>
      </nav>

      <div className="px-3 py-4 border-t border-[var(--claw-border)]">
        <div className="flex items-center gap-2.5 rounded-lg px-2 py-2 bg-[var(--claw-surface)] border border-[var(--claw-border)]">
          <div
            className="w-8 h-8 rounded-md flex items-center justify-center text-[11px] font-semibold font-mono shrink-0 text-[var(--claw-accent-bright)]"
            style={{ background: "rgba(34,211,238,0.12)", border: "1px solid rgba(34,211,238,0.2)" }}
          >
            {initials}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-medium truncate text-[var(--text-primary)]">
              {user?.name || "User"}
            </p>
            <p className="text-[10px] truncate text-[var(--text-muted)] font-mono">
              {user?.email || "—"}
            </p>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="p-1.5 rounded-md text-[var(--text-muted)] hover:bg-[rgba(255,255,255,0.06)] hover:text-[var(--text-primary)] transition-colors shrink-0"
            title="Log out"
          >
            <LogOut className="w-[16px] h-[16px]" strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </aside>
  );
}
