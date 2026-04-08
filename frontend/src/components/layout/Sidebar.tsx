import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Plug,
  Shield,
  Settings,
  LogOut,
  Brain,
} from "lucide-react";
import clsx from "clsx";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/chat", icon: MessageSquare, label: "Chat" },
  { to: "/connectors", icon: Plug, label: "Connectors" },
  { to: "/audit", icon: Shield, label: "Audit Logs" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export default function Sidebar() {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    navigate("/login");
  };

  return (
    <aside
      className="fixed left-0 top-0 z-40 h-screen w-[260px] shrink-0 flex flex-col border-r border-[var(--border-subtle)] bg-[var(--bg-sidebar)] backdrop-blur-xl supports-[backdrop-filter]:bg-[rgba(22,22,24,0.92)]"
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-6 border-b border-[var(--border-subtle)]">
        <div className="w-10 h-10 rounded-[12px] flex items-center justify-center bg-[var(--accent-primary)] shadow-sm">
          <Brain className="w-[22px] h-[22px] text-white" strokeWidth={1.75} />
        </div>
        <div className="min-w-0">
          <h1 className="text-[17px] font-semibold tracking-tight text-[var(--text-primary)] leading-tight">
            SentientAI
          </h1>
          <p className="text-[13px] text-[var(--text-muted)] leading-snug mt-0.5">
            Secure Agent Platform
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 min-h-0 overflow-y-auto px-3 py-4 space-y-0.5">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              clsx(
                "group flex items-center gap-3 px-3 py-2.5 rounded-[10px] text-[15px] font-medium transition-colors duration-200",
                isActive
                  ? "bg-[rgba(10,132,255,0.18)] text-[var(--text-primary)]"
                  : "text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.06)] hover:text-[var(--text-primary)]"
              )
            }
          >
            {({ isActive }) => (
              <>
                <item.icon
                  className="w-[20px] h-[20px] shrink-0"
                  strokeWidth={isActive ? 2.25 : 1.75}
                  style={{
                    color: isActive
                      ? "var(--accent-primary)"
                      : "var(--text-muted)",
                  }}
                />
                <span className="flex-1 truncate">{item.label}</span>
                {isActive && (
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--accent-primary)] shrink-0" />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User section */}
      <div className="px-3 py-4 border-t border-[var(--border-subtle)]">
        <div className="flex items-center gap-3 rounded-[12px] px-2 py-2 bg-[rgba(255,255,255,0.04)] border border-[var(--border-subtle)]">
          <div className="w-9 h-9 rounded-full flex items-center justify-center text-[13px] font-semibold bg-[rgba(10,132,255,0.22)] text-[var(--accent-primary)] shrink-0">
            U
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[15px] font-medium truncate text-[var(--text-primary)]">
              User
            </p>
            <p className="text-[12px] truncate text-[var(--text-muted)]">
              user@example.com
            </p>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="p-2 rounded-lg text-[var(--text-muted)] hover:bg-[rgba(255,255,255,0.08)] hover:text-[var(--text-primary)] transition-colors shrink-0"
            title="Log out"
          >
            <LogOut className="w-[18px] h-[18px]" strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </aside>
  );
}
