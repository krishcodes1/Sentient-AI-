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
      className="fixed left-0 top-0 h-screen w-64 flex flex-col border-r"
      style={{
        backgroundColor: "var(--bg-sidebar)",
        borderColor: "var(--border-primary)",
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center gap-3 px-6 py-5 border-b"
        style={{ borderColor: "var(--border-primary)" }}
      >
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: "var(--accent-primary)" }}
        >
          <Brain className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1
            className="text-lg font-bold tracking-tight"
            style={{ color: "var(--text-primary)" }}
          >
            SentientAI
          </h1>
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            Secure Agent Platform
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              clsx(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150",
                isActive
                  ? "shadow-sm"
                  : "hover:opacity-90"
              )
            }
            style={({ isActive }) => ({
              backgroundColor: isActive
                ? "rgba(99, 102, 241, 0.15)"
                : "transparent",
              color: isActive
                ? "var(--accent-primary-hover)"
                : "var(--text-secondary)",
            })}
          >
            {({ isActive }) => (
              <>
                <item.icon
                  className="w-5 h-5"
                  style={{
                    color: isActive
                      ? "var(--accent-primary)"
                      : "var(--text-muted)",
                  }}
                />
                {item.label}
                {isActive && (
                  <div
                    className="ml-auto w-1.5 h-1.5 rounded-full"
                    style={{ backgroundColor: "var(--accent-primary)" }}
                  />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User section */}
      <div
        className="px-4 py-4 border-t"
        style={{ borderColor: "var(--border-primary)" }}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold"
            style={{
              backgroundColor: "rgba(99, 102, 241, 0.2)",
              color: "var(--accent-primary)",
            }}
          >
            U
          </div>
          <div className="flex-1 min-w-0">
            <p
              className="text-sm font-medium truncate"
              style={{ color: "var(--text-primary)" }}
            >
              User
            </p>
            <p
              className="text-xs truncate"
              style={{ color: "var(--text-muted)" }}
            >
              user@example.com
            </p>
          </div>
          <button
            onClick={handleLogout}
            className="p-1.5 rounded-md transition-colors hover:opacity-80"
            style={{ color: "var(--text-muted)" }}
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
