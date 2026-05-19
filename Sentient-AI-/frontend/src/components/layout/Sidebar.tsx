import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Plug,
  Shield,
  Settings as SettingsIcon,
  LogOut,
} from "lucide-react";
import clsx from "clsx";
import type { User } from "@/types";
import { getMe, logout } from "@/services/api";
import Brand, { Wordmark } from "@/components/Brand";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Gateway", end: true },
  { to: "/chat", icon: MessageSquare, label: "Chat" },
  { to: "/connectors", icon: Plug, label: "Connectors" },
  { to: "/audit", icon: Shield, label: "Audit logs" },
  { to: "/settings", icon: SettingsIcon, label: "Settings" },
];

export default function Sidebar() {
  const [me, setMe] = useState<User | null>(null);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((u) => {
        if (!cancelled) setMe(u);
      })
      .catch(() => {
        logout();
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLogout = () => {
    logout();
  };

  const displayName = me?.name?.trim() || "User";
  const displayEmail = me?.email || "loading...";
  const initial = (me?.name?.trim()?.[0] || me?.email?.[0] || "U").toUpperCase();

  return (
    <aside
      className="fixed left-0 top-0 h-screen flex flex-col flex-shrink-0"
      style={{
        width: 248,
        background: "var(--claw-sidebar)",
        borderRight: "1px solid var(--claw-border)",
        padding: "20px 14px",
      }}
    >
      {/* Brand */}
      <div
        className="flex items-center gap-3"
        style={{
          padding: "0 4px 20px",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <Brand size={44} variant="emblem" rounded={0} />
        <div className="flex flex-col leading-none min-w-0">
          <Wordmark height={18} />
          <span
            className="eyebrow mt-2"
            style={{ letterSpacing: "0.14em" }}
          >
            Control UI
          </span>
        </div>
      </div>

      {/* Nav */}
      <nav className="mt-5 flex flex-col gap-1">
        <div className="eyebrow px-2.5 pb-2">Workspace</div>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              clsx(
                "group relative flex items-center gap-3 px-3 py-2 rounded-[10px] text-sm transition-colors",
                isActive ? "font-medium" : "font-normal"
              )
            }
            style={({ isActive }) => ({
              background: isActive
                ? "var(--claw-surface-active)"
                : "transparent",
              border: `1px solid ${
                isActive ? "var(--claw-border)" : "transparent"
              }`,
              color: isActive
                ? "var(--text-primary)"
                : "var(--text-secondary)",
              boxShadow: isActive ? "var(--shadow-bevel)" : "none",
            })}
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span
                    aria-hidden
                    style={{
                      position: "absolute",
                      left: -14,
                      top: 10,
                      bottom: 10,
                      width: 2,
                      background: "var(--accent-primary)",
                      borderRadius: "0 2px 2px 0",
                    }}
                  />
                )}
                <item.icon
                  size={16}
                  strokeWidth={isActive ? 2 : 1.75}
                  style={{
                    color: isActive
                      ? "var(--text-primary)"
                      : "var(--text-muted)",
                  }}
                />
                <span className="flex-1">{item.label}</span>
                {isActive && (
                  <span
                    aria-hidden
                    style={{
                      width: 4,
                      height: 4,
                      borderRadius: 999,
                      background: "var(--accent-primary)",
                    }}
                  />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div
        className="mt-auto pt-4"
        style={{ borderTop: "1px solid var(--border-subtle)" }}
      >
        <div
          className="flex items-center gap-2.5 px-2 py-2.5 rounded-[10px]"
        >
          <div
            className="w-8 h-8 rounded-full flex items-center justify-center text-[13px] font-semibold shrink-0"
            style={{
              background: "var(--accent-glow)",
              color: "var(--accent-primary)",
              border: "1px solid var(--claw-border)",
            }}
          >
            {initial}
          </div>
          <div className="flex-1 min-w-0 leading-tight">
            <div
              className="text-[13px] font-medium truncate"
              style={{ color: "var(--text-primary)" }}
            >
              {displayName}
            </div>
            <div
              className="mono-tag truncate"
              style={{ color: "var(--text-muted)" }}
              title={displayEmail}
            >
              {displayEmail}
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="p-1 transition-colors"
            style={{ color: "var(--text-muted)" }}
            title="Sign out"
          >
            <LogOut size={15} strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </aside>
  );
}