/**
 * Navigation sidebar: the brand, the nav links, the theme toggle, and the signed-in user with a
 * sign-out button.
 *
 * Why it exists: It becomes a focus-trapped dialog only while it overlays the page, and only an
 * actual 401/403 from getMe signs the user out; Layout renders it in both modes.
 */

import { useEffect, useRef, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Brain,
  Plug,
  Shield,
  Settings as SettingsIcon,
  LogOut,
  X,
} from "lucide-react";
import clsx from "clsx";
import type { User } from "@/types";
import { getMe, logout } from "@/services/api";
import Brand, { Wordmark } from "@/components/Brand";
import ThemeToggle from "@/components/ThemeToggle";
import { useFocusTrap } from "@/hooks/useFocusTrap";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Gateway", end: true },
  { to: "/chat", icon: MessageSquare, label: "Chat" },
  { to: "/memory", icon: Brain, label: "Memory" },
  { to: "/connectors", icon: Plug, label: "Connectors" },
  { to: "/audit", icon: Shield, label: "Audit logs" },
  { to: "/settings", icon: SettingsIcon, label: "Settings" },
];

export default function Sidebar({
  open = false,
  onClose,
  isDrawer = false,
}: {
  open?: boolean;
  onClose?: () => void;
  /** True below the desktop breakpoint, where this is an overlay. */
  isDrawer?: boolean;
}) {
  const [me, setMe] = useState<User | null>(null);
  const asideRef = useRef<HTMLElement>(null);
  const trapped = isDrawer && open;

  useFocusTrap(trapped, asideRef, onClose);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((u) => {
        if (!cancelled) setMe(u);
      })
      .catch((err: Error & { status?: number }) => {
        // Only an actual auth rejection means the session is dead. A
        // transient network error or a 5xx must not hard-log the user out
        // of an otherwise working session.
        if (err?.status === 401 || err?.status === 403) {
          logout();
        }
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
      ref={asideRef}
      id="app-navigation"
      data-open={open ? "true" : "false"}
      // Only a dialog while it overlays the page; above 1024px it is an
      // ordinary landmark and announcing it as modal would be a lie.
      role={trapped ? "dialog" : undefined}
      aria-modal={trapped ? true : undefined}
      aria-label="Sidebar"
      className="app-sidebar flex flex-col flex-shrink-0 overflow-y-auto"
      style={{
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
        <Brand size={44} variant="emblem" rounded={0} alt="" />
        <div className="flex flex-col leading-none min-w-0">
          <Wordmark height={18} />
          <span className="eyebrow mt-2" style={{ letterSpacing: "0.14em" }}>
            Control UI
          </span>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close navigation"
          className="lg:hidden ml-auto inline-flex items-center justify-center rounded-[10px] shrink-0"
          style={{ width: 44, height: 44, color: "var(--text-muted)" }}
        >
          <X size={18} strokeWidth={1.75} aria-hidden />
        </button>
      </div>

      {/* Nav */}
      <nav aria-label="Main navigation" className="mt-5 flex flex-col gap-1">
        <div className="eyebrow px-2.5 pb-2">Workspace</div>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              clsx(
                "group relative flex items-center gap-3 px-3 rounded-[10px] text-sm transition-colors",
                isActive ? "font-medium" : "font-normal"
              )
            }
            style={({ isActive }) => ({
              // A 44px row is the tap target; the nav is the most-used
              // control on the page and the hardest to hit on a phone.
              minHeight: 44,
              // backgroundColor, not the `background` shorthand: jsdom
              // cannot re-parse a shorthand holding a var() when it clones
              // a node, which it does to compute an accessible name — every
              // role query touching these links would throw.
              backgroundColor: isActive
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
                  aria-hidden
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
        <div className="flex items-center justify-between gap-2 px-2 pb-3">
          <span className="eyebrow">Theme</span>
          <ThemeToggle />
        </div>
        <div className="flex items-center gap-2.5 px-2 py-2.5 rounded-[10px]">
          <div
            aria-hidden
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
            type="button"
            onClick={handleLogout}
            aria-label="Sign out"
            title="Sign out"
            className="inline-flex items-center justify-center rounded-[8px] shrink-0 transition-colors"
            style={{ width: 44, height: 44, color: "var(--text-muted)" }}
          >
            <LogOut size={15} strokeWidth={1.75} aria-hidden />
          </button>
        </div>
      </div>
    </aside>
  );
}
