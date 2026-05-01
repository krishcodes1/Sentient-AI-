import { useState, useEffect, useCallback } from "react";
import { NavLink, useNavigate, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Radio,
  Shield,
  Settings,
  LogOut,
  ExternalLink,
  Terminal,
  AppWindow,
  Plug,
  Menu,
  X,
} from "lucide-react";
import clsx from "clsx";
import {
  getOpenClawEmbedUrl,
  getStoredUser,
  logout as apiLogout,
} from "@/services/api";
import { OPENCLAW_BROWSER_URL } from "@/lib/env";
import { useMediaQuery } from "@/hooks/useMediaQuery";

const GATEWAY_FALLBACK = OPENCLAW_BROWSER_URL;

function normalizeGatewayHref(u: string): string {
  const t = u.trim();
  return t.endsWith("/") ? t : `${t}/`;
}

const navItems = [
  { to: "/gateway", icon: AppWindow, label: "OpenClaw UI" },
  { to: "/overview", icon: LayoutDashboard, label: "Overview" },
  { to: "/chat", icon: MessageSquare, label: "Chat" },
  { to: "/channels", icon: Radio, label: "Channels" },
  { to: "/connectors", icon: Plug, label: "Connectors" },
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

function BrandLogo() {
  const [svgFailed, setSvgFailed] = useState(false);
  return (
    <div
      className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 font-mono text-[18px] leading-none overflow-hidden"
      style={{
        background: "var(--claw-surface)",
        border: "1px solid var(--claw-border)",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)",
      }}
      aria-hidden
    >
      {svgFailed ? (
        <span>🦞</span>
      ) : (
        <img
          src="/icons/icon.svg"
          alt=""
          className="w-6 h-6 select-none"
          draggable={false}
          onError={() => setSvgFailed(true)}
        />
      )}
    </div>
  );
}

interface SidebarBodyProps {
  gatewayHref: string;
  initials: string;
  user: ReturnType<typeof getStoredUser>;
  onLogout: () => void;
  onNavigate?: () => void;
  closeButton?: React.ReactNode;
}

function SidebarBody({
  gatewayHref,
  initials,
  user,
  onLogout,
  onNavigate,
  closeButton,
}: SidebarBodyProps) {
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-start gap-3 px-4 pt-5 pb-4 border-b border-[var(--claw-border)]">
        <BrandLogo />
        <div className="min-w-0 pt-0.5 flex-1">
          <h1 className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)] leading-tight font-mono">
            SentientAI
          </h1>
          <p className="text-[11px] text-[var(--text-muted)] mt-0.5 font-mono leading-snug">
            OpenClaw wrapper
          </p>
        </div>
        {closeButton}
      </div>

      <nav
        aria-label="Primary"
        className="flex-1 min-h-0 overflow-y-auto px-3 py-4"
      >
        <SectionLabel>Workspace</SectionLabel>
        <div className="space-y-0.5 mb-6">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/gateway" || item.to === "/overview"}
              onClick={onNavigate}
              // NavLink applies aria-current="page" to the rendered <a>
              // automatically when the route is active — let it do its job.
              className={({ isActive }) =>
                clsx(
                  "group flex items-center gap-2.5 px-2.5 py-3 md:py-2 rounded-md text-[13px] font-medium transition-colors duration-150 border border-transparent min-h-[44px] md:min-h-0",
                  isActive
                    ? "bg-[var(--claw-surface-active)] text-[var(--text-primary)] border-[var(--claw-border)] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
                    : "text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.04)] hover:text-[var(--text-primary)]"
                )
              }
            >
              {({ isActive }) => (
                <span className="flex flex-1 items-center gap-2.5">
                  <item.icon
                    className="w-[17px] h-[17px] shrink-0"
                    strokeWidth={isActive ? 2.25 : 1.65}
                    style={{
                      color: isActive ? "var(--claw-accent)" : "var(--text-muted)",
                    }}
                    aria-hidden
                  />
                  <span className="flex-1 truncate">{item.label}</span>
                  {isActive && (
                    <span
                      className="w-1 h-1 rounded-full shrink-0"
                      style={{ background: "var(--claw-accent)" }}
                      aria-hidden
                    />
                  )}
                </span>
              )}
            </NavLink>
          ))}
        </div>

        <SectionLabel>Gateway</SectionLabel>
        <div className="rounded-md border border-[var(--claw-border)] bg-[var(--claw-surface)] p-2.5 space-y-2">
          <div className="flex items-center gap-2 text-[11px] text-[var(--text-muted)] font-mono">
            <Terminal className="w-3.5 h-3.5 shrink-0 text-[var(--claw-accent)]" strokeWidth={2} aria-hidden />
            <span className="truncate">Control UI</span>
          </div>
          <a
            href={gatewayHref}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-1.5 w-full py-3 md:py-2 rounded-md text-[12px] font-medium font-mono text-[var(--claw-accent-bright)] bg-[rgba(34,211,238,0.08)] border border-[rgba(34,211,238,0.22)] hover:bg-[rgba(34,211,238,0.14)] transition-colors min-h-[44px] md:min-h-0"
          >
            Open Gateway
            <ExternalLink className="w-3 h-3 opacity-80" strokeWidth={2} aria-hidden />
          </a>
          <p className="text-[10px] text-[var(--text-muted)] leading-relaxed px-0.5">
            Sessions, config, WebChat — same surface as native OpenClaw.
          </p>
        </div>
      </nav>

      <div className="px-3 py-4 border-t border-[var(--claw-border)]">
        <div className="flex items-center gap-2.5 rounded-lg px-2 py-2 bg-[var(--claw-surface)] border border-[var(--claw-border)]">
          <div
            className="w-8 h-8 rounded-md flex items-center justify-center text-[11px] font-semibold font-mono shrink-0 text-[var(--claw-accent-bright)]"
            style={{ background: "rgba(34,211,238,0.12)", border: "1px solid rgba(34,211,238,0.2)" }}
            aria-hidden
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
            onClick={onLogout}
            aria-label="Log out"
            title="Log out"
            className="p-3 rounded-md text-[var(--text-muted)] hover:bg-[rgba(255,255,255,0.06)] hover:text-[var(--text-primary)] transition-colors shrink-0 min-w-[44px] min-h-[44px] md:p-1.5 md:min-w-0 md:min-h-0 flex items-center justify-center"
          >
            <LogOut className="w-[16px] h-[16px]" strokeWidth={1.75} aria-hidden />
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();
  const isDesktop = useMediaQuery("(min-width: 768px)");
  const [user, setUser] = useState(getStoredUser());
  const [gatewayHref, setGatewayHref] = useState(normalizeGatewayHref(GATEWAY_FALLBACK));
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    getOpenClawEmbedUrl()
      .then((r) => setGatewayHref(normalizeGatewayHref(r.url)))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const onStorage = () => setUser(getStoredUser());
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // Close on route change.
  useEffect(() => {
    setDrawerOpen(false);
  }, [location.pathname]);

  // Close on Esc + lock body scroll while drawer is open.
  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setDrawerOpen(false);
    };
    window.addEventListener("keydown", onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [drawerOpen]);

  const initials = user?.name
    ? user.name.split(" ").map((w) => w[0]).join("").slice(0, 2).toUpperCase()
    : user?.email?.[0]?.toUpperCase() || "U";

  const handleLogout = useCallback(() => {
    apiLogout().catch(() => {
      // logout() already navigates internally; fall back just in case.
      navigate("/login");
    });
  }, [navigate]);

  // Skip-to-content link is rendered alongside the sidebar so it's always
  // first in the tab order.
  const skipLink = (
    <a
      href="#main"
      className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[1100] focus:px-3 focus:py-2 focus:rounded-md focus:bg-[var(--accent-primary)] focus:text-black focus:shadow-lg"
    >
      Skip to content
    </a>
  );

  if (isDesktop) {
    return (
      <>
        {skipLink}
        <aside className="sticky top-0 z-30 h-screen w-[248px] shrink-0 border-r border-[var(--claw-border)] bg-[var(--claw-sidebar)]">
          <SidebarBody
            gatewayHref={gatewayHref}
            initials={initials}
            user={user}
            onLogout={handleLogout}
          />
        </aside>
      </>
    );
  }

  // ── Mobile ────────────────────────────────────────────────────────────
  return (
    <>
      {skipLink}
      <header className="fixed top-0 left-0 right-0 z-40 h-12 flex items-center gap-2 px-3 border-b border-[var(--claw-border)] bg-[var(--claw-sidebar)]/95 backdrop-blur md:hidden">
        <button
          type="button"
          aria-label="Open navigation menu"
          aria-expanded={drawerOpen}
          aria-controls="mobile-sidebar"
          onClick={() => setDrawerOpen(true)}
          className="p-3 -ml-1 rounded-md text-[var(--text-secondary)] hover:bg-[rgba(255,255,255,0.06)] flex items-center justify-center min-w-[44px] min-h-[44px]"
        >
          <Menu className="w-5 h-5" strokeWidth={1.75} aria-hidden />
        </button>
        <div className="flex items-center gap-2 min-w-0">
          <BrandLogo />
          <span className="text-[14px] font-semibold tracking-tight text-[var(--text-primary)] truncate font-mono">
            SentientAI
          </span>
        </div>
      </header>

      {drawerOpen && (
        <div
          className="fixed inset-0 z-50 md:hidden"
          role="dialog"
          aria-modal="true"
          aria-label="Navigation"
        >
          <button
            type="button"
            aria-label="Close navigation menu"
            onClick={() => setDrawerOpen(false)}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          />
          <aside
            id="mobile-sidebar"
            className="relative h-full w-[280px] max-w-[85vw] border-r border-[var(--claw-border)] bg-[var(--claw-sidebar)] shadow-2xl"
          >
            <SidebarBody
              gatewayHref={gatewayHref}
              initials={initials}
              user={user}
              onLogout={handleLogout}
              onNavigate={() => setDrawerOpen(false)}
              closeButton={
                <button
                  type="button"
                  aria-label="Close navigation menu"
                  onClick={() => setDrawerOpen(false)}
                  className="p-2 -mr-1 rounded-md text-[var(--text-muted)] hover:bg-[rgba(255,255,255,0.06)] hover:text-[var(--text-primary)] transition-colors min-w-[44px] min-h-[44px] flex items-center justify-center"
                >
                  <X className="w-5 h-5" strokeWidth={1.75} aria-hidden />
                </button>
              }
            />
          </aside>
        </div>
      )}
    </>
  );
}
