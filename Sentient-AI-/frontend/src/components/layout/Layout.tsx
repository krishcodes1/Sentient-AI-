import { useCallback, useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Menu } from "lucide-react";
import Sidebar from "./Sidebar";
import Brand, { Wordmark } from "@/components/Brand";
import { DESKTOP_QUERY, useMediaQuery } from "@/hooks/useMediaQuery";

export default function Layout() {
  const [drawerRequested, setDrawerRequested] = useState(false);
  const isDesktop = useMediaQuery(DESKTOP_QUERY, true);
  const location = useLocation();

  // Derived rather than stored: a window that grows past the breakpoint
  // turns the drawer back into a static column, and a stored "open" would
  // leave focus trapped in something that is no longer an overlay.
  const navOpen = drawerRequested && !isDesktop;

  const closeNav = useCallback(() => setDrawerRequested(false), []);

  // Navigating is the whole point of the drawer, so it closes behind the
  // reader rather than covering the page they just asked for. Adjusted
  // during render (React's "reset state when a prop changes" pattern) so the
  // new page never paints under a still-open drawer first. Any navigation
  // counts — a link, the back button, a redirect — so this cannot live in
  // the links' click handlers alone.
  const [drawerPath, setDrawerPath] = useState(location.pathname);
  if (drawerPath !== location.pathname) {
    setDrawerPath(location.pathname);
    setDrawerRequested(false);
  }

  // The page behind an open drawer must not scroll under it.
  useEffect(() => {
    if (!navOpen) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, [navOpen]);

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-[70] focus:px-3 focus:py-2 focus:rounded-[10px] focus:text-sm focus:font-semibold"
        style={{ background: "var(--accent-primary)", color: "var(--text-on-accent)" }}
      >
        Skip to content
      </a>

      {/* Mobile chrome. Above 1024px the sidebar is a static column and this
          bar would only repeat what it already shows. */}
      <header
        className="lg:hidden fixed top-0 inset-x-0 z-30 flex items-center gap-3 px-4"
        style={{
          height: 56,
          background: "var(--claw-sidebar)",
          borderBottom: "1px solid var(--claw-border)",
        }}
      >
        <button
          type="button"
          onClick={() => setDrawerRequested(true)}
          aria-label="Open navigation"
          aria-expanded={navOpen}
          aria-controls="app-navigation"
          className="inline-flex items-center justify-center rounded-[10px]"
          style={{
            width: 44,
            height: 44,
            marginLeft: -10,
            color: "var(--text-primary)",
          }}
        >
          <Menu size={20} strokeWidth={1.75} aria-hidden />
        </button>
        <div className="flex items-center gap-2 min-w-0">
          <Brand size={26} variant="emblem" rounded={0} alt="" />
          <Wordmark height={14} />
        </div>
      </header>

      {navOpen && (
        <div className="app-scrim lg:hidden" onClick={closeNav} aria-hidden />
      )}

      <Sidebar open={navOpen} onClose={closeNav} isDrawer={!isDesktop} />

      <main id="main-content" className="app-main overflow-x-hidden">
        <Outlet />
      </main>
    </>
  );
}
