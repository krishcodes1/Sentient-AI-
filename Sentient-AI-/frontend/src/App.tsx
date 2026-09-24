/**
 * The route table: lazy-loaded pages, the ProtectedRoute wrapper, and the SetupGate that sends
 * every page to /setup until first-run setup is finished.
 *
 * Why it exists: Pages are code-split here so the initial bundle stays small, and the gate lives
 * above the routes so no page has to check the setup status itself; main.tsx renders it inside the
 * router.
 */

import { lazy, Suspense, useEffect, useState } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { getSetupStatus } from "@/services/api";
import Layout from "./components/layout/Layout";
import Login from "./pages/Login";

// Pages are code-split so the initial bundle stays small — recharts alone
// (Dashboard) is several hundred KB. Login stays eager: it is the first
// screen logged-out users see and is tiny.
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Chat = lazy(() => import("./pages/Chat"));
const Connectors = lazy(() => import("./pages/Connectors"));
const AuditLogs = lazy(() => import("./pages/AuditLogs"));
const Settings = lazy(() => import("./pages/Settings"));
const MemoryPage = lazy(() => import("./pages/Memory"));
// Seen once per install, so it never belongs in the main bundle.
const Setup = lazy(() => import("./pages/Setup"));

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem("auth_token");
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function RouteFallback() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <Loader2
        className="w-6 h-6 animate-spin"
        style={{ color: "var(--text-muted)" }}
      />
    </div>
  );
}

type GateState =
  | { kind: "unknown" }
  | { kind: "needs"; hasOwner: boolean }
  | { kind: "done" };

/**
 * Until first-run setup is finished, every page redirects to /setup.
 *
 * The status is asked once per full page load; the wizard ends with a full
 * reload, which is what asks again. /login stays reachable once an owner
 * exists, so an owner whose session ended mid-setup can sign back in.
 *
 * This is a convenience for the browser, not a security boundary, so a
 * failed check lets the app through rather than locking it behind a spinner
 * (an older server has no /setup/status at all).
 */
function SetupGate({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<GateState>({ kind: "unknown" });
  const { pathname } = useLocation();

  useEffect(() => {
    let cancelled = false;
    getSetupStatus()
      .then((s) => {
        if (cancelled) return;
        setState(s.needs_setup ? { kind: "needs", hasOwner: s.has_owner } : { kind: "done" });
      })
      .catch(() => {
        if (!cancelled) setState({ kind: "done" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.kind === "unknown") return <RouteFallback />;
  if (
    state.kind === "needs" &&
    pathname !== "/setup" &&
    !(state.hasOwner && pathname === "/login")
  ) {
    return <Navigate to="/setup" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <SetupGate>
        <Routes>
          {/* Outside ProtectedRoute: its first step runs with no session. */}
          <Route path="/setup" element={<Setup />} />
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route path="/" element={<Dashboard />} />
            <Route path="/chat" element={<Chat />} />
            <Route path="/memory" element={<MemoryPage />} />
            <Route path="/connectors" element={<Connectors />} />
            <Route path="/audit" element={<AuditLogs />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </SetupGate>
    </Suspense>
  );
}
