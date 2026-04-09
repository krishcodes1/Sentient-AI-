import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";
import LayoutFull from "./components/layout/LayoutFull";
import Dashboard from "./pages/Dashboard";
import Gateway from "./pages/Gateway";
import Chat from "./pages/Chat";
import Channels from "./pages/Channels";
import AuditLogs from "./pages/AuditLogs";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import Onboarding from "./pages/Onboarding";
import { getStoredUser } from "./services/api";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem("auth_token");
  if (!token) return <Navigate to="/login" replace />;

  const user = getStoredUser();
  if (user && !user.onboarding_completed) {
    return <Navigate to="/onboarding" replace />;
  }

  return <>{children}</>;
}

function OnboardingGuard({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem("auth_token");
  if (!token) return <Navigate to="/login" replace />;

  const user = getStoredUser();
  if (user && user.onboarding_completed) {
    return <Navigate to="/gateway" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/onboarding"
        element={
          <OnboardingGuard>
            <Onboarding />
          </OnboardingGuard>
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Navigate to="/gateway" replace />
          </ProtectedRoute>
        }
      />
      <Route
        element={
          <ProtectedRoute>
            <LayoutFull />
          </ProtectedRoute>
        }
      >
        <Route path="/gateway" element={<Gateway />} />
      </Route>
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route path="/overview" element={<Dashboard />} />
        <Route path="/chat" element={<Chat />} />
        <Route path="/channels" element={<Channels />} />
        <Route path="/audit" element={<AuditLogs />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
