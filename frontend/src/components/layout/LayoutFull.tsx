import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

/** Shell for fullscreen embedded apps (OpenClaw Control UI): no max-width padding. */
export default function LayoutFull() {
  return (
    <div className="flex min-h-screen min-h-[100dvh] min-w-0 bg-[var(--bg-primary)]">
      <Sidebar />
      <main className="flex-1 min-w-0 min-h-0 flex flex-col overflow-hidden">
        <Outlet />
      </main>
    </div>
  );
}
