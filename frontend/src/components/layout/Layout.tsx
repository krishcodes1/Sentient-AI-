import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

export default function Layout() {
  return (
    <div className="flex min-h-screen min-w-0 bg-[var(--bg-primary)]">
      <Sidebar />
      <main className="flex-1 min-w-0 ml-[260px] overflow-y-auto overflow-x-hidden px-6 py-8 md:px-10 md:py-10">
        <div className="mx-auto max-w-[1200px] w-full min-w-0">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
