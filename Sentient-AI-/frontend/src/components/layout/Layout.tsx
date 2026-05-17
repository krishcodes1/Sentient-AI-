import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

export default function Layout() {
  // Sidebar is position: fixed (256px wide), so the main column just
  // needs a matching left margin. No flex wrapper required.
  return (
    <>
      <Sidebar />
      <main className="ml-64 min-h-screen p-6 overflow-x-hidden">
        <Outlet />
      </main>
    </>
  );
}
