import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

export default function Layout() {
  return (
    <>
      <Sidebar />
      <main
        className="min-h-screen p-6 overflow-x-hidden"
        style={{ marginLeft: 248 }}
      >
        <Outlet />
      </main>
    </>
  );
}
