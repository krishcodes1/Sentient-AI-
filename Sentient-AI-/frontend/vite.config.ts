/**
 * Vite build and dev-server configuration: the React and Tailwind plugins, the "@" alias for src,
 * and the /api proxy.
 *
 * Why it exists: The dev server on port 3000 must forward /api to the backend (VITE_API_TARGET or
 * localhost:8000) so the app's same-origin /api calls work without CORS; `vite` and `vite build`
 * read it at startup.
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET || "http://localhost:8000",
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("error", (err) => {
            console.log("proxy error", err.message);
          });
        },
      },
    },
  },
});
