/**
 * Vite + Vitest configuration for the desktop app's setup window.
 *
 * Why it exists: Tauri serves this UI from the dev server in `tauri dev` (fixed port 5174, which
 * src-tauri/tauri.conf.json's devUrl points at) and from `dist/` in a release build. The build
 * settings follow Tauri's WebView targets (WKWebView on macOS, WebView2 on Windows) and keep every
 * asset a separate file, so the app's strict CSP (`default-src 'self'`) never meets an inline
 * data: URI. The `test` block runs the component tests in jsdom with the bridge mocked.
 */

/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const tauriPlatform = process.env.TAURI_ENV_PLATFORM;
const tauriDebug = !!process.env.TAURI_ENV_DEBUG;

export default defineConfig({
  plugins: [react()],
  // Keep Rust's compile output visible in `tauri dev`.
  clearScreen: false,
  server: {
    // tauri.conf.json's devUrl; the web frontend's dev server owns 5173.
    port: 5174,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    // WebView2 is Chromium 105+; macOS 10.15's WKWebView is Safari 13.
    target: tauriPlatform === "windows" ? "chrome105" : "safari13",
    minify: tauriDebug ? false : "esbuild",
    sourcemap: tauriDebug,
    // Never inline assets as data: URIs; the CSP only allows 'self'.
    assetsInlineLimit: 0,
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
