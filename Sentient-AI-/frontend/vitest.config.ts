/**
 * Vitest configuration: the jsdom environment, the "@" alias, the setup file and the test-file
 * glob.
 *
 * Why it exists: Unit tests need jsdom, the alias and src/test/setup.ts but not the dev-server
 * proxy or the Tailwind plugin, so the test run has its own config; `restoreMocks` and
 * `unstubGlobals` keep one test's fetch/location stubs from leaking into the next.
 */

import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "path";

// Kept separate from vite.config.ts so the dev-server proxy and Tailwind
// plugin (neither of which a unit test needs) stay out of the test run.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
    // Tests replace `fetch` and `window.location`; without this a stub leaks
    // into every later test in the file.
    unstubGlobals: true,
  },
});
