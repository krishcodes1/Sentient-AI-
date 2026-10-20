/**
 * Vitest configuration: the jsdom environment, the "@" alias, the setup file and the test-file
 * glob.
 *
 * Why it exists: Unit tests need jsdom, the alias and src/test/setup.ts but not the dev-server
 * proxy or the Tailwind plugin, so the test run has its own config; `restoreMocks`, `mockReset`
 * and `unstubGlobals` keep one test's mocks and fetch/location stubs from leaking into the next.
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
    // Since vitest 4, restoreMocks only puts vi.spyOn spies back; mockReset
    // also returns every vi.fn (including those in vi.mock factories) to
    // the implementation it was created with and clears its calls, so a
    // mockResolvedValue from one test cannot answer for the next.
    restoreMocks: true,
    mockReset: true,
    // Above the async queries' 5 s wait (src/test/setup.ts), so a query that
    // times out reports its own error rather than a bare test timeout.
    testTimeout: 15000,
    // Tests replace `fetch` and `window.location`; without this a stub leaks
    // into every later test in the file.
    unstubGlobals: true,
    // Vitest 4 dropped `coverage.all`: with no include, only files a test
    // imports are reported, and a page no test touches would vanish from
    // the summary instead of counting as uncovered.
    coverage: {
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/test/setup.ts"],
    },
  },
});
