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
