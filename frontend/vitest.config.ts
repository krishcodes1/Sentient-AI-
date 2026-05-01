/// <reference types="vitest" />
import { defineConfig, mergeConfig } from "vite";
import viteConfig from "./vite.config";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      globals: true,
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      css: false,
      coverage: {
        provider: "v8",
        reporter: ["text", "html"],
        exclude: ["node_modules", "dist", "**/*.config.*", "src/test/**"],
      },
    },
  }),
);
