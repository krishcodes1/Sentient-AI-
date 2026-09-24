import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";

export default tseslint.config(
  {
    // `.claude/` holds nested agent worktrees — whole copies of this repo,
    // built `dist/` bundles and all. Linting them would report thousands of
    // problems from minified vendor code that does not exist in source.
    ignores: [
      "dist/**",
      "node_modules/**",
      "coverage/**",
      ".claude/**",
      "*.tsbuildinfo",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.browser, ...globals.es2022 },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
      // The React Compiler ships these as errors in the "recommended" preset,
      // but they flag idiomatic-but-not-compilable patterns rather than bugs
      // (reading refs during render for one-shot guards, mutating a local
      // draft object). Downgraded to warnings so `lint` stays a real gate for
      // correctness rules instead of failing on style-of-memoization.
      "react-hooks/refs": "warn",
      "react-hooks/purity": "warn",
      "react-hooks/immutability": "warn",
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/static-components": "warn",
      "react-hooks/preserve-manual-memoization": "warn",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // A warning, like the react-hooks rules above; CI runs with
      // --max-warnings 0, so a new `any` in app code still fails the build.
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },
  {
    // Config files run in Node, not the browser.
    files: ["*.config.{js,ts}", "vite.config.ts", "vitest.config.ts"],
    languageOptions: { globals: globals.node },
  },
  {
    // Tests deliberately reach for `any` when forging DOM/stream doubles and
    // import Vitest's globals implicitly.
    files: ["src/**/*.test.{ts,tsx}", "src/test/**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "react-refresh/only-export-components": "off",
    },
  },
);
