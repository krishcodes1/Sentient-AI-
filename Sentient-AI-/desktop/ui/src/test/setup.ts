/**
 * Vitest setup: jest-dom matchers and a clean DOM between tests.
 *
 * Why it exists: Every component test uses matchers such as toBeDisabled / toHaveTextContent,
 * and each test must start from an empty document with no leftover mounted screens (whose
 * timers or subscriptions would otherwise keep running into the next test).
 */

import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});
