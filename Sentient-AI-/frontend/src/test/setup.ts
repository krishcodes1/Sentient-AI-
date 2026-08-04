import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest does not auto-cleanup when `globals: true` is combined with the
// modern RTL build, so unmount between tests to keep queries scoped to the
// component under test.
afterEach(() => {
  cleanup();
  localStorage.clear();
});
