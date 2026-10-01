/**
 * Vitest setup file: jest-dom matchers, a matchMedia double for jsdom, a longer wait for the
 * async queries, and cleanup plus localStorage.clear() after each test.
 *
 * Why it exists: jsdom ships no matchMedia and RTL does not auto-clean with globals on, so every
 * suite would otherwise throw on mount or leak DOM and storage between tests; and a busy machine
 * (CI, or the backend suite running beside it) can take longer than RTL's default one second to
 * render what a findBy or waitFor waits for.
 */

import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// findBy* and waitFor give up after this long (RTL's default is 1000 ms).
// A passing wait returns as soon as its condition holds, so only a machine
// under load ever uses the extra time; it stays under the test timeout
// (vitest.config.ts) so a real failure still reports the query's error.
configure({ asyncUtilTimeout: 5000 });

// jsdom ships no matchMedia at all, so anything that asks about the
// viewport or a motion preference throws on mount. The double reports "no
// match", which is what every caller treats as its safe default (mobile
// layout, motion allowed) — tests that care override it per case.
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })) as unknown as typeof window.matchMedia;
}

// Vitest does not auto-cleanup when `globals: true` is combined with the
// modern RTL build, so unmount between tests to keep queries scoped to the
// component under test.
afterEach(() => {
  cleanup();
  localStorage.clear();
});
