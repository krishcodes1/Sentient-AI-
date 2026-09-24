import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

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
