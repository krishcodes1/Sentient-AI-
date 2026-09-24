import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import ThemeToggle from "@/components/ThemeToggle";
import { THEME_STORAGE_KEY, ThemeProvider, useTheme } from "@/theme";

/**
 * The theme is the one preference this app persists on the device, and it is
 * read back by two places that cannot see each other: the stylesheet (via
 * the data-theme attribute) and the inline bootstrap in index.html (via
 * localStorage). These tests pin both, plus the private-window case where
 * localStorage throws on every access — the app has to keep rendering.
 */

/**
 * A matchMedia double whose "(prefers-color-scheme: dark)" answer is ours,
 * and can change the way a real OS preference does. The value is read from
 * mutable state rather than captured, because the hook re-reads `matches`
 * after each notification rather than trusting the event.
 */
function stubMatchMedia(prefersDark: boolean) {
  const state = { dark: prefersDark };
  const listeners = new Set<() => void>();
  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => ({
      media: query,
      matches: query.includes("prefers-color-scheme: dark") ? state.dark : false,
      onchange: null,
      addEventListener: (_: string, fn: () => void) => listeners.add(fn),
      removeEventListener: (_: string, fn: () => void) => listeners.delete(fn),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  );
  return {
    setDark(next: boolean) {
      state.dark = next;
      for (const notify of listeners) notify();
    },
  };
}

function renderToggle() {
  return render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  );
}

const option = (name: string) => screen.getByRole("radio", { name });
const root = () => document.documentElement;

afterEach(() => {
  root().removeAttribute("data-theme");
});

describe("theme", () => {
  it("follows the OS out of the box and writes no attribute", () => {
    stubMatchMedia(true);
    renderToggle();

    // No data-theme at all: the stylesheet's light-dark() pairs then resolve
    // from the OS. Writing "system" here would pin color-scheme to a literal
    // that means nothing to CSS.
    expect(root()).not.toHaveAttribute("data-theme");
    expect(option("System")).toBeChecked();
  });

  it("pins the theme and persists it when a mode is chosen", async () => {
    stubMatchMedia(true);
    const user = userEvent.setup();
    renderToggle();

    await user.click(option("Light"));

    expect(root()).toHaveAttribute("data-theme", "light");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(option("Light")).toBeChecked();
    expect(option("System")).not.toBeChecked();
  });

  it("restores a previously chosen theme on the next visit", () => {
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    stubMatchMedia(false); // the OS disagrees — the saved choice still wins

    renderToggle();

    expect(root()).toHaveAttribute("data-theme", "dark");
    expect(option("Dark")).toBeChecked();
  });

  it("hands the decision back to the OS when System is re-selected", async () => {
    localStorage.setItem(THEME_STORAGE_KEY, "light");
    stubMatchMedia(true);
    const user = userEvent.setup();
    renderToggle();

    await user.click(option("System"));

    expect(root()).not.toHaveAttribute("data-theme");
    // Removed rather than stored as "system": a later visit must not see a
    // stale pin, and the inline bootstrap only understands light/dark.
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
  });

  it("migrates a theme saved under the pre-rename key", () => {
    localStorage.setItem("sentientai_theme", "dark");
    stubMatchMedia(true); // the OS disagrees — the legacy choice still wins

    renderToggle();

    expect(root()).toHaveAttribute("data-theme", "dark");
    expect(option("Dark")).toBeChecked();
    // Migrated onto the new key and the old one cleaned up, so a later
    // read never has to consult the legacy key again.
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(localStorage.getItem("sentientai_theme")).toBeNull();
  });

  it("ignores a stored value that is not a theme", () => {
    localStorage.setItem(THEME_STORAGE_KEY, "solarized");
    stubMatchMedia(false);

    renderToggle();

    expect(root()).not.toHaveAttribute("data-theme");
    expect(option("System")).toBeChecked();
  });

  it("still renders and switches when localStorage throws", async () => {
    // A private window with site data blocked throws on read *and* write.
    // Losing the preference is acceptable; failing to render is not.
    const getItem = vi
      .spyOn(Storage.prototype, "getItem")
      .mockImplementation(() => {
        throw new DOMException("denied", "SecurityError");
      });
    const setItem = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new DOMException("denied", "SecurityError");
      });
    stubMatchMedia(true);
    const user = userEvent.setup();

    renderToggle();
    expect(option("System")).toBeChecked();

    await user.click(option("Dark"));

    expect(root()).toHaveAttribute("data-theme", "dark");
    expect(option("Dark")).toBeChecked();

    getItem.mockRestore();
    setItem.mockRestore();
  });

  it("tracks the OS while in system mode", () => {
    const os = stubMatchMedia(false);
    function Resolved() {
      return <span data-testid="resolved">{useTheme().resolved}</span>;
    }
    render(
      <ThemeProvider>
        <Resolved />
      </ThemeProvider>,
    );

    expect(screen.getByTestId("resolved")).toHaveTextContent("light");

    // The OS flipping to dark must reach the page without a reload.
    act(() => os.setDark(true));

    expect(screen.getByTestId("resolved")).toHaveTextContent("dark");
  });
});
