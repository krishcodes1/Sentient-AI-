import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Layout from "@/components/layout/Layout";
import { ThemeProvider } from "@/theme";

vi.mock("@/services/api", () => ({
  getMe: vi.fn(async () => ({
    id: "u1",
    email: "krish@example.com",
    name: "Krish",
    created_at: "2026-01-01T00:00:00Z",
    default_permission_tier: "user_confirm",
    rate_limit: 60,
  })),
  logout: vi.fn(),
}));

/**
 * Below 1024px the sidebar is an overlay, and everything that makes an
 * overlay usable has to come with it: a way in, a way out, focus that stays
 * inside while it is open, and no page scrolling underneath. Above 1024px
 * none of that applies and the same markup has to behave like a plain
 * column — including staying reachable when the drawer is "closed".
 */
function setViewport(desktop: boolean) {
  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => ({
      media: query,
      matches: query.includes("min-width: 1024px") ? desktop : false,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  );
}

/**
 * Renders and waits for Sidebar's getMe() to land, so no state update
 * escapes the test body.
 */
async function renderApp(initialPath = "/") {
  const utils = render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<h1>Gateway page</h1>} />
            <Route path="/chat" element={<h1>Chat page</h1>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </ThemeProvider>,
  );
  await screen.findByText("Krish");
  return utils;
}

// The drawer is an <aside> that becomes a dialog while it overlays the
// page, so its role is not stable across breakpoints — its label is.
const drawer = () => screen.getByLabelText("Sidebar");
const openButton = () => screen.getByRole("button", { name: "Open navigation" });

beforeEach(() => {
  document.body.style.overflow = "";
});

describe("Layout on a phone", () => {
  beforeEach(() => setViewport(false));

  it("starts with the drawer closed and out of the way", async () => {
    await renderApp();

    expect(drawer()).toHaveAttribute("data-open", "false");
    expect(openButton()).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("main")).toBeInTheDocument();
  });

  it("opens the drawer as a modal dialog and locks the page behind it", async () => {
    const user = userEvent.setup();
    await renderApp();

    await user.click(openButton());

    const panel = screen.getByRole("dialog", { name: "Sidebar" });
    expect(panel).toHaveAttribute("data-open", "true");
    expect(panel).toHaveAttribute("aria-modal", "true");
    expect(document.body.style.overflow).toBe("hidden");
  });

  it("closes on the close button, on Escape, and restores page scrolling", async () => {
    const user = userEvent.setup();
    await renderApp();

    await user.click(openButton());
    await user.click(screen.getByRole("button", { name: "Close navigation" }));

    expect(drawer()).toHaveAttribute("data-open", "false");
    expect(document.body.style.overflow).not.toBe("hidden");

    await user.click(openButton());
    await user.keyboard("{Escape}");

    expect(drawer()).toHaveAttribute("data-open", "false");
  });

  it("moves focus into the drawer and gives it back on close", async () => {
    const user = userEvent.setup();
    await renderApp();

    const opener = openButton();
    await user.click(opener);
    await waitFor(() =>
      expect(
        screen.getByRole("dialog", { name: "Sidebar" }),
      ).toContainElement(document.activeElement as HTMLElement),
    );

    await user.keyboard("{Escape}");

    // Without this the next Tab restarts from the top of the document, with
    // no indication of where the reader had got to.
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("closes itself once the reader has navigated", async () => {
    const user = userEvent.setup();
    await renderApp();

    await user.click(openButton());
    await user.click(screen.getByRole("link", { name: "Chat" }));

    expect(await screen.findByText("Chat page")).toBeInTheDocument();
    expect(drawer()).toHaveAttribute("data-open", "false");
  });
});

describe("Layout on a desktop", () => {
  beforeEach(() => setViewport(true));

  it("shows the sidebar as a plain landmark with no hamburger chrome", async () => {
    await renderApp();

    // data-open stays false — above the breakpoint the stylesheet, not this
    // attribute, is what puts the column on screen.
    expect(drawer()).toHaveAttribute("data-open", "false");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(document.body.style.overflow).not.toBe("hidden");
  });

  it("keeps every navigation link reachable", async () => {
    await renderApp();

    for (const label of [
      "Gateway",
      "Chat",
      "Memory",
      "Connectors",
      "Audit logs",
      "Settings",
    ]) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });
});
