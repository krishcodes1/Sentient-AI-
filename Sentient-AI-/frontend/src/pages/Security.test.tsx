/**
 * Tests for the Security page shell: they prove the owner sees every tab in the registry's order,
 * a member never sees or mounts the owner-only tabs (not even when ?tab= names one), ?tab= opens a
 * visible tab and anything else falls back to the first, a tab's openTab switches the tab and the
 * query, a failed account load shows the error with Retry, and the tablist scrolls inside itself
 * with the open tab brought into view.
 *
 * Why it exists: nine skills each fill one tab later, and the shell is the only thing that decides
 * who sees which. An owner-only tab mounted for a member would make owner-only requests from their
 * browser, and a wrong ?tab= rule would break every "/security?tab=..." link the app sends.
 * Every tab module is mocked, so these tests stay true whatever the tabs become.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { User } from "@/types";

const { mounted, stubTab } = vi.hoisted(() => {
  // Every id a mocked tab rendered for, in order, so a test can prove one never mounted.
  const mounted: string[] = [];
  const stubTab = (id: string) => async () => {
    const { createElement } = await import("react");
    return {
      default: (props: { isOwner?: boolean; onOpenKeys?: () => void }) => {
        mounted.push(id);
        return createElement(
          "div",
          null,
          createElement("p", null, `${id} tab body (owner: ${String(props.isOwner ?? "n/a")})`),
          props.onOpenKeys
            ? createElement("button", { type: "button", onClick: props.onOpenKeys }, `Open keys from ${id}`)
            : null,
        );
      },
    };
  };
  return { mounted, stubTab };
});

vi.mock("@/pages/security/MailAlertsTab", stubTab("mail"));
vi.mock("@/pages/security/ScamCheckTab", stubTab("scam-check"));
vi.mock("@/pages/security/OutgoingMessagesTab", stubTab("outgoing"));
vi.mock("@/pages/security/FileChecksTab", stubTab("files"));
vi.mock("@/pages/security/BreachMonitorTab", stubTab("breach"));
vi.mock("@/pages/security/McpReviewsTab", stubTab("mcp"));
vi.mock("@/pages/security/SiteRulesTab", stubTab("site-rules"));
vi.mock("@/pages/security/ToolRulesTab", stubTab("tool-rules"));
vi.mock("@/pages/security/ServiceKeysTab", stubTab("keys"));

vi.mock("@/services/api", () => {
  class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
      this.name = "ApiError";
    }
  }
  return { ApiError, getMe: vi.fn() };
});

import Security from "@/pages/Security";
import { SECURITY_TABS } from "@/pages/security/tabs";
import { ApiError, getMe } from "@/services/api";

const OWNER_ONLY = ["site-rules", "tool-rules", "keys"];

function viewer(isAdmin: boolean): User {
  return {
    id: isAdmin ? "owner" : "member",
    email: isAdmin ? "owner@example.com" : "member@example.com",
    name: null,
    is_admin: isAdmin,
    created_at: "2026-10-14T12:00:00Z",
    default_permission_tier: "user_confirm",
    rate_limit: 60,
  };
}

function LocationProbe() {
  const { search } = useLocation();
  return <output data-testid="search">{search}</output>;
}

async function renderSecurity(path: string, isAdmin: boolean) {
  mounted.length = 0;
  vi.mocked(getMe).mockResolvedValue(viewer(isAdmin));
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/security"
          element={
            <>
              <Security />
              <LocationProbe />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
  await screen.findAllByRole("tab");
}

const tabLabels = () => screen.getAllByRole("tab").map((tab) => tab.textContent);
const selectedTab = () => screen.getByRole("tab", { selected: true });

describe("Security page", () => {
  it("shows every tab to the owner in order", async () => {
    await renderSecurity("/security", true);

    expect(tabLabels()).toEqual(SECURITY_TABS.map((tab) => tab.label));
    expect(tabLabels()).toEqual([
      "Mail alerts",
      "Check for scams",
      "Outgoing messages",
      "File checks",
      "Breach monitor",
      "MCP reviews",
      "Site rules",
      "Tool rules",
      "Service keys",
    ]);
    expect(selectedTab()).toHaveTextContent("Mail alerts");
    expect(screen.getByRole("tabpanel", { name: "Mail alerts" })).toHaveTextContent(
      "mail tab body (owner: true)",
    );
  });

  it("hides the owner-only tabs from a member and never mounts them", async () => {
    // Even a link straight to an owner-only tab must not mount it for a member.
    await renderSecurity("/security?tab=keys", false);

    expect(tabLabels()).toEqual(
      SECURITY_TABS.filter((tab) => !tab.ownerOnly).map((tab) => tab.label),
    );
    expect(tabLabels()).not.toContain("Service keys");
    expect(selectedTab()).toHaveTextContent("Mail alerts");
    expect(screen.getByText("mail tab body (owner: false)")).toBeInTheDocument();

    for (const label of ["Check for scams", "Outgoing messages", "File checks", "Breach monitor", "MCP reviews"]) {
      fireEvent.click(screen.getByRole("tab", { name: label }));
    }
    await waitFor(() => expect(selectedTab()).toHaveTextContent("MCP reviews"));
    expect(mounted.some((id) => OWNER_ONLY.includes(id))).toBe(false);
  });

  it("opens the tab named in ?tab= when it is visible", async () => {
    await renderSecurity("/security?tab=mcp", true);

    expect(selectedTab()).toHaveTextContent("MCP reviews");
    expect(screen.getByRole("tabpanel", { name: "MCP reviews" })).toHaveTextContent("mcp tab body");
    expect(mounted).not.toContain("mail");
  });

  it("falls back to the first tab for an unknown or hidden tab", async () => {
    await renderSecurity("/security?tab=nothing-like-this", true);
    expect(selectedTab()).toHaveTextContent("Mail alerts");
  });

  it("falls back to the first tab when a member opens an owner-only tab's link", async () => {
    await renderSecurity("/security?tab=tool-rules", false);
    expect(selectedTab()).toHaveTextContent("Mail alerts");
    expect(mounted).not.toContain("tool-rules");
  });

  it("openTab switches the tab and the query", async () => {
    await renderSecurity("/security?tab=scam-check", true);

    // A tab asks for another one (a missing key opens Service keys) through openTab.
    fireEvent.click(screen.getByRole("button", { name: "Open keys from scam-check" }));
    await waitFor(() => expect(selectedTab()).toHaveTextContent("Service keys"));
    expect(screen.getByTestId("search")).toHaveTextContent("?tab=keys");
    expect(screen.getByRole("tabpanel", { name: "Service keys" })).toHaveTextContent("keys tab body");

    // Clicking a tab does the same.
    fireEvent.click(screen.getByRole("tab", { name: "File checks" }));
    await waitFor(() => expect(selectedTab()).toHaveTextContent("File checks"));
    expect(screen.getByTestId("search")).toHaveTextContent("?tab=files");
  });

  it("moves between tabs with the arrow keys, Home and End", async () => {
    await renderSecurity("/security", true);
    const tablist = screen.getByRole("tablist");

    fireEvent.keyDown(tablist, { key: "ArrowRight" });
    await waitFor(() => expect(selectedTab()).toHaveTextContent("Check for scams"));
    expect(selectedTab()).toHaveFocus();

    fireEvent.keyDown(tablist, { key: "End" });
    await waitFor(() => expect(selectedTab()).toHaveTextContent("Service keys"));

    fireEvent.keyDown(tablist, { key: "ArrowRight" });
    await waitFor(() => expect(selectedTab()).toHaveTextContent("Mail alerts"));

    fireEvent.keyDown(tablist, { key: "ArrowLeft" });
    await waitFor(() => expect(selectedTab()).toHaveTextContent("Service keys"));

    fireEvent.keyDown(tablist, { key: "Home" });
    await waitFor(() => expect(selectedTab()).toHaveTextContent("Mail alerts"));
    // Only the open tab is in the Tab order; the arrows reach the rest.
    expect(screen.getAllByRole("tab").filter((tab) => tab.tabIndex === 0)).toHaveLength(1);
  });

  it("a failed getMe shows the error with Retry", async () => {
    mounted.length = 0;
    vi.mocked(getMe)
      .mockRejectedValueOnce(new ApiError("The server is not answering.", 503))
      .mockResolvedValueOnce(viewer(true));
    render(
      <MemoryRouter initialEntries={["/security"]}>
        <Routes>
          <Route path="/security" element={<Security />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("The server is not answering.");
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(mounted).toEqual([]);

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findAllByRole("tab")).toHaveLength(SECURITY_TABS.length);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(getMe).toHaveBeenCalledTimes(2);
  });

  it("the tablist scrolls inside itself so nine tabs never widen the page", async () => {
    const scrolled: string[] = [];
    const proto = HTMLElement.prototype as unknown as { scrollIntoView?: (arg?: unknown) => void };
    const original = proto.scrollIntoView;
    proto.scrollIntoView = function (this: HTMLElement) {
      scrolled.push(this.textContent ?? "");
    };
    try {
      await renderSecurity("/security?tab=keys", true);

      const tablist = screen.getByRole("tablist");
      expect(tablist).toHaveClass("flex", "overflow-x-auto", "whitespace-nowrap");
      for (const tab of screen.getAllByRole("tab")) expect(tab).toHaveClass("shrink-0");
      // ?tab=keys still selects the last tab, and that tab is scrolled into view.
      expect(selectedTab()).toHaveTextContent("Service keys");
      const tabs = screen.getAllByRole("tab");
      expect(tabs[tabs.length - 1]).toBe(selectedTab());
      await waitFor(() => expect(scrolled).toContain("Service keys"));
    } finally {
      if (original) proto.scrollIntoView = original;
      else delete proto.scrollIntoView;
    }
  });
});
