/**
 * Tests for Dashboard's token usage: they prove today's tokens appear as a stat card with an
 * estimated cost, the usage panel renders the by-model table, and a failed summary is named in the
 * load-error banner.
 *
 * Why it exists: Guards against a usage failure blanking the page or going unreported.
 */

import { render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { usageSummary } from "@/test/usage";

vi.mock("@/services/api", () => ({
  decideApproval: vi.fn(),
  getAuditLogs: vi.fn(async () => []),
  getAuditStats: vi.fn(async () => ({
    total_actions_24h: 3,
    blocked_24h: 1,
    approved_24h: 2,
    pending_approvals: 0,
    by_day: [],
  })),
  getConnectorHealth: vi.fn(async () => []),
  getConnectors: vi.fn(async () => []),
  getPendingApprovals: vi.fn(async () => []),
  getUsageSummary: vi.fn(async () => usageSummary()),
}));

import Dashboard from "@/pages/Dashboard";
import { getUsageSummary } from "@/services/api";
import { ThemeProvider } from "@/theme";

function renderDashboard() {
  return render(
    <ThemeProvider>
      <Dashboard />
    </ThemeProvider>,
  );
}

describe("Dashboard token usage", () => {
  beforeEach(() => {
    // recharts' ResponsiveContainer measures itself; jsdom has no observer.
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.mocked(getUsageSummary).mockImplementation(async () => usageSummary());
  });

  it("shows today's tokens as a stat card with an estimated cost", async () => {
    renderDashboard();
    const card = (await screen.findByText("Tokens today")).closest("div.rounded-\\[14px\\]");
    expect(card).not.toBeNull();
    expect(await within(card as HTMLElement).findByText("1,290")).toBeInTheDocument();
    expect(within(card as HTMLElement).getByText("Est. cost <$0.01")).toBeInTheDocument();
  });

  it("renders the usage panel with the by-model breakdown", async () => {
    renderDashboard();
    const panel = await screen.findByRole("region", { name: "Tokens & estimated cost" });
    expect(within(panel).getByText("Last 30 days")).toBeInTheDocument();
    expect(within(panel).getByRole("table")).toBeInTheDocument();
    expect(within(panel).getByText("gemini-2.5-flash")).toBeInTheDocument();
  });

  it("names usage in the load-error banner when the summary fails", async () => {
    vi.mocked(getUsageSummary).mockRejectedValue(new Error("boom"));
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      renderDashboard();
      expect(await screen.findByRole("alert")).toHaveTextContent("usage");
      expect(screen.getByText("Usage could not be loaded.")).toBeInTheDocument();
    } finally {
      quiet.mockRestore();
    }
  });
});
