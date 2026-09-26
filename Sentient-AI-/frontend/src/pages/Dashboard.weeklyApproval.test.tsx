/**
 * Tests for the weekly button on Dashboard's approval rows: a desktop.act row the server offers for
 * a week gets "Allow Calendar for 7 days" with its helper line; pressing it approves with remember
 * "week", removes the row as Approve does and says until when the app is allowed; and a row
 * without `weekly_app` has no third button while its Approve posts what it always did.
 *
 * Why it exists: The Dashboard's queue is the other place the owner decides cards on the web, so it
 * must offer the same choice in the same words as Chat, and only on the rows it was offered for.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PendingApproval } from "@/types";
import { usageSummary } from "@/test/usage";

vi.mock("@/services/api", () => ({
  decideApproval: vi.fn(),
  getAuditLogs: vi.fn(async () => []),
  getAuditStats: vi.fn(async () => ({
    total_actions_24h: 0,
    blocked_24h: 0,
    approved_24h: 0,
    pending_approvals: 1,
    by_day: [],
  })),
  getConnectorHealth: vi.fn(async () => []),
  getConnectors: vi.fn(async () => []),
  getPendingApprovals: vi.fn(async () => []),
  getUsageSummary: vi.fn(async () => usageSummary()),
}));

import Dashboard from "@/pages/Dashboard";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import { decideApproval, getPendingApprovals } from "@/services/api";
import { ThemeProvider } from "@/theme";

const UNTIL = "2026-10-02T15:14:00Z";
const ALLOW = "Allow Calendar for 7 days";
const HELPER =
  "Crawler then acts in Calendar without asking, for requests from this browser, for 7 days. Revoke in Settings.";

// A desktop.act card as the backend parks it, offered for a week.
const CALENDAR: PendingApproval = {
  action_id: "a7",
  tool_name: "desktop.act",
  reason: 'Click "Month" in Calendar',
  arguments: { action: "click", ref: "e12", _screen: { app: "Calendar", outline: "4be1c2" } },
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  weekly_app: "Calendar",
};

function renderDashboard() {
  return render(
    <ThemeProvider>
      <Dashboard />
    </ThemeProvider>,
  );
}

describe("Dashboard's weekly button on an approval row", () => {
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
  });

  it("offers the row's app for a week and, pressed, allows it and removes the row", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([CALENDAR]);
    renderDashboard();

    const allow = await screen.findByRole("button", { name: ALLOW });
    expect(screen.getByText(HELPER)).toBeInTheDocument();

    vi.mocked(decideApproval).mockResolvedValue({
      action_id: "a7",
      approved: true,
      result: { ok: true },
      weekly: { app: "Calendar", expires_at: UNTIL },
    });
    // The server no longer lists a decided card, so the refresh after the decision drops it.
    vi.mocked(getPendingApprovals).mockResolvedValue([]);
    fireEvent.click(allow);

    expect(
      await screen.findByText(`Calendar is allowed until ${formatAllowedUntil(UNTIL)}.`),
    ).toBeInTheDocument();
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["a7", true, "week"]]);
    await waitFor(() => expect(screen.queryByRole("button", { name: ALLOW })).not.toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
  });

  it("gives a row without weekly_app no third button, and its Approve posts what it always did", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([{ ...CALENDAR, action_id: "a8", weekly_app: null }]);
    vi.mocked(decideApproval).mockResolvedValue({ action_id: "a8", approved: true, weekly: null });
    renderDashboard();

    const approve = await screen.findByRole("button", { name: "Approve" });
    expect(screen.queryByRole("button", { name: /for 7 days/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/without asking/)).not.toBeInTheDocument();

    vi.mocked(getPendingApprovals).mockResolvedValue([]);
    fireEvent.click(approve);

    await waitFor(() => expect(vi.mocked(decideApproval).mock.calls).toEqual([["a8", true]]));
    expect(screen.queryByText(/is allowed until/)).not.toBeInTheDocument();
  });
});
