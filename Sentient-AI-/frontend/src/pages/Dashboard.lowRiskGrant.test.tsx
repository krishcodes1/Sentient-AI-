/**
 * Tests for the low-risk button on Dashboard's approval rows: a row the server offers a low-risk
 * grant for gets "Allow low-risk changes on <account> for 7 days"; pressing it approves with
 * remember "low_risk", removes the row and says until when the account is allowed; a row without
 * `low_risk_account` has no such button.
 *
 * Why it exists: the Dashboard's queue is the other place the owner decides cards on the web, so
 * it must offer the same choice in the same words as Chat, and only on the rows it was offered for.
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

const UNTIL = "2026-10-07T15:14:00Z";
const ALLOW = "Allow low-risk changes on School Gmail for 7 days";

const STAR: PendingApproval = {
  action_id: "a9",
  tool_name: "google_workspace.modify_labels",
  reason: "Tool 'google_workspace.modify_labels' requires explicit user approval",
  arguments: { message_id: "m1", add_label_ids: ["STARRED"] },
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  low_risk_account: "School Gmail",
};

function renderDashboard() {
  return render(
    <ThemeProvider>
      <Dashboard />
    </ThemeProvider>,
  );
}

describe("Dashboard's low-risk button on an approval row", () => {
  beforeEach(() => {
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

  it("offers the row's account and, pressed, allows it and removes the row", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([STAR]);
    renderDashboard();

    const allow = await screen.findByRole("button", { name: ALLOW });
    vi.mocked(decideApproval).mockResolvedValue({
      action_id: "a9",
      approved: true,
      result: { ok: true },
      low_risk: { account: "School Gmail", expires_at: UNTIL },
    });
    vi.mocked(getPendingApprovals).mockResolvedValue([]);
    fireEvent.click(allow);

    expect(
      await screen.findByText(
        `Low-risk changes on School Gmail are allowed until ${formatAllowedUntil(UNTIL)}.`,
      ),
    ).toBeInTheDocument();
    expect(vi.mocked(decideApproval).mock.calls).toEqual([["a9", true, "low_risk"]]);
    await waitFor(() => expect(screen.queryByRole("button", { name: ALLOW })).not.toBeInTheDocument());
  });

  it("gives a row without low_risk_account no low-risk button", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([{ ...STAR, action_id: "a10", low_risk_account: null }]);
    renderDashboard();

    await screen.findByRole("button", { name: "Approve" });
    expect(screen.queryByRole("button", { name: /low-risk/ })).not.toBeInTheDocument();
  });
});
