/**
 * Tests for Dashboard's approval rows on the way to a purchase: a browser.act row is its one
 * sentence (no JSON of refs or typed text) with the picture of the page, a normal purchase row carries no risk warning, and
 * approving shows the confirmation picture the decision brings back.
 *
 * Why it exists: The queue printed `{"action": "fill", "ref": "e7", "text": …}` under every
 * browser.act row and a red "Risk warning" on every real purchase; and the confirmation page of
 * an approved checkout had nowhere to appear, since the dashboard has no transcript.
 */

import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PendingApproval } from "@/types";
import { PURCHASE_NOTICE } from "@/pages/purchaseNotice";
import { usageSummary } from "@/test/usage";

vi.mock("@/services/api", () => ({
  decideApproval: vi.fn(),
  getAuditLogs: vi.fn(async () => []),
  getAuditStats: vi.fn(async () => ({
    total_actions_24h: 0,
    blocked_24h: 0,
    approved_24h: 0,
    pending_approvals: 2,
    by_day: [],
  })),
  getConnectorHealth: vi.fn(async () => []),
  getConnectors: vi.fn(async () => []),
  getPendingApprovals: vi.fn(async () => []),
  getUsageSummary: vi.fn(async () => usageSummary()),
}));

import Dashboard from "@/pages/Dashboard";
import { decideApproval, getPendingApprovals } from "@/services/api";
import { ThemeProvider } from "@/theme";

const SHOT = `data:image/jpeg;base64,${"/9j/".repeat(40)}`;

// The shapes the backend produces for the two cards.
const ACT: PendingApproval = {
  action_id: "a0",
  tool_name: "browser.act",
  reason: 'Type 17 characters into "Email" on tickets.example.com',
  arguments: {
    action: "fill",
    ref: "e7",
    text: "krish@example.com",
    _page: { origin: "https://tickets.example.com", outline: "9f2c1a" },
  },
  expires_at: new Date(Date.now() + 600_000).toISOString(),
};

const CHECKOUT: PendingApproval = {
  action_id: "a1",
  tool_name: "browser.checkout",
  reason: "Pay $5.00 to tickets.example.com (1 item) with Visa ····4242",
  arguments: {
    merchant: "tickets.example.com",
    amount: "5.00",
    _checkout: {
      checkout_id: "ck1",
      origin: "https://tickets.example.com",
      host: "tickets.example.com",
      amount_usd: "5.00",
      currency: "USD",
      items: ["General admission — $5.00"],
      card_label: "Visa ····4242",
      outline: "9f2c1a",
      notice: PURCHASE_NOTICE,
    },
  },
  image: "data:image/jpeg;base64,/9j/4AAQSkZJRg==",
  expires_at: new Date(Date.now() + 600_000).toISOString(),
};

function renderDashboard() {
  return render(
    <ThemeProvider>
      <Dashboard />
    </ThemeProvider>,
  );
}

describe("Dashboard approval rows of a ticket purchase", () => {
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
    vi.mocked(getPendingApprovals).mockResolvedValue([ACT, CHECKOUT]);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows plain sentences: no JSON, no typed text, no security jargon", async () => {
    renderDashboard();
    expect(await screen.findByText(PURCHASE_NOTICE)).toBeInTheDocument();
    expect(screen.getByText(ACT.reason)).toBeInTheDocument();
    expect(document.querySelectorAll("pre")).toHaveLength(0);
    expect(document.body.textContent).not.toContain("krish@example.com");
    expect(document.body.textContent).not.toContain('"ref"');
    expect(screen.queryByText("Risk warning")).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Approve" })).toHaveLength(2);
  });

  it("shows a browser.act row with the picture of the page it will run on", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([{ ...ACT, image: SHOT }]);
    renderDashboard();
    expect(await screen.findByText(ACT.reason)).toBeInTheDocument();
    const img = screen.getByRole("img", {
      name: "The page this step will run on, with its target outlined in red",
    });
    expect(img).toHaveAttribute("src", SHOT);
  });

  it("shows the confirmation picture an approved purchase brings back", async () => {
    vi.mocked(decideApproval).mockResolvedValue({
      action_id: "a1",
      approved: true,
      images: [{ tool: "browser.checkout", source: "tickets.example.com", index: 0, data_url: SHOT }],
      message_id: "m9",
    });
    renderDashboard();
    await screen.findByText(PURCHASE_NOTICE);
    const [, approvePurchase] = screen.getAllByRole("button", { name: "Approve" });
    fireEvent.click(approvePurchase);

    const img = await screen.findByRole("img", {
      name: "Screenshot of tickets.example.com (browser.checkout)",
    });
    expect(img).toHaveAttribute("src", SHOT);
    expect(screen.getByText("After your approval")).toBeInTheDocument();
    expect(decideApproval).toHaveBeenCalledWith("a1", true);
  });
});
