/**
 * Tests for PurchaseApproval: they prove a browser.checkout card shows the amount, merchant, item
 * lines, card label and notice read from `_checkout`, renders the screenshot only from a base64
 * raster data URL, falls back sensibly when the notice or the whole block is missing, and that
 * Dashboard renders it — with Approve and Deny — in place of the JSON dump for a checkout.
 *
 * Why it exists: Guards against a purchase being approved from a wall of JSON, against a merchant
 * URL or an SVG reaching an <img>, and against the card's reserved block being shown raw.
 */

import { render, screen, within } from "@testing-library/react";
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
    pending_approvals: 1,
    by_day: [],
  })),
  getConnectorHealth: vi.fn(async () => []),
  getConnectors: vi.fn(async () => []),
  getPendingApprovals: vi.fn(async () => []),
  getUsageSummary: vi.fn(async () => usageSummary()),
}));

import PurchaseApproval from "@/components/PurchaseApproval";
import Dashboard from "@/pages/Dashboard";
import { getPendingApprovals } from "@/services/api";
import { ThemeProvider } from "@/theme";

const IMAGE = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";

function checkout(overrides: Partial<PendingApproval> = {}): PendingApproval {
  return {
    action_id: "a1",
    tool_name: "browser.checkout",
    reason: "Pay $23.40 to shop.example.com (2 items) with Visa ····4242",
    arguments: {
      merchant: "shop.example.com",
      amount: 23.4,
      note: "Two tickets for Friday",
      _checkout: {
        checkout_id: "ck1",
        origin: "https://shop.example.com",
        host: "shop.example.com",
        amount_usd: "23.40",
        currency: "USD",
        items: ["Concert ticket — $19.00", "Service fee — $4.40"],
        card_label: "Visa ····4242",
        outline: "9f2c1a",
        notice: PURCHASE_NOTICE,
      },
    },
    image: IMAGE,
    ...overrides,
  };
}

describe("PurchaseApproval", () => {
  it("shows the page's facts: amount, merchant, items, the card and the notice", () => {
    render(<PurchaseApproval approval={checkout()} />);
    expect(screen.getByText("$23.40")).toBeInTheDocument();
    expect(screen.getByText("shop.example.com")).toBeInTheDocument();
    expect(screen.getByText("Concert ticket — $19.00")).toBeInTheDocument();
    expect(screen.getByText("Service fee — $4.40")).toBeInTheDocument();
    expect(screen.getByText("Visa ····4242")).toBeInTheDocument();
    expect(screen.getByText(PURCHASE_NOTICE)).toBeInTheDocument();
    expect(screen.getByText(/Two tickets for Friday/)).toBeInTheDocument();
    // The reserved block is laid out as facts, never dumped raw.
    expect(screen.queryByText(/checkout_id|ck1|9f2c1a/)).not.toBeInTheDocument();
  });

  it("renders the screenshot from a base64 raster data URL", () => {
    render(<PurchaseApproval approval={checkout()} />);
    const img = screen.getByRole("img", { name: /checkout page on shop\.example\.com/ });
    expect(img).toHaveAttribute("src", IMAGE);
  });

  it("renders no image for a URL or a non-raster data URL, and says so", () => {
    const { rerender } = render(
      <PurchaseApproval approval={checkout({ image: "https://shop.example.com/receipt.png" })} />,
    );
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.getByText(/no screenshot came with this request/i)).toBeInTheDocument();

    rerender(<PurchaseApproval approval={checkout({ image: "data:image/svg+xml;base64,PHN2Zz4=" })} />);
    expect(screen.queryByRole("img")).not.toBeInTheDocument();

    rerender(<PurchaseApproval approval={checkout({ image: null })} />);
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.getByText("$23.40")).toBeInTheDocument();
  });

  it("falls back to the design's notice when the card carries none", () => {
    const args = checkout().arguments;
    const block = args._checkout as Record<string, unknown>;
    render(
      <PurchaseApproval
        approval={checkout({ arguments: { ...args, _checkout: { ...block, notice: "" } } })}
      />,
    );
    expect(screen.getByText(PURCHASE_NOTICE)).toBeInTheDocument();
  });

  it("says when the card has no page details instead of rendering blanks", () => {
    render(<PurchaseApproval approval={checkout({ arguments: { merchant: "shop.example.com" } })} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/no page details/i);
    expect(screen.queryByText("Pay")).not.toBeInTheDocument();
  });
});

describe("Dashboard purchase approval", () => {
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
    vi.mocked(getPendingApprovals).mockResolvedValue([checkout()]);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the purchase card with Approve and Deny, and no JSON of the reserved block", async () => {
    render(
      <ThemeProvider>
        <Dashboard />
      </ThemeProvider>,
    );
    const img = await screen.findByRole("img", { name: /checkout page on shop\.example\.com/ });
    const row = img.closest("div.rounded-\\[10px\\]") as HTMLElement | null;
    expect(row).not.toBeNull();
    const inRow = within(row as HTMLElement);
    expect(inRow.getByText("$23.40")).toBeInTheDocument();
    expect(inRow.getByText("Visa ····4242")).toBeInTheDocument();
    expect(inRow.getByText(PURCHASE_NOTICE)).toBeInTheDocument();
    expect(inRow.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(inRow.getByRole("button", { name: "Deny" })).toBeInTheDocument();
    expect(inRow.queryByText(/checkout_id/)).not.toBeInTheDocument();
    expect((row as HTMLElement).querySelector("pre")).toBeNull();
  });
});
