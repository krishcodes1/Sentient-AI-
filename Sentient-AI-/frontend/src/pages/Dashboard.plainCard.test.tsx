/**
 * Tests for the plain words on Dashboard's approval rows: a row reads like the chat's card, its
 * sentence first, then every value as a labelled row, "Okay to go ahead?" with the time left, the
 * buttons and the quiet check code, with the tool id and raw arguments only under a closed
 * "Technical details"; a row that ran out of time says so plainly.
 *
 * Why it exists: the row used to lead with the tool id in a mono tag and end with a JSON dump. The
 * Dashboard's queue is the other place the owner decides cards on the web, so it must use the same
 * words as Chat (docs/bot-message-style.md) and still show every value whole (spec F3).
 */

import { render, screen, within } from "@testing-library/react";
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
import { getPendingApprovals } from "@/services/api";
import { ThemeProvider } from "@/theme";

const BODY = "Hi Priya,\nare we still on for noon?";

const EMAIL: PendingApproval = {
  action_id: "a1",
  tool_name: "google_workspace.send_email",
  reason: "Send an email to priya@acme.com from your Gmail",
  arguments: { to: "priya@acme.com", subject: "Friday lunch", body: BODY },
  details: [
    { label: "To", value: "priya@acme.com" },
    { label: "Subject", value: "Friday lunch" },
    { label: "Message", value: BODY },
  ],
  check_code: "6d3b dfca 7bf8 cfc5",
  expires_at: new Date(Date.now() + 9 * 60_000 + 30_000).toISOString(),
};

function renderDashboard() {
  return render(
    <ThemeProvider>
      <Dashboard />
    </ThemeProvider>,
  );
}

/** The row's text with its closed "Technical details" left out. */
function visibleText(row: HTMLElement): string {
  const copy = row.cloneNode(true) as HTMLElement;
  copy.querySelectorAll("details").forEach((el) => el.remove());
  return copy.textContent ?? "";
}

describe("Dashboard approval rows in plain words", () => {
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

  it("reads the sentence, the labelled values, the question and the check code", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([EMAIL]);
    renderDashboard();

    const row = (await screen.findByText(EMAIL.reason)).parentElement as HTMLElement;
    expect(within(row).getByText("To")).toBeInTheDocument();
    expect(within(row).getByText("priya@acme.com")).toBeInTheDocument();
    expect(within(row).getByText((_, el) => el?.tagName === "DD" && el.textContent === BODY)).toBeInTheDocument();
    expect(within(row).getByText(/Okay to go ahead\?/).textContent).toBe(
      "Okay to go ahead? This expires in 9 minutes.",
    );
    expect(within(row).getByRole("button", { name: "Approve" })).toBeEnabled();
    expect(within(row).getByText(/Check code/).textContent).toBe("Check code 6d3b dfca 7bf8 cfc5");

    const technical = within(row).getByText("Technical details").closest("details") as HTMLDetailsElement;
    expect(technical.open).toBe(false);
    expect(within(technical).getByText("google_workspace.send_email")).toBeInTheDocument();
    expect(visibleText(row)).not.toContain("google_workspace");
    expect(visibleText(row)).not.toMatch(/[{}]/);
    expect(screen.getByText("Waiting for your OK")).toBeInTheDocument();
  });

  it("says plainly when a row ran out of time and turns its buttons off", async () => {
    vi.mocked(getPendingApprovals).mockResolvedValue([
      { ...EMAIL, expires_at: new Date(Date.now() - 1000).toISOString() },
    ]);
    renderDashboard();

    const row = (await screen.findByText(EMAIL.reason)).parentElement as HTMLElement;
    expect(
      within(row).getByText(
        "This request ran out of time, so nothing was done. Ask Crawler again if you still want it.",
      ),
    ).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Approve" })).toBeDisabled();
    expect(within(row).queryByText(/Okay to go ahead/)).not.toBeInTheDocument();
  });
});
