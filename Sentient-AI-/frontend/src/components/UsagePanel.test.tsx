/**
 * Tests for UsagePanel: they prove each window shows tokens and an estimated cost, unpriced turns
 * are called out, the by-model table names rows with no recorded model, and empty and failed loads
 * say so.
 *
 * Why it exists: Guards against a partly priced window posing as a total, or a failed load showing
 * zeros.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import UsagePanel from "@/components/UsagePanel";
import { usageSummary, usageWindow } from "@/test/usage";

describe("UsagePanel", () => {
  it("shows every window's tokens and an explicitly estimated cost", () => {
    render(<UsagePanel usage={usageSummary()} loading={false} />);

    const today = screen.getByText("Today").parentElement!;
    expect(within(today).getByText("1,290")).toBeInTheDocument();
    expect(within(today).getByText("1,234 in · 56 out")).toBeInTheDocument();
    expect(within(today).getByText("est. <$0.01")).toBeInTheDocument();

    const week = screen.getByText("Last 7 days").parentElement!;
    expect(within(week).getByText("est. $0.25")).toBeInTheDocument();

    // A partly priced window says what it left out rather than posing as a total.
    const month = screen.getByText("Last 30 days").parentElement!;
    expect(within(month).getByText("est. $1.50 + 3 unpriced")).toBeInTheDocument();

    const allTime = screen.getByText("All time").parentElement!;
    expect(within(allTime).getByText("est. cost unknown")).toBeInTheDocument();

    expect(screen.getByText(/Estimated from list prices/)).toBeInTheDocument();
  });

  it("breaks usage down by model, naming rows with no recorded model", () => {
    render(<UsagePanel usage={usageSummary()} loading={false} />);
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // Header + two models.
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("gemini-2.5-flash")).toBeInTheDocument();
    expect(within(rows[1]).getByText("100,000")).toBeInTheDocument();
    expect(within(rows[1]).getByText("$0.05")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Model not recorded")).toBeInTheDocument();
    expect(within(rows[2]).getByText("unknown")).toBeInTheDocument();
    expect(within(table).getByRole("columnheader", { name: "Est. cost" })).toBeInTheDocument();
  });

  it("keeps a wide table inside its own scroll box", () => {
    render(<UsagePanel usage={usageSummary()} loading={false} />);
    expect(screen.getByRole("table").parentElement).toHaveClass("overflow-x-auto");
  });

  it("says plainly when nothing has been recorded", () => {
    const empty = usageSummary({
      windows: {
        today: usageWindow(),
        last_7_days: usageWindow(),
        last_30_days: usageWindow(),
        all_time: usageWindow(),
      },
      by_model: [],
    });
    render(<UsagePanel usage={empty} loading={false} />);
    expect(screen.getByText(/No token usage recorded yet/)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("reports a failed load instead of showing zeros", () => {
    render(<UsagePanel usage={null} loading={false} />);
    expect(screen.getByText("Usage could not be loaded.")).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });
});
