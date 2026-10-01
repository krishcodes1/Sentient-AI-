/**
 * Tests for CapabilitySettings: they prove the purchase caps show the stored values (or the
 * defaults), save one changed field on blur or Enter and nothing when the value did not change,
 * refuse a blank amount or one outside $1 to $10,000 on this side, follow a value the server
 * saved, and are disabled for a reader who cannot edit; that the scheduled-task budgets are
 * entered in dollars and saved in cents, and the video and knowledge limits as whole numbers; and
 * that a capability without settings gets no fields.
 *
 * Why it exists: Guards against a request on every tab through the form, against sending the
 * server a value it would 422, against the fields leaking onto rows that have no settings, and
 * against messages that send the owner to Settings → Permissions for a limit it cannot change.
 */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import CapabilitySettings from "@/components/CapabilitySettings";
import { CAPS } from "@/test/capabilities";
import type { CapabilityStatus } from "@/types";

function purchases(settings?: Record<string, unknown>): CapabilityStatus {
  return {
    ...CAPS[3],
    key: "purchases",
    label: "Buy things for me",
    risk: "high",
    tools: ["browser.checkout"],
    settings,
  };
}

const STORED = { per_purchase_cap_usd: 25, per_day_cap_usd: 50 };

describe("CapabilitySettings", () => {
  it("renders nothing for a capability without settings", () => {
    const { container } = render(<CapabilitySettings item={CAPS[0]} editable onChange={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the stored caps, or the defaults when the server sent none", () => {
    const { rerender } = render(
      <CapabilitySettings
        item={purchases({ per_purchase_cap_usd: 40, per_day_cap_usd: 120 })}
        editable
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByLabelText("Per purchase (USD)")).toHaveValue(40);
    expect(screen.getByLabelText("Per day (USD)")).toHaveValue(120);

    rerender(<CapabilitySettings item={purchases()} editable onChange={vi.fn()} />);
    expect(screen.getByLabelText("Per purchase (USD)")).toHaveValue(25);
    expect(screen.getByLabelText("Per day (USD)")).toHaveValue(50);
  });

  it("saves one changed field on blur, and nothing when the value did not change", () => {
    const onChange = vi.fn();
    render(<CapabilitySettings item={purchases(STORED)} editable onChange={onChange} />);

    const perDay = screen.getByLabelText("Per day (USD)");
    fireEvent.change(perDay, { target: { value: "80" } });
    fireEvent.blur(perDay);
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith({ per_day_cap_usd: 80 });

    // Retyping the stored value, and a blur with nothing typed, send nothing.
    const perPurchase = screen.getByLabelText("Per purchase (USD)");
    fireEvent.change(perPurchase, { target: { value: "25" } });
    fireEvent.blur(perPurchase);
    fireEvent.blur(perDay);
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it("commits on Enter", () => {
    const onChange = vi.fn();
    render(<CapabilitySettings item={purchases(STORED)} editable onChange={onChange} />);
    const perPurchase = screen.getByLabelText("Per purchase (USD)");
    perPurchase.focus();
    fireEvent.change(perPurchase, { target: { value: "15" } });
    fireEvent.keyDown(perPurchase, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith({ per_purchase_cap_usd: 15 });
  });

  it("refuses a blank, fractional or out-of-bounds amount and shows the stored value again", () => {
    const onChange = vi.fn();
    render(<CapabilitySettings item={purchases(STORED)} editable onChange={onChange} />);
    const perPurchase = screen.getByLabelText("Per purchase (USD)");
    // The same bounds the server holds (SETTING_MIN / SETTING_MAX), on the
    // field itself and in the complaint.
    expect(perPurchase).toHaveAttribute("min", "1");
    expect(perPurchase).toHaveAttribute("max", "10000");
    // A cap is a whole number of dollars (the server refuses 25.5 too).
    for (const bad of ["", "0", "0.5", "-5", "10001", "20000", "25.5"]) {
      fireEvent.change(perPurchase, { target: { value: bad } });
      fireEvent.blur(perPurchase);
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Enter a whole number of dollars between $1 and $10,000.",
      );
      expect(perPurchase).toHaveValue(25);
    }
    expect(onChange).not.toHaveBeenCalled();

    // A good value clears the complaint; the ceiling itself is allowed.
    fireEvent.change(perPurchase, { target: { value: "30" } });
    fireEvent.blur(perPurchase);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(onChange).toHaveBeenCalledWith({ per_purchase_cap_usd: 30 });
    fireEvent.change(perPurchase, { target: { value: "10000" } });
    fireEvent.blur(perPurchase);
    expect(onChange).toHaveBeenCalledWith({ per_purchase_cap_usd: 10000 });
  });

  it("shows the value the server saved once the item updates", () => {
    const { rerender } = render(
      <CapabilitySettings item={purchases(STORED)} editable onChange={vi.fn()} />,
    );
    rerender(
      <CapabilitySettings
        item={purchases({ ...STORED, per_purchase_cap_usd: 40 })}
        editable
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByLabelText("Per purchase (USD)")).toHaveValue(40);
  });

  it("enters the scheduled-task budgets in dollars and saves them in cents", () => {
    const onChange = vi.fn();
    const scheduled: CapabilityStatus = {
      ...CAPS[3],
      key: "scheduled_tasks",
      settings: { run_cap_cents: 5, day_cap_cents: 25, runs_per_day: 24 },
    };
    render(<CapabilitySettings item={scheduled} editable onChange={onChange} />);
    const perRun = screen.getByLabelText("Per run (USD)");
    expect(perRun).toHaveValue(0.05);
    expect(screen.getByLabelText("Per 24 hours (USD)")).toHaveValue(0.25);
    expect(screen.getByLabelText("Runs per 24 hours")).toHaveValue(24);

    fireEvent.change(perRun, { target: { value: "0.20" } });
    fireEvent.blur(perRun);
    expect(onChange).toHaveBeenCalledWith({ run_cap_cents: 20 });

    // A fraction of a cent, nothing, or more than $100.00 is refused here.
    for (const bad of ["0.005", "", "0", "100.01"]) {
      fireEvent.change(perRun, { target: { value: bad } });
      fireEvent.blur(perRun);
      expect(screen.getByRole("alert")).toHaveTextContent("Enter an amount between $0.01 and $100.00.");
    }
    expect(onChange).toHaveBeenCalledTimes(1);

    const runs = screen.getByLabelText("Runs per 24 hours");
    fireEvent.change(runs, { target: { value: "48" } });
    fireEvent.blur(runs);
    expect(onChange).toHaveBeenLastCalledWith({ runs_per_day: 48 });
  });

  it("gives the video and knowledge base limits whole-number fields", () => {
    const onChange = vi.fn();
    const video: CapabilityStatus = { ...CAPS[3], key: "video_transcripts", settings: {} };
    const { unmount } = render(<CapabilitySettings item={video} editable onChange={onChange} />);
    const perDay = screen.getByLabelText("Minutes per day");
    expect(perDay).toHaveValue(240);
    fireEvent.change(perDay, { target: { value: "2.5" } });
    fireEvent.blur(perDay);
    expect(screen.getByRole("alert")).toHaveTextContent("Enter a whole number from 1 to 10,000.");
    fireEvent.change(perDay, { target: { value: "300" } });
    fireEvent.blur(perDay);
    expect(onChange).toHaveBeenCalledWith({ video_minutes_per_day: 300 });
    unmount();

    const knowledge: CapabilityStatus = { ...CAPS[3], key: "knowledge_base", settings: { file_mb: 40 } };
    render(<CapabilitySettings item={knowledge} editable onChange={onChange} />);
    expect(screen.getByLabelText("Largest file (MB)")).toHaveValue(40);
    expect(screen.getByLabelText("Documents per person")).toHaveValue(400);
  });

  it("disables both fields for a reader who cannot edit", () => {
    render(<CapabilitySettings item={purchases(STORED)} editable={false} onChange={vi.fn()} />);
    expect(screen.getByLabelText("Per purchase (USD)")).toBeDisabled();
    expect(screen.getByLabelText("Per day (USD)")).toBeDisabled();
  });
});
