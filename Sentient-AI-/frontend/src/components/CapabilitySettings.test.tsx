/**
 * Tests for CapabilitySettings: they prove the purchase caps show the stored values (or the
 * defaults), save one changed field on blur or Enter and nothing when the value did not change,
 * refuse a blank amount or one outside $1 to $10,000 on this side, follow a value the server
 * saved, and are disabled for a reader who cannot edit; and that no other capability gets any
 * fields.
 *
 * Why it exists: Guards against a request on every tab through the form, against sending the
 * server an amount it would 422, and against the fields leaking onto rows that have no settings.
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

  it("disables both fields for a reader who cannot edit", () => {
    render(<CapabilitySettings item={purchases(STORED)} editable={false} onChange={vi.fn()} />);
    expect(screen.getByLabelText("Per purchase (USD)")).toBeDisabled();
    expect(screen.getByLabelText("Per day (USD)")).toBeDisabled();
  });
});
