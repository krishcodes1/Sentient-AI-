/**
 * Tests for CapabilityList: they prove each row shows label, risk and status, the switch calls
 * onToggle with the new value, Grant access and Install appear only when applicable, non-owners
 * get every control disabled, the purchases row carries its spending caps, saved through
 * onSettingsChange only where a handler is given, and the acting-on-sites row carries its warning.
 *
 * Why it exists: Guards against showing an Install or Grant access button that does nothing,
 * letting a non-owner change capabilities the server would refuse, or the caps going missing or
 * editable where they should not be.
 */

import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import CapabilityList, { CapabilityListError } from "@/components/CapabilityList";
import { CAPS } from "@/test/capabilities";
import type { CapabilityStatus } from "@/types";

const PURCHASES: CapabilityStatus = {
  ...CAPS[3],
  key: "purchases",
  label: "Buy things for me",
  description: "Book tickets and make small purchases with the card you stored.",
  risk: "high",
  enabled: true,
  default_enabled: false,
  effective: "on",
  tools: ["browser.checkout"],
  settings: { per_purchase_cap_usd: 25, per_day_cap_usd: 50 },
};

describe("CapabilityList", () => {
  it("renders label, risk, status line and a switch per capability", () => {
    render(<CapabilityList items={CAPS} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    expect(screen.getByText("See my screen")).toBeInTheDocument();
    expect(screen.getByText(/high/i)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /see my screen/i })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByText(/not granted screen recording/i)).toBeInTheDocument();
  });

  it("calls onToggle with the new value", async () => {
    const onToggle = vi.fn();
    render(<CapabilityList items={CAPS} editable onToggle={onToggle} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    await userEvent.click(screen.getByRole("switch", { name: /browse the web/i }));
    expect(onToggle).toHaveBeenCalledWith("web_browsing", false);
  });

  it("shows Grant access only when the OS denied it, Install only when installable", () => {
    render(<CapabilityList items={CAPS} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    expect(screen.getByRole("button", { name: /grant access/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /install/i })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /grant access|install/i })).toHaveLength(2);
  });

  it("puts the download size on the Install button when the server gives one", () => {
    render(<CapabilityList items={CAPS} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Install (~150-300 MB download)" })).toBeInTheDocument();
  });

  it("labels the button plain Install when there is no size hint", () => {
    const items = CAPS.map((c) => (c.install ? { ...c, install_size_hint: null } : c));
    render(<CapabilityList items={items} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Install" })).toBeInTheDocument();
  });

  it("is read-only for non-owners", () => {
    render(<CapabilityList items={CAPS} editable={false} onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    for (const sw of screen.getAllByRole("switch")) expect(sw).toBeDisabled();
    for (const btn of screen.getAllByRole("button", { name: /grant access|install/i })) {
      expect(btn).toBeDisabled();
    }
    expect(screen.getByText(/only the owner can change/i)).toBeInTheDocument();
  });
});

describe("CapabilityList purchase caps", () => {
  const items = [...CAPS, PURCHASES];

  it("shows the caps under the purchases row and saves a changed one through onSettingsChange", () => {
    const onSettingsChange = vi.fn();
    render(
      <CapabilityList
        items={items}
        editable
        onToggle={vi.fn()}
        onRequestAccess={vi.fn()}
        onInstall={vi.fn()}
        onSettingsChange={onSettingsChange}
      />,
    );
    const perPurchase = screen.getByLabelText("Per purchase (USD)");
    expect(perPurchase).toHaveValue(25);
    expect(screen.getByLabelText("Per day (USD)")).toHaveValue(50);
    // One pair of fields in the whole list: only the purchases row has settings.
    expect(screen.getAllByRole("spinbutton")).toHaveLength(2);

    fireEvent.change(perPurchase, { target: { value: "40" } });
    fireEvent.blur(perPurchase);
    expect(onSettingsChange).toHaveBeenCalledWith("purchases", { per_purchase_cap_usd: 40 });
  });

  it("renders no settings fields where there is no save handler", () => {
    render(<CapabilityList items={items} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    expect(screen.getByText("Buy things for me")).toBeInTheDocument();
    expect(screen.queryByLabelText("Per purchase (USD)")).not.toBeInTheDocument();
  });

  it("keeps the caps read-only for non-owners and while the row is busy", () => {
    const { rerender } = render(
      <CapabilityList
        items={items}
        editable={false}
        onToggle={vi.fn()}
        onRequestAccess={vi.fn()}
        onInstall={vi.fn()}
        onSettingsChange={vi.fn()}
      />,
    );
    expect(screen.getByLabelText("Per purchase (USD)")).toBeDisabled();
    expect(screen.getByLabelText("Per day (USD)")).toBeDisabled();

    rerender(
      <CapabilityList
        items={items}
        editable
        busyKey="purchases"
        onToggle={vi.fn()}
        onRequestAccess={vi.fn()}
        onInstall={vi.fn()}
        onSettingsChange={vi.fn()}
      />,
    );
    expect(screen.getByLabelText("Per day (USD)")).toBeDisabled();
  });
});

describe("CapabilityList acting on sites", () => {
  const ACTING: CapabilityStatus = {
    ...CAPS[3],
    key: "browser_act",
    label: "Fill in forms and click on sites",
    description:
      "Type into forms, choose options and click buttons on sites in Crawler's browser; you approve every step on a card with a picture of the page.",
    risk: "high",
    enabled: true,
    default_enabled: false,
    effective: "blocked",
    reason: "Needs 'Control a browser' on in Permissions.",
    tools: ["browser.act"],
  };
  const WARNING = "Crawler will ask before every click or keystroke, with a picture of the page.";

  it("shows the switch with its one-line description, its plain warning and why it is blocked", () => {
    render(
      <CapabilityList items={[...CAPS, ACTING]} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />,
    );
    expect(screen.getByRole("switch", { name: "Fill in forms and click on sites" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByText(ACTING.description)).toBeInTheDocument();
    // The warning is on this row alone.
    expect(screen.getAllByText(WARNING)).toHaveLength(1);
    expect(screen.getByText("Blocked — Needs 'Control a browser' on in Permissions.")).toBeInTheDocument();
  });
});

describe("CapabilityListError", () => {
  it("renders the failure message and calls onRetry when clicked", async () => {
    const onRetry = vi.fn();
    render(<CapabilityListError message="Network request failed" onRetry={onRetry} />);
    expect(screen.getByText(/couldn't load permissions/i)).toBeInTheDocument();
    expect(screen.getByText("Network request failed")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
