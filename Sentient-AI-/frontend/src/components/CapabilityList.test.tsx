import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import CapabilityList, { CapabilityListError } from "@/components/CapabilityList";
import { CAPS } from "@/test/capabilities";

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

  it("is read-only for non-owners", () => {
    render(<CapabilityList items={CAPS} editable={false} onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    for (const sw of screen.getAllByRole("switch")) expect(sw).toBeDisabled();
    for (const btn of screen.getAllByRole("button", { name: /grant access|install/i })) {
      expect(btn).toBeDisabled();
    }
    expect(screen.getByText(/only the owner can change/i)).toBeInTheDocument();
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
