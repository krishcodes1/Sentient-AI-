/**
 * Tests for CapabilityList: they prove each category opens to its own switches with risk and
 * status, the switch calls onToggle with the new value, Grant access and Install appear only when
 * applicable, non-owners get every control disabled, the purchases row carries its spending caps,
 * saved through onSettingsChange only where a handler is given, each row shows a summary and pills
 * with its three facts behind an info button, the acting-on-sites row says what waits for you, the attention banner jumps to a blocked switch, and a protection level shows exactly
 * what it changes and saves only the switches it governs.
 *
 * Why it exists: Guards against showing an Install or Grant access button that does nothing,
 * letting a non-owner change capabilities the server would refuse, the caps going missing or
 * editable where they should not be, or a level silently turning off a privacy check.
 */

import { fireEvent, render, screen, within } from "@testing-library/react";
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

/** CAPS puts See my screen under Your computer, the two web ones under Websites and Reminders
 *  under Background tasks. */
async function openCategory(label: string) {
  await userEvent.click(screen.getByRole("button", { name: new RegExp(`^${label}`) }));
}

function renderList(items: CapabilityStatus[] = CAPS, editable = true) {
  return render(
    <CapabilityList items={items} editable={editable} onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />,
  );
}

describe("CapabilityList", () => {
  it("shows one button per category with its status, and opens one at a time", async () => {
    renderList();
    expect(screen.getByRole("button", { name: /^Your computer.*1 needs attention/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /^Background tasks.*Off/ })).toHaveAttribute("aria-pressed", "false");
    // Only the open category's switches are on screen.
    expect(screen.getByRole("switch", { name: /see my screen/i })).toHaveAttribute("aria-checked", "true");
    expect(screen.queryByRole("switch", { name: /browse the web/i })).not.toBeInTheDocument();

    await openCategory("Websites");
    expect(screen.getByRole("switch", { name: /browse the web/i })).toBeInTheDocument();
    expect(screen.queryByRole("switch", { name: /see my screen/i })).not.toBeInTheDocument();
  });

  it("marks a risky switch and says why it is blocked", () => {
    renderList();
    expect(screen.getByText("High risk")).toBeInTheDocument();
    expect(screen.getByText(/^Blocked — .*not granted screen recording/i)).toBeInTheDocument();
  });

  it("shows the summary and pills at a glance, and the three facts behind the info button", async () => {
    renderList([...CAPS, PURCHASES]);
    await openCategory("Money");
    expect(screen.getByText("Buys small things with your stored card, within your limits.")).toBeInTheDocument();
    expect(screen.getByText("You approve every purchase")).toBeInTheDocument();
    expect(screen.queryByText("Every purchase, before it's paid.")).not.toBeInTheDocument();

    const info = screen.getByRole("button", { name: "About Buy things for me" });
    expect(info).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(info);
    expect(info).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("On its own:")).toBeInTheDocument();
    expect(screen.getByText("Every purchase, before it's paid.")).toBeInTheDocument();
    expect(screen.getByText("Pays only with the card you stored.")).toBeInTheDocument();
  });

  it("falls back to the first sentence, and the full description, for a permission without facts", async () => {
    const UNLISTED = { ...CAPS[0], key: "something_new", label: "Something new", description: "Does one thing. Then a long story." };
    renderList([...CAPS, UNLISTED]);
    await openCategory("Other");
    expect(screen.getByText("Does one thing.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "About Something new" }));
    expect(screen.getByText("Does one thing. Then a long story.")).toBeInTheDocument();
  });

  it("calls onToggle with the new value", async () => {
    const onToggle = vi.fn();
    render(<CapabilityList items={CAPS} editable onToggle={onToggle} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    await openCategory("Websites");
    await userEvent.click(screen.getByRole("switch", { name: /browse the web/i }));
    expect(onToggle).toHaveBeenCalledWith("web_browsing", false);
  });

  it("shows Grant access only when the OS denied it, Install only when installable", async () => {
    renderList();
    expect(screen.getByRole("button", { name: /grant access/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^install/i })).not.toBeInTheDocument();
    await openCategory("Websites");
    expect(screen.getByRole("button", { name: /^install/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /grant access/i })).not.toBeInTheDocument();
  });

  it("puts the download size on the Install button when the server gives one", async () => {
    renderList();
    await openCategory("Websites");
    expect(screen.getByRole("button", { name: "Install (~150-300 MB download)" })).toBeInTheDocument();
  });

  it("labels the button plain Install when there is no size hint", async () => {
    renderList(CAPS.map((c) => (c.install ? { ...c, install_size_hint: null } : c)));
    await openCategory("Websites");
    expect(screen.getByRole("button", { name: "Install" })).toBeInTheDocument();
  });

  it("is read-only for non-owners", async () => {
    renderList(CAPS, false);
    expect(screen.getByText(/only the owner can change/i)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /see my screen/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /grant access/i })).toBeDisabled();
    await openCategory("Websites");
    for (const sw of screen.getAllByRole("switch")) expect(sw).toBeDisabled();
    expect(screen.getByRole("button", { name: /^install/i })).toBeDisabled();
  });

  it("names what needs attention and opens its category when clicked", async () => {
    renderList();
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent("2 permissions need your attention");
    await userEvent.click(within(banner).getByRole("button", { name: "Take screenshots of websites" }));
    expect(screen.getByRole("button", { name: /^Websites/ })).toHaveAttribute("aria-pressed", "true");
  });

  it("shows extra content at the foot of its category", async () => {
    render(
      <CapabilityList
        items={CAPS}
        editable
        onToggle={vi.fn()}
        onRequestAccess={vi.fn()}
        onInstall={vi.fn()}
        extras={{ money: <p>Card on file</p> }}
      />,
    );
    // Money has no switches in CAPS, but its extra content still earns it a button.
    await openCategory("Money");
    expect(screen.getByRole("region", { name: "Money" })).toHaveTextContent("Card on file");
  });
});

describe("CapabilityList purchase caps", () => {
  const items = [...CAPS, PURCHASES];
  const props = { editable: true, onToggle: vi.fn(), onRequestAccess: vi.fn(), onInstall: vi.fn() };

  it("shows the caps under the purchases row and saves a changed one through onSettingsChange", async () => {
    const onSettingsChange = vi.fn();
    render(<CapabilityList items={items} {...props} onSettingsChange={onSettingsChange} />);
    await openCategory("Money");
    expect(screen.getByText("Has limits")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "About Buy things for me" }));
    const perPurchase = screen.getByLabelText("Per purchase (USD)");
    expect(perPurchase).toHaveValue(25);
    expect(screen.getByLabelText("Per day (USD)")).toHaveValue(50);
    // One pair of fields in the whole panel: only the purchases row has settings.
    expect(screen.getAllByRole("spinbutton")).toHaveLength(2);

    fireEvent.change(perPurchase, { target: { value: "40" } });
    fireEvent.blur(perPurchase);
    expect(onSettingsChange).toHaveBeenCalledWith("purchases", { per_purchase_cap_usd: 40 });
  });

  it("renders no settings fields where there is no save handler", async () => {
    render(<CapabilityList items={items} {...props} />);
    await openCategory("Money");
    expect(screen.queryByText("Has limits")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "About Buy things for me" }));
    expect(screen.queryByLabelText("Per purchase (USD)")).not.toBeInTheDocument();
  });

  it("keeps the caps read-only for non-owners and while the row is busy", async () => {
    const { rerender } = render(<CapabilityList items={items} {...props} editable={false} onSettingsChange={vi.fn()} />);
    await openCategory("Money");
    await userEvent.click(screen.getByRole("button", { name: "About Buy things for me" }));
    expect(screen.getByLabelText("Per purchase (USD)")).toBeDisabled();
    expect(screen.getByLabelText("Per day (USD)")).toBeDisabled();

    rerender(<CapabilityList items={items} {...props} busyKey="purchases" onSettingsChange={vi.fn()} />);
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
  it("says at a glance it asks before paying, why it is blocked, and what waits for you behind the info button", async () => {
    renderList([...CAPS, ACTING]);
    await openCategory("Websites");
    expect(screen.getByRole("switch", { name: "Fill in forms and click on sites" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByText("Asks before paying or sending")).toBeInTheDocument();
    expect(screen.getByText("Blocked — Needs 'Control a browser' on in Permissions.")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "About Fill in forms and click on sites" }));
    expect(screen.getByText("Asks you first:").parentElement).toHaveTextContent(
      "Paying, sending, posting, deleting, cancelling, signing you up, agreeing to terms or typing your details",
    );
  });
});

describe("CapabilityList protection levels", () => {
  const cap = (key: string, label: string, enabled: boolean, risk: CapabilityStatus["risk"] = "medium") => ({
    ...CAPS[0],
    key,
    label,
    risk,
    enabled,
    effective: enabled ? ("on" as const) : ("off" as const),
  });
  // Crawler's shipped switches: Balanced.
  const SHIPPED = [
    cap("low_risk_actions", "Make low-risk changes without asking", true),
    cap("browser_control", "Control a browser", false, "high"),
    cap("hide_personal_details", "Hide personal details from the AI provider", true, "low"),
  ];

  function renderLevels(items: CapabilityStatus[], onApplyLevel = vi.fn(async () => {})) {
    render(
      <CapabilityList
        items={items}
        editable
        onToggle={vi.fn()}
        onRequestAccess={vi.fn()}
        onInstall={vi.fn()}
        onApplyLevel={onApplyLevel}
      />,
    );
    return onApplyLevel;
  }

  it("marks the level the switches match", () => {
    renderLevels(SHIPPED);
    expect(screen.getByRole("radio", { name: /^Balanced/ })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("radio", { name: /^Cautious/ })).toHaveAttribute("aria-checked", "false");
    expect(screen.queryByText(/your own mix/i)).not.toBeInTheDocument();
  });

  it("says when no level matches", () => {
    renderLevels([...SHIPPED, cap("screen", "See my screen", true, "high")]);
    for (const radio of screen.getAllByRole("radio")) expect(radio).toHaveAttribute("aria-checked", "false");
    expect(screen.getByText(/your own mix/i)).toBeInTheDocument();
  });

  it("lists what a level changes, saves only that, and never touches a privacy check", async () => {
    const onApplyLevel = renderLevels(SHIPPED);
    await userEvent.click(screen.getByRole("radio", { name: /^Cautious/ }));

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("Turns off: Make low-risk changes without asking");
    expect(dialog).not.toHaveTextContent("Hide personal details");
    await userEvent.click(within(dialog).getByRole("button", { name: "Switch to Cautious" }));

    expect(onApplyLevel).toHaveBeenCalledWith({ low_risk_actions: false });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("turns the browser on for Hands-off", async () => {
    const onApplyLevel = renderLevels(SHIPPED);
    await userEvent.click(screen.getByRole("radio", { name: /^Hands-off/ }));
    expect(screen.getByRole("dialog")).toHaveTextContent("Turns on: Control a browser");
    await userEvent.click(screen.getByRole("button", { name: "Switch to Hands-off" }));
    expect(onApplyLevel).toHaveBeenCalledWith({ browser_control: true });
  });

  it("keeps the dialog open with the error when saving fails", async () => {
    renderLevels(SHIPPED, vi.fn(async () => {
      throw new Error("Only the owner can change permissions.");
    }));
    await userEvent.click(screen.getByRole("radio", { name: /^Cautious/ }));
    await userEvent.click(screen.getByRole("button", { name: "Switch to Cautious" }));
    expect(await within(screen.getByRole("dialog")).findByText("Only the owner can change permissions.")).toBeInTheDocument();
  });

  it("has no level picker without a save handler", () => {
    renderList(SHIPPED);
    expect(screen.queryByRole("radiogroup")).not.toBeInTheDocument();
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
