/**
 * Tests for WeeklyAppButton, WeeklyAllowedNote and formatAllowedUntil: they prove the third button
 * shows only when the server offers the card's app for a week, is labelled with that app and
 * described by the line saying what it does, follows the card's disabled state and reports a
 * press; and that the note says until when the app is allowed.
 *
 * Why it exists: The button lets Crawler act in an app without asking for 7 days, so it must never
 * appear on a card the server did not offer it for, and its words are all the owner reads about
 * what pressing it allows.
 */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import WeeklyAppButton, { WeeklyAllowedNote } from "@/components/WeeklyAppButton";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import type { PendingApproval } from "@/types";

// A desktop.act card as the backend parks it, with the screen it was made from under `_screen`.
const CARD: PendingApproval = {
  action_id: "a7",
  tool_name: "desktop.act",
  reason: 'Click "Month" in Calendar',
  arguments: { action: "click", ref: "e12", _screen: { app: "Calendar", outline: "4be1c2" } },
  expires_at: "2099-01-01T00:00:00Z",
  weekly_app: "Calendar",
};

const ALLOW = "Allow Calendar for 7 days";
const HELPER =
  "Crawler then acts in Calendar without asking, for requests from this browser, for 7 days. Revoke in Settings.";

describe("WeeklyAppButton", () => {
  it.each([undefined, null, "", "   "])("renders nothing when weekly_app is %j", (weekly_app) => {
    const { container } = render(
      <WeeklyAppButton approval={{ ...CARD, weekly_app }} disabled={false} onAllow={() => {}} />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("offers the card's app for 7 days, described by what that does", () => {
    render(<WeeklyAppButton approval={CARD} disabled={false} onAllow={() => {}} />);

    const button = screen.getByRole("button", { name: ALLOW });
    expect(button).toBeEnabled();
    expect(button).toHaveAccessibleDescription(HELPER);
    expect(screen.getByText(HELPER)).toBeInTheDocument();
  });

  it("names whichever app the server offered", () => {
    render(
      <WeeklyAppButton approval={{ ...CARD, weekly_app: "Reminders" }} disabled={false} onAllow={() => {}} />,
    );

    expect(screen.getByRole("button", { name: "Allow Reminders for 7 days" })).toBeInTheDocument();
    expect(screen.getByText(/^Crawler then acts in Reminders without asking/)).toBeInTheDocument();
  });

  it("reports a press, and none while the card is busy or expired", () => {
    const onAllow = vi.fn();
    const { rerender } = render(<WeeklyAppButton approval={CARD} disabled={false} onAllow={onAllow} />);

    fireEvent.click(screen.getByRole("button", { name: ALLOW }));
    expect(onAllow).toHaveBeenCalledTimes(1);

    rerender(<WeeklyAppButton approval={CARD} disabled onAllow={onAllow} />);
    const button = screen.getByRole("button", { name: ALLOW });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(onAllow).toHaveBeenCalledTimes(1);
  });
});

describe("WeeklyAllowedNote", () => {
  it("says until when the app is allowed", () => {
    render(<WeeklyAllowedNote weekly={{ app: "Calendar", expires_at: "2026-10-02T15:14:00Z" }} />);

    expect(screen.getByRole("status")).toHaveTextContent(
      `Calendar is allowed until ${formatAllowedUntil("2026-10-02T15:14:00Z")}.`,
    );
  });
});

describe("formatAllowedUntil", () => {
  it("gives the time as well as the day, and no year", () => {
    const text = formatAllowedUntil("2026-10-02T15:14:00Z");

    expect(text).toMatch(/\d:\d\d/);
    expect(text).not.toContain("2026");
  });

  it("hands back a value that is not a date as it was, never Invalid Date", () => {
    expect(formatAllowedUntil("next week")).toBe("next week");
  });
});
