/**
 * Tests for LowRiskGrantButton and LowRiskAllowedNote: the button shows only when the server
 * offers the card's account a low-risk grant, is labelled with that account and described by the
 * line saying what it does and what still asks, follows the card's disabled state and reports a
 * press; the note says until when the account is allowed.
 *
 * Why it exists: The button lets an account's small changes run without asking for 7 days, so it
 * must never appear on a card the server did not offer it for (a tainted, unattended or
 * higher-risk card), and its words are all the owner reads about what pressing it allows.
 */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import LowRiskGrantButton, { LowRiskAllowedNote } from "@/components/LowRiskGrantButton";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import type { PendingApproval } from "@/types";

const CARD: PendingApproval = {
  action_id: "a9",
  tool_name: "google_workspace.modify_labels",
  reason: "Tool 'google_workspace.modify_labels' requires explicit user approval",
  arguments: { message_id: "m1", add_label_ids: ["STARRED"] },
  expires_at: "2099-01-01T00:00:00Z",
  low_risk_account: "School Gmail",
};

const ALLOW = "Allow low-risk changes on School Gmail for 7 days";
const HELPER =
  "Crawler then makes low-risk changes on this account without asking, for 7 days. Sends, deletes, sharing and anything other people see still ask. Revoke in Settings.";

describe("LowRiskGrantButton", () => {
  it.each([undefined, null, "", "   "])("renders nothing when low_risk_account is %j", (low_risk_account) => {
    const { container } = render(
      <LowRiskGrantButton approval={{ ...CARD, low_risk_account }} disabled={false} onAllow={() => {}} />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("offers the card's account for 7 days, described by what that does", () => {
    render(<LowRiskGrantButton approval={CARD} disabled={false} onAllow={() => {}} />);

    const button = screen.getByRole("button", { name: ALLOW });
    expect(button).toBeEnabled();
    expect(button).toHaveAccessibleDescription(HELPER);
  });

  it("reports a press, and none while the card is busy or expired", () => {
    const onAllow = vi.fn();
    const { rerender } = render(<LowRiskGrantButton approval={CARD} disabled={false} onAllow={onAllow} />);

    fireEvent.click(screen.getByRole("button", { name: ALLOW }));
    expect(onAllow).toHaveBeenCalledTimes(1);

    rerender(<LowRiskGrantButton approval={CARD} disabled onAllow={onAllow} />);
    const button = screen.getByRole("button", { name: ALLOW });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(onAllow).toHaveBeenCalledTimes(1);
  });
});

describe("LowRiskAllowedNote", () => {
  it("says until when the account is allowed", () => {
    render(<LowRiskAllowedNote grant={{ account: "School Gmail", expires_at: "2026-10-07T15:14:00Z" }} />);

    expect(screen.getByRole("status")).toHaveTextContent(
      `Low-risk changes on School Gmail are allowed until ${formatAllowedUntil("2026-10-07T15:14:00Z")}.`,
    );
  });
});
