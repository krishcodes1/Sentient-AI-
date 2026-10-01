/**
 * Tests for PermissionGrants (Settings ▸ Permissions ▸ Accounts allowed low-risk changes): each
 * grant is listed with its account, service, until when and last use; the empty list says every
 * change asks; Revoke removes only its own row; a failed revoke keeps the row with the reason; a
 * 404 reads the list again; a failed load can be retried.
 *
 * Why it exists: While an account holds a grant, its small changes run with no card at all, so the
 * owner has to be able to see every live grant and end it. A row that vanished without the server
 * agreeing would say a grant ended while changes still ran without asking.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { PermissionGrant } from "@/types";

vi.mock("@/services/api", () => {
  class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
      this.name = "ApiError";
    }
  }
  return {
    ApiError,
    listPermissionGrants: vi.fn(async () => []),
    revokePermissionGrant: vi.fn(),
  };
});

import PermissionGrants from "@/components/PermissionGrants";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import { ApiError, listPermissionGrants, revokePermissionGrant } from "@/services/api";

const UNTIL = "2026-10-07T15:14:00Z";
const USED = "2026-10-01T09:02:00Z";

function grant(overrides: Partial<PermissionGrant>): PermissionGrant {
  return {
    id: "g1",
    connector_id: "c1",
    account: "School Gmail",
    connector_type: "google_workspace",
    kind: "low_risk",
    granted_from: "web",
    granted_at: "2026-09-30T15:14:00Z",
    expires_at: UNTIL,
    last_used_at: null,
    uses: 0,
    ...overrides,
  };
}

const SCHOOL = grant({});
const OUTLOOK = grant({
  id: "g2",
  connector_id: "c2",
  account: "Personal Outlook",
  connector_type: "microsoft",
  granted_from: "telegram",
  last_used_at: USED,
  uses: 3,
});

const EMPTY =
  "No account has a 7-day low-risk grant. Each account still follows its permission tier, so changes ask first unless the tier lets them run. A card for a small change can allow its account for 7 days.";

describe("PermissionGrants", () => {
  it("lists each account with its service, until when and last use", async () => {
    vi.mocked(listPermissionGrants).mockResolvedValue([SCHOOL, OUTLOOK]);
    render(<PermissionGrants />);

    expect(screen.getByRole("region", { name: "Accounts allowed low-risk changes" })).toBeInTheDocument();
    expect(screen.getByText("Loading allowed accounts…")).toBeInTheDocument();

    const until = formatAllowedUntil(UNTIL);
    await screen.findByText("School Gmail");
    expect(screen.getAllByRole("listitem").map((row) => row.textContent)).toEqual([
      `School Gmailgoogle_workspace · until ${until} · not used yetRevoke`,
      `Personal Outlookmicrosoft · until ${until} · last used ${formatAllowedUntil(USED)} (3 changes)Revoke`,
    ]);
    expect(screen.getByRole("button", { name: "Revoke low-risk changes on School Gmail" })).toBeEnabled();
  });

  it("says every change asks when none are allowed", async () => {
    render(<PermissionGrants />);

    expect(await screen.findByText(EMPTY)).toBeInTheDocument();
    expect(screen.queryByRole("listitem")).not.toBeInTheDocument();
  });

  it("revokes one grant and removes only its row", async () => {
    vi.mocked(listPermissionGrants).mockResolvedValue([SCHOOL, OUTLOOK]);
    vi.mocked(revokePermissionGrant).mockResolvedValue(undefined);
    render(<PermissionGrants />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke low-risk changes on School Gmail" }));

    await waitFor(() => expect(screen.queryByText("School Gmail")).not.toBeInTheDocument());
    expect(vi.mocked(revokePermissionGrant).mock.calls).toEqual([["g1"]]);
    expect(screen.getByText("Personal Outlook")).toBeInTheDocument();
  });

  it("keeps the row, with the reason beside it, when revoking fails", async () => {
    vi.mocked(listPermissionGrants).mockResolvedValue([SCHOOL]);
    vi.mocked(revokePermissionGrant).mockRejectedValue(
      new ApiError("Request failed: Internal Server Error", 500),
    );
    render(<PermissionGrants />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke low-risk changes on School Gmail" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Request failed: Internal Server Error");
    expect(alert.closest("li")).toHaveTextContent("School Gmail");
    expect(listPermissionGrants).toHaveBeenCalledTimes(1);
  });

  it("reads the list again when the server answers 404", async () => {
    vi.mocked(listPermissionGrants)
      .mockResolvedValueOnce([SCHOOL, OUTLOOK])
      .mockResolvedValueOnce([OUTLOOK]);
    vi.mocked(revokePermissionGrant).mockRejectedValue(new ApiError("No such grant.", 404));
    render(<PermissionGrants />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke low-risk changes on School Gmail" }));

    await waitFor(() => expect(screen.queryByText("School Gmail")).not.toBeInTheDocument());
    expect(listPermissionGrants).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("reports a failed load with a way to try again", async () => {
    vi.mocked(listPermissionGrants)
      .mockRejectedValueOnce(new Error("Request failed: Bad Gateway"))
      .mockResolvedValueOnce([SCHOOL]);
    render(<PermissionGrants />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed: Bad Gateway");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("School Gmail")).toBeInTheDocument();
  });
});
