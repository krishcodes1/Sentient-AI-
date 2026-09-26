/**
 * Tests for AppApprovals (Settings ▸ Permissions ▸ Apps allowed for a week): they prove each app is
 * listed with where it was allowed (this browser, another browser, Telegram) and until when, that
 * the empty list says how to allow one, that Revoke removes only its own row, that a failed revoke
 * keeps the row with the reason beside it, that a revoke answered 404 reads the list again instead
 * of assuming, and that a failed load can be retried.
 *
 * Why it exists: While an app is allowed, Crawler acts in it with no card at all, so the owner has
 * to be able to see every one that is live and end it. A row that vanished without the server
 * agreeing would tell them an app was revoked while Crawler could still act in it.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { AppApproval } from "@/types";

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
    listAppApprovals: vi.fn(async () => []),
    revokeAppApproval: vi.fn(),
  };
});

import AppApprovals from "@/components/AppApprovals";
import { formatAllowedUntil } from "@/components/appApprovalFormat";
import { ApiError, listAppApprovals, revokeAppApproval } from "@/services/api";

const UNTIL = "2026-10-02T15:14:00Z";

function allowed(overrides: Partial<AppApproval>): AppApproval {
  return {
    id: "w1",
    app: "Calendar",
    channel: "web",
    this_device: true,
    granted_at: "2026-09-25T15:14:00Z",
    expires_at: UNTIL,
    last_used_at: null,
    ...overrides,
  };
}

const HERE = allowed({});
const ELSEWHERE = allowed({ id: "w2", app: "Notes", this_device: false });
const TELEGRAM = allowed({ id: "w3", app: "Reminders", channel: "telegram", this_device: false });

const EMPTY =
  "No apps are allowed for a week. When Crawler asks to act in an app like Calendar, you can allow it for 7 days from the approval card.";

describe("AppApprovals", () => {
  it("lists each app with where it was allowed and until when", async () => {
    vi.mocked(listAppApprovals).mockResolvedValue([HERE, ELSEWHERE, TELEGRAM]);
    render(<AppApprovals />);

    expect(screen.getByRole("region", { name: "Apps allowed for a week" })).toBeInTheDocument();
    expect(screen.getByText("Loading allowed apps…")).toBeInTheDocument();

    const until = formatAllowedUntil(UNTIL);
    await screen.findByText("Calendar");
    expect(screen.getAllByRole("listitem").map((row) => row.textContent)).toEqual([
      `CalendarFrom this browser · until ${until}Revoke`,
      `NotesFrom another browser · until ${until}Revoke`,
      `RemindersFrom Telegram · until ${until}Revoke`,
    ]);
    expect(screen.getByRole("button", { name: "Revoke Calendar (this browser)" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Revoke Notes (another browser)" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Revoke Reminders (Telegram)" })).toBeEnabled();
  });

  it("says how to allow one when none are allowed", async () => {
    render(<AppApprovals />);

    expect(await screen.findByText(EMPTY)).toBeInTheDocument();
    expect(screen.queryByRole("listitem")).not.toBeInTheDocument();
  });

  it("revokes one app and removes only its row", async () => {
    vi.mocked(listAppApprovals).mockResolvedValue([HERE, TELEGRAM]);
    vi.mocked(revokeAppApproval).mockResolvedValue(undefined);
    render(<AppApprovals />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke Calendar (this browser)" }));

    await waitFor(() => expect(screen.queryByText("Calendar")).not.toBeInTheDocument());
    expect(vi.mocked(revokeAppApproval).mock.calls).toEqual([["w1"]]);
    expect(screen.getByText("Reminders")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke Reminders (Telegram)" })).toBeEnabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows the empty line once the last app is revoked", async () => {
    vi.mocked(listAppApprovals).mockResolvedValue([HERE]);
    vi.mocked(revokeAppApproval).mockResolvedValue(undefined);
    render(<AppApprovals />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke Calendar (this browser)" }));

    expect(await screen.findByText(EMPTY)).toBeInTheDocument();
  });

  it("keeps the row, with the reason beside it, when revoking fails", async () => {
    vi.mocked(listAppApprovals).mockResolvedValue([HERE, TELEGRAM]);
    vi.mocked(revokeAppApproval).mockRejectedValue(
      new ApiError("Request failed: Internal Server Error", 500),
    );
    render(<AppApprovals />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke Calendar (this browser)" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Request failed: Internal Server Error");
    expect(alert.closest("li")).toHaveTextContent("Calendar");
    expect(screen.getByRole("button", { name: "Revoke Calendar (this browser)" })).toBeEnabled();
    expect(listAppApprovals).toHaveBeenCalledTimes(1);
  });

  it("reads the list again when the server answers 404, instead of assuming it is gone", async () => {
    vi.mocked(listAppApprovals)
      .mockResolvedValueOnce([HERE, TELEGRAM])
      .mockResolvedValueOnce([TELEGRAM]);
    vi.mocked(revokeAppApproval).mockRejectedValue(new ApiError("App approval not found", 404));
    render(<AppApprovals />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke Calendar (this browser)" }));

    await waitFor(() => expect(screen.queryByText("Calendar")).not.toBeInTheDocument());
    expect(listAppApprovals).toHaveBeenCalledTimes(2);
    expect(screen.getByText("Reminders")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("reports a failed load with a way to try again", async () => {
    vi.mocked(listAppApprovals)
      .mockRejectedValueOnce(new Error("Request failed: Bad Gateway"))
      .mockResolvedValueOnce([HERE]);
    render(<AppApprovals />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed: Bad Gateway");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("Calendar")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
