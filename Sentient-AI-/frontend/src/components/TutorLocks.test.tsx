/**
 * Tests for TutorLocks (Settings ▸ Permissions ▸ Tutor locks, owner only): they prove each lock is
 * listed with what it locks and who it applies to, that a lock is added from a course picked in the
 * owner's Canvas (or typed) with its aliases, that the server's reason for refusing one is shown
 * beside the form, that Remove asks first and removes only its own row, that the switch being off is
 * said plainly, and that the picker is hidden without Canvas.
 *
 * Why it exists: locks are the owner's only control over tutor mode. A form that sent the wrong
 * course, a refusal the owner never saw, or a lock removed without asking would each leave a
 * student's chats in a state the owner did not choose.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { TutorLock } from "@/types";

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
    listTutorLocks: vi.fn(async () => ({ enabled: true, locks: [] })),
    createTutorLock: vi.fn(),
    deleteTutorLock: vi.fn(),
    listTutorCanvasCourses: vi.fn(async () => ({ available: false, courses: [] })),
  };
});

import TutorLocks from "@/components/TutorLocks";
import {
  ApiError,
  createTutorLock,
  deleteTutorLock,
  listTutorCanvasCourses,
  listTutorLocks,
} from "@/services/api";

function lock(overrides: Partial<TutorLock>): TutorLock {
  return {
    id: "l1",
    scope: "course",
    user_id: null,
    applies_to: "every account",
    label: "MATH 221",
    canvas_course_id: "5",
    course_code: "MATH 221",
    course_name: "Calculus I",
    aliases: ["calc one"],
    created_at: "2026-09-30T12:00:00Z",
    ...overrides,
  };
}

const MATH = lock({});
const KID = lock({
  id: "l2",
  scope: "account",
  user_id: "u2",
  applies_to: "kid@example.com",
  label: "this account",
  canvas_course_id: null,
  course_code: null,
  course_name: null,
  aliases: [],
});

describe("TutorLocks", () => {
  afterEach(() => {
    vi.mocked(listTutorLocks).mockReset();
    vi.mocked(listTutorLocks).mockResolvedValue({ enabled: true, locks: [] });
    vi.mocked(createTutorLock).mockReset();
    vi.mocked(deleteTutorLock).mockReset();
    vi.mocked(listTutorCanvasCourses).mockReset();
    vi.mocked(listTutorCanvasCourses).mockResolvedValue({ available: false, courses: [] });
  });

  it("lists each lock with what it locks and who it applies to", async () => {
    vi.mocked(listTutorLocks).mockResolvedValue({ enabled: true, locks: [MATH, KID] });
    render(<TutorLocks />);

    expect(screen.getByRole("region", { name: "Tutor locks" })).toBeInTheDocument();
    expect(screen.getByText("Loading tutor locks…")).toBeInTheDocument();
    await screen.findByText("MATH 221");
    expect(screen.getAllByRole("listitem").map((row) => row.textContent)).toEqual([
      "MATH 221MATH 221 · Calculus I · Canvas course 5 · applies to every account · also “calc one”Remove",
      "this accountEvery chat · applies to kid@example.comRemove",
    ]);
    expect(screen.queryByText("Tutor mode is off, so these locks do nothing.")).not.toBeInTheDocument();
  });

  it("says plainly when the tutor mode switch is off", async () => {
    vi.mocked(listTutorLocks).mockResolvedValue({ enabled: false, locks: [MATH] });
    render(<TutorLocks />);

    expect(await screen.findByText("Tutor mode is off, so these locks do nothing.")).toBeInTheDocument();
  });

  it("adds a lock for a course picked from Canvas, with its aliases", async () => {
    vi.mocked(listTutorCanvasCourses).mockResolvedValue({
      available: true,
      courses: [{ id: "5", name: "Calculus I", course_code: "MATH 221" }],
    });
    vi.mocked(createTutorLock).mockResolvedValue(MATH);
    render(<TutorLocks />);

    const picker = await screen.findByLabelText("Course from your Canvas");
    fireEvent.change(picker, { target: { value: "5" } });
    expect(screen.getByLabelText("Course code")).toHaveValue("MATH 221");
    expect(screen.getByLabelText("Canvas course id")).toHaveValue("5");
    fireEvent.change(screen.getByLabelText(/Other names/), { target: { value: " calc one , , calculus 1 " } });
    fireEvent.change(screen.getByLabelText("Applies to"), { target: { value: "email" } });
    fireEvent.change(screen.getByLabelText("Account email"), { target: { value: "kid@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add lock" }));

    await screen.findByText("MATH 221", { selector: "p" });
    expect(vi.mocked(createTutorLock).mock.calls).toEqual([
      [
        {
          scope: "course",
          applies_to: "email",
          email: "kid@example.com",
          canvas_course_id: "5",
          course_code: "MATH 221",
          course_name: "Calculus I",
          aliases: ["calc one", "calculus 1"],
        },
      ],
    ]);
    await waitFor(() => expect(screen.getByLabelText("Course code")).toHaveValue(""));
  });

  it("adds a whole-account lock with no course fields and hides the picker without Canvas", async () => {
    vi.mocked(createTutorLock).mockResolvedValue(KID);
    render(<TutorLocks />);

    await screen.findByText(/No tutor locks/);
    expect(screen.queryByLabelText("Course from your Canvas")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Lock"), { target: { value: "account" } });
    expect(screen.queryByLabelText("Course code")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add lock" }));

    await waitFor(() =>
      expect(vi.mocked(createTutorLock).mock.calls).toEqual([[{ scope: "account", applies_to: "all" }]]),
    );
  });

  it("shows the server's reason when a lock is refused, and keeps what was typed", async () => {
    vi.mocked(createTutorLock).mockRejectedValue(
      new ApiError("The course code is too general: it would lock chats that only mention it.", 422),
    );
    render(<TutorLocks />);

    await screen.findByText(/No tutor locks/);
    fireEvent.change(screen.getByLabelText("Course code"), { target: { value: "math" } });
    fireEvent.click(screen.getByRole("button", { name: "Add lock" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("too general");
    expect(screen.getByLabelText("Course code")).toHaveValue("math");
    expect(screen.queryAllByRole("listitem")).toEqual([]);
  });

  it("refuses more than five aliases before asking the server", async () => {
    render(<TutorLocks />);

    await screen.findByText(/No tutor locks/);
    fireEvent.change(screen.getByLabelText("Course code"), { target: { value: "MATH 221" } });
    fireEvent.change(screen.getByLabelText(/Other names/), { target: { value: "aaa, bbb, ccc, ddd, eee, fff" } });
    fireEvent.click(screen.getByRole("button", { name: "Add lock" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("at most 5 aliases");
    expect(createTutorLock).not.toHaveBeenCalled();
  });

  it("asks before removing a lock and removes only its own row", async () => {
    vi.mocked(listTutorLocks).mockResolvedValue({ enabled: true, locks: [MATH, KID] });
    vi.mocked(deleteTutorLock).mockResolvedValue(undefined);
    render(<TutorLocks />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove the MATH 221 lock (every account)" }));
    const dialog = await screen.findByRole("dialog");
    expect(deleteTutorLock).not.toHaveBeenCalled();
    expect(dialog).toHaveTextContent("Chats locked for MATH 221 go back to each person's own tutor mode switch.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(vi.mocked(deleteTutorLock).mock.calls).toEqual([["l1"]]);
    expect(screen.getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByText("this account")).toBeInTheDocument();
  });

  it("keeps the lock when removing it fails, with the reason in the dialog", async () => {
    vi.mocked(listTutorLocks).mockResolvedValue({ enabled: true, locks: [MATH] });
    vi.mocked(deleteTutorLock).mockRejectedValue(new ApiError("No such tutor lock.", 404));
    render(<TutorLocks />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove the MATH 221 lock (every account)" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    expect(await within(dialog).findByText("No such tutor lock.")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(1);
  });

  it("can retry a failed load", async () => {
    vi.mocked(listTutorLocks)
      .mockRejectedValueOnce(new ApiError("Only the owner of this install can change this.", 403))
      .mockResolvedValueOnce({ enabled: true, locks: [MATH] });
    render(<TutorLocks />);

    fireEvent.click(await screen.findByRole("button", { name: "Try again" }));
    expect(await screen.findByText("MATH 221", { selector: "p" })).toBeInTheDocument();
  });
});
