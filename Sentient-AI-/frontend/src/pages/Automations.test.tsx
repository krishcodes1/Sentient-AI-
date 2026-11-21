/**
 * Tests for the Automations page: it lists the user's scheduled tasks, reminders and triggers,
 * pauses a task, shows the server's own sentence when an action is refused, and creates a task
 * with only the tools that were ticked and the browser's time zone.
 *
 * Why it exists: a task created here runs unattended with exactly the tools it lists, so the form
 * must send what the person chose, and a refusal (the switch is off) must reach them as written.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/services/api", () => ({
  browserTimeZone: () => "America/New_York",
  listSchedules: vi.fn(),
  listReminders: vi.fn(),
  listTriggers: vi.fn(),
  listScheduleTools: vi.fn(),
  createSchedule: vi.fn(),
  createReminder: vi.fn(),
  cancelReminder: vi.fn(),
  deleteSchedule: vi.fn(),
  deleteTrigger: vi.fn(),
  runScheduleNow: vi.fn(),
  setSchedulePaused: vi.fn(),
  setTriggerPaused: vi.fn(),
}));

import Automations from "@/pages/Automations";
import * as api from "@/services/api";

const mocked = vi.mocked(api);

beforeEach(() => {
  vi.clearAllMocks();
  mocked.listSchedules.mockResolvedValue({
    timezone: "America/New_York",
    count: 1,
    tasks: [
      {
        id: "t1",
        kind: "prompt",
        label: "Canvas summary",
        schedule: "every weekday at 08:00",
        timezone: "America/New_York",
        status: "active",
        next_run_local: "Mon 2026-11-23 08:00",
        last_run_local: null,
        last_status: null,
        prompt: "Summarise Canvas",
      },
    ],
  });
  mocked.listReminders.mockResolvedValue([
    { id: "r1", title: "Submit lab", note: null, due_at: "2026-11-21T14:00:00Z", status: "scheduled" },
  ]);
  mocked.listTriggers.mockResolvedValue([
    {
      id: "g1",
      label: "Grades",
      source: "canvas.grade",
      when: "a new grade is posted on Canvas",
      account: null,
      mode: "notify",
      status: "active",
      last_fired_at: null,
    },
  ]);
  mocked.listScheduleTools.mockResolvedValue([
    { name: "canvas.get_upcoming", description: "What's due" },
    { name: "web.search", description: "Search the web" },
  ]);
});

describe("Automations page", () => {
  it("lists everything and pauses a task", async () => {
    render(<Automations />);
    expect(await screen.findByText("Canvas summary")).toBeTruthy();
    expect(screen.getByText("Submit lab")).toBeTruthy();
    expect(screen.getByText("When a new grade is posted on Canvas: messages you")).toBeTruthy();

    mocked.setSchedulePaused.mockResolvedValue();
    fireEvent.click(screen.getByRole("button", { name: "Pause Canvas summary" }));
    await waitFor(() => expect(mocked.setSchedulePaused).toHaveBeenCalledWith("t1", true));
  });

  it("says the task started after Run now", async () => {
    mocked.runScheduleNow.mockResolvedValue();
    render(<Automations />);
    fireEvent.click(await screen.findByRole("button", { name: "Run Canvas summary now" }));
    expect(await screen.findByText(/Started "Canvas summary"/)).toBeTruthy();
  });

  it("shows the server's sentence when an action is refused", async () => {
    mocked.runScheduleNow.mockRejectedValue(new Error("Scheduled tasks are turned off."));
    render(<Automations />);
    fireEvent.click(await screen.findByRole("button", { name: "Run Canvas summary now" }));
    expect(await screen.findByText("Scheduled tasks are turned off.")).toBeTruthy();
  });

  it("creates a task with the ticked tools and the browser's zone", async () => {
    mocked.createSchedule.mockResolvedValue();
    render(<Automations />);
    fireEvent.click(await screen.findByRole("button", { name: /New task/ }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Due soon" } });
    fireEvent.change(screen.getByLabelText("What should Crawler do?"), { target: { value: "List what's due" } });
    fireEvent.click(await screen.findByRole("checkbox", { name: /get upcoming/ }));
    fireEvent.click(screen.getByRole("button", { name: /Save task/ }));

    await waitFor(() =>
      expect(mocked.createSchedule).toHaveBeenCalledWith({
        label: "Due soon",
        prompt: "List what's due",
        freq: "weekdays",
        time: "08:00",
        tools: ["canvas.get_upcoming"],
        timezone: "America/New_York",
      }),
    );
  });
});
