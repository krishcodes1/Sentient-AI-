/**
 * Tests for the Goals page: a loading line, then one card per goal with its category, target date,
 * where it stands and a progress bar read out as "2 of 5 milestones done"; the empty state that
 * points to the chat; the status filter; the New goal form with its first milestones; opening a
 * plan to tick, drop and add milestones; the progress log with who wrote each note and Add note;
 * Pause; Delete only after its confirm step; and the server's reason shown when it refuses. A
 * change keeps the log already loaded (its answer carries only the newest notes), a note never
 * goes to a milestone dropped after it was picked, and a change that answers after the user picked
 * another filter is judged against the list shown then.
 *
 * Why it exists: The page and the goals.* tools share one store, so the page must send exactly the
 * change the click meant (complete, not reopen; this milestone, not that one) and show the server's
 * own reason for a refusal. A Delete that skipped its confirm step would lose a goal's whole plan
 * and log on one stray click.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Goal, GoalDetail } from "@/types";

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
    listGoals: vi.fn(async () => []),
    getGoal: vi.fn(),
    createGoal: vi.fn(),
    updateGoal: vi.fn(),
    addGoalEntry: vi.fn(),
    deleteGoal: vi.fn(),
  };
});

import GoalsPage from "@/pages/Goals";
import {
  addGoalEntry,
  ApiError,
  createGoal,
  deleteGoal,
  getGoal,
  listGoals,
  updateGoal,
} from "@/services/api";

function goal(overrides: Partial<Goal>): Goal {
  return {
    id: "g1",
    title: "Run a 10k",
    description: null,
    category: "health",
    status: "active",
    current_state: "Running 5k twice a week",
    target_date: "2026-12-01",
    check_in: "weekly",
    created_at: "2026-10-01T09:00:00Z",
    updated_at: "2026-10-10T09:00:00Z",
    completed_at: null,
    progress: { done: 2, total: 5 },
    ...overrides,
  };
}

const RUN = goal({});
const SAVE = goal({
  id: "g2",
  title: "Save for a laptop",
  category: "money",
  current_state: null,
  target_date: null,
  check_in: "none",
  progress: { done: 0, total: 0 },
});

const RUN_DETAIL: GoalDetail = {
  ...RUN,
  description: "Finish the city 10k in under an hour.",
  progress: { done: 1, total: 2 },
  milestones: [
    { id: "m1", title: "Run 5k", due_date: null, state: "done", position: 0, done_at: "2026-10-05T09:00:00Z" },
    { id: "m2", title: "Run 8k", due_date: "2026-11-01", state: "open", position: 1, done_at: null },
    { id: "m3", title: "Buy shoes", due_date: null, state: "dropped", position: 2, done_at: null },
  ],
  entries: [
    { id: "e1", note: "Ran 5k", source: "user", milestone_id: "m1", created_at: "2026-10-05T09:00:00Z" },
    {
      id: "e2",
      note: "Planned the week",
      source: "agent",
      milestone_id: null,
      created_at: "2026-10-08T09:00:00Z",
    },
  ],
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

/** The same words the page uses for a "YYYY-MM-DD" day. */
function day(year: number, month: number, date: number): string {
  return new Date(year, month - 1, date).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

async function card(title: string) {
  return screen.findByRole("article", { name: title });
}

async function openPlan(title: string) {
  const article = await card(title);
  fireEvent.click(within(article).getByRole("button", { name: `Plan and notes for ${title}` }));
  await within(article).findByRole("heading", { name: "Milestones" });
  return within(article);
}

describe("Goals page", () => {
  it("shows a loading line, then one card per goal with its category, target, state and progress", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN, SAVE]);
    render(<GoalsPage />);

    expect(screen.getByText("Loading goals…")).toBeInTheDocument();

    const run = within(await card("Run a 10k"));
    expect(run.getByText("Health")).toBeInTheDocument();
    expect(run.getByText(`Target ${day(2026, 12, 1)}`)).toBeInTheDocument();
    expect(run.getByText("· Weekly check-in")).toBeInTheDocument();
    expect(run.getByText("Running 5k twice a week")).toBeInTheDocument();
    const bar = run.getByRole("progressbar", { name: "Progress on Run a 10k" });
    expect(bar).toHaveAttribute("aria-valuenow", "2");
    expect(bar).toHaveAttribute("aria-valuemax", "5");
    expect(bar).toHaveAttribute("aria-valuetext", "2 of 5 milestones done");
    expect(run.getByText("2 of 5 milestones done")).toBeInTheDocument();

    const save = within(await card("Save for a laptop"));
    expect(save.getByText("Money")).toBeInTheDocument();
    expect(save.getByText("No target date")).toBeInTheDocument();
    expect(save.getByText("No milestones yet")).toBeInTheDocument();
    expect(save.queryByRole("progressbar")).not.toBeInTheDocument();

    expect(listGoals).toHaveBeenCalledWith("active");
  });

  it("explains goals and points to the chat when there are none", async () => {
    render(<GoalsPage />);

    expect(await screen.findByText("No active goals.")).toBeInTheDocument();
    expect(
      screen.getByText("Tell Crawler about a goal in chat and it can set one up with you."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });

  it("reads the goals again for another status", async () => {
    vi.mocked(listGoals).mockResolvedValueOnce([RUN]).mockResolvedValueOnce([]);
    render(<GoalsPage />);
    await card("Run a 10k");

    const group = screen.getByRole("group", { name: "Show goals" });
    fireEvent.click(within(group).getByRole("button", { name: "Paused" }));

    expect(await screen.findByText(/^No paused goals\./)).toBeInTheDocument();
    expect(within(group).getByRole("button", { name: "Paused" })).toHaveAttribute("aria-pressed", "true");
    expect(within(group).getByRole("button", { name: "Active" })).toHaveAttribute("aria-pressed", "false");
    expect(vi.mocked(listGoals).mock.calls).toEqual([["active"], ["paused"]]);
  });

  it("creates a goal with its first milestones and puts it at the top", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    const created: GoalDetail = {
      ...goal({
        id: "g3",
        title: "Pass calculus",
        category: "school",
        current_state: null,
        target_date: "2026-12-15",
        check_in: "none",
        progress: { done: 0, total: 1 },
      }),
      milestones: [],
      entries: [],
    };
    vi.mocked(createGoal).mockResolvedValue(created);
    render(<GoalsPage />);
    await card("Run a 10k");

    const open = screen.getByRole("button", { name: "New goal" });
    expect(open).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(open);
    expect(open).toHaveAttribute("aria-expanded", "true");
    const form = within(screen.getByRole("region", { name: "New goal" }));

    fireEvent.change(form.getByLabelText("Title"), { target: { value: "  Pass calculus " } });
    fireEvent.change(form.getByLabelText("Category"), { target: { value: "school" } });
    fireEvent.change(form.getByLabelText("Target date (optional)"), { target: { value: "2026-12-15" } });
    fireEvent.change(form.getByLabelText("Description (optional)"), { target: { value: "A or B." } });
    for (let i = 0; i < 3; i += 1) fireEvent.click(form.getByRole("button", { name: "Add a milestone" }));
    fireEvent.change(form.getByRole("textbox", { name: "Milestone 1" }), { target: { value: "Read ch. 1" } });
    fireEvent.change(form.getByLabelText("Milestone 1 Due date"), { target: { value: "2026-11-01" } });
    fireEvent.change(form.getByRole("textbox", { name: "Milestone 2" }), { target: { value: "Drop me" } });
    // Removing the second row renumbers the third; left blank, it is no milestone at all.
    fireEvent.click(form.getByRole("button", { name: "Remove milestone 2" }));
    expect(form.getByRole("textbox", { name: "Milestone 2" })).toHaveValue("");
    fireEvent.click(form.getByRole("button", { name: "Save goal" }));

    await waitFor(() => expect(createGoal).toHaveBeenCalledTimes(1));
    expect(vi.mocked(createGoal).mock.calls[0][0]).toEqual({
      title: "Pass calculus",
      category: "school",
      target_date: "2026-12-15",
      description: "A or B.",
      milestones: [{ title: "Read ch. 1", due_date: "2026-11-01" }],
    });
    await waitFor(() =>
      expect(screen.queryByRole("region", { name: "New goal" })).not.toBeInTheDocument(),
    );
    const articles = screen.getAllByRole("article");
    expect(articles).toHaveLength(2);
    expect(articles[0]).toHaveAccessibleName("Pass calculus");
    expect(screen.getByText("Saved “Pass calculus”.")).toBeInTheDocument();
  });

  it("keeps the form and shows the server's reason when it refuses the goal", async () => {
    vi.mocked(createGoal).mockRejectedValue(
      new ApiError("You already have an active goal called “Run a 10k”; update it instead.", 409),
    );
    render(<GoalsPage />);
    await screen.findByText("No active goals.");

    fireEvent.click(screen.getByRole("button", { name: "New goal" }));
    const form = within(screen.getByRole("region", { name: "New goal" }));
    fireEvent.click(form.getByRole("button", { name: "Save goal" }));
    expect(form.getByRole("alert")).toHaveTextContent("Give the goal a title.");
    expect(createGoal).not.toHaveBeenCalled();

    fireEvent.change(form.getByLabelText("Title"), { target: { value: "Run a 10k" } });
    fireEvent.click(form.getByRole("button", { name: "Save goal" }));

    await waitFor(() =>
      expect(form.getByRole("alert")).toHaveTextContent(
        "You already have an active goal called “Run a 10k”; update it instead.",
      ),
    );
    expect(form.getByLabelText("Title")).toHaveValue("Run a 10k");
    expect(vi.mocked(createGoal).mock.calls).toEqual([[{ title: "Run a 10k", category: "other" }]]);
  });

  it("opens a goal's plan on demand and ticks a milestone off through updateGoal", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    vi.mocked(getGoal).mockResolvedValue(RUN_DETAIL);
    vi.mocked(updateGoal).mockResolvedValue({
      ...RUN_DETAIL,
      progress: { done: 2, total: 2 },
      milestones: RUN_DETAIL.milestones.map((m) =>
        m.id === "m2" ? { ...m, state: "done", done_at: "2026-10-12T09:00:00Z" } : m,
      ),
    });
    render(<GoalsPage />);
    await card("Run a 10k");
    expect(getGoal).not.toHaveBeenCalled();

    const plan = await openPlan("Run a 10k");
    expect(vi.mocked(getGoal).mock.calls).toEqual([["g1"]]);
    expect(plan.getByText("Finish the city 10k in under an hour.")).toBeInTheDocument();
    expect(plan.getByRole("checkbox", { name: "Run 5k" })).toBeChecked();
    expect(plan.getByRole("checkbox", { name: "Buy shoes" })).toBeDisabled();
    const next = plan.getByRole("checkbox", { name: "Run 8k" });
    expect(next).not.toBeChecked();
    expect(next).toHaveAccessibleDescription(`Due ${day(2026, 11, 1)}`);

    fireEvent.click(next);

    await waitFor(() => expect(plan.getByRole("checkbox", { name: "Run 8k" })).toBeChecked());
    expect(vi.mocked(updateGoal).mock.calls).toEqual([["g1", { complete_milestones: ["m2"] }]]);
    expect(plan.getByText("2 of 2 milestones done")).toBeInTheDocument();
  });

  it("keeps the whole progress log when a change answers with only the newest notes", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    vi.mocked(getGoal).mockResolvedValue(RUN_DETAIL);
    // PATCH answers with fewer notes than GET (10 against 50 on the server).
    vi.mocked(updateGoal).mockResolvedValue({
      ...RUN_DETAIL,
      progress: { done: 2, total: 2 },
      milestones: RUN_DETAIL.milestones.map((m) =>
        m.id === "m2" ? { ...m, state: "done", done_at: "2026-10-12T09:00:00Z" } : m,
      ),
      entries: [RUN_DETAIL.entries[1]],
    });
    render(<GoalsPage />);

    const plan = await openPlan("Run a 10k");
    const log = plan.getByRole("list", { name: "Progress log for Run a 10k" });
    expect(within(log).getAllByRole("listitem")).toHaveLength(2);
    fireEvent.click(plan.getByRole("checkbox", { name: "Run 8k" }));

    await waitFor(() => expect(plan.getByRole("checkbox", { name: "Run 8k" })).toBeChecked());
    expect(within(log).getAllByRole("listitem").map((row) => row.querySelector("p")?.textContent)).toEqual([
      "Planned the week",
      "Ran 5k",
    ]);
  });

  it("loads the plan in full when it is opened after a change made from the card", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    vi.mocked(getGoal).mockResolvedValue({ ...RUN_DETAIL, status: "paused" });
    vi.mocked(updateGoal).mockResolvedValue({
      ...RUN_DETAIL,
      status: "paused",
      entries: [RUN_DETAIL.entries[1]],
    });
    render(<GoalsPage />);
    fireEvent.click(within(screen.getByRole("group", { name: "Show goals" })).getByRole("button", { name: "All" }));

    fireEvent.click(within(await card("Run a 10k")).getByRole("button", { name: "Pause goal: Run a 10k" }));
    await within(await card("Run a 10k")).findByRole("button", { name: "Resume goal: Run a 10k" });
    expect(getGoal).not.toHaveBeenCalled();

    const plan = await openPlan("Run a 10k");
    expect(vi.mocked(getGoal).mock.calls).toEqual([["g1"]]);
    const log = plan.getByRole("list", { name: "Progress log for Run a 10k" });
    expect(within(log).getAllByRole("listitem")).toHaveLength(2);
  });

  it("reopens a done milestone, drops an open one and restores a dropped one", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    vi.mocked(getGoal).mockResolvedValue(RUN_DETAIL);
    vi.mocked(updateGoal).mockResolvedValue(RUN_DETAIL);
    render(<GoalsPage />);

    const plan = await openPlan("Run a 10k");
    fireEvent.click(plan.getByRole("checkbox", { name: "Run 5k" }));
    await waitFor(() => expect(updateGoal).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(plan.getByRole("button", { name: "Drop milestone: Run 8k" })).toBeEnabled());
    fireEvent.click(plan.getByRole("button", { name: "Drop milestone: Run 8k" }));
    await waitFor(() => expect(updateGoal).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(plan.getByRole("button", { name: "Restore milestone: Buy shoes" })).toBeEnabled(),
    );
    fireEvent.click(plan.getByRole("button", { name: "Restore milestone: Buy shoes" }));
    await waitFor(() => expect(updateGoal).toHaveBeenCalledTimes(3));

    expect(vi.mocked(updateGoal).mock.calls).toEqual([
      ["g1", { reopen_milestones: ["m1"] }],
      ["g1", { drop_milestones: ["m2"] }],
      ["g1", { reopen_milestones: ["m3"] }],
    ]);
  });

  it("adds a milestone to an open goal", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    vi.mocked(getGoal).mockResolvedValue(RUN_DETAIL);
    vi.mocked(updateGoal).mockResolvedValue({
      ...RUN_DETAIL,
      milestones: [
        ...RUN_DETAIL.milestones,
        { id: "m4", title: "Run 10k", due_date: "2026-11-20", state: "open", position: 3, done_at: null },
      ],
    });
    render(<GoalsPage />);

    const plan = await openPlan("Run a 10k");
    const form = within(plan.getByRole("form", { name: "Add a milestone to Run a 10k" }));
    fireEvent.change(form.getByLabelText("New milestone"), { target: { value: " Run 10k " } });
    fireEvent.change(form.getByLabelText("Due date (optional)"), { target: { value: "2026-11-20" } });
    fireEvent.click(form.getByRole("button", { name: "Add milestone" }));

    expect(await plan.findByRole("checkbox", { name: "Run 10k" })).not.toBeChecked();
    expect(vi.mocked(updateGoal).mock.calls).toEqual([
      ["g1", { add_milestones: [{ title: "Run 10k", due_date: "2026-11-20" }] }],
    ]);
    expect(form.getByLabelText("New milestone")).toHaveValue("");
  });

  it("lists the progress log newest first with who wrote each note, and adds a note", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    vi.mocked(getGoal).mockResolvedValue(RUN_DETAIL);
    vi.mocked(addGoalEntry).mockResolvedValue({
      id: "e3",
      note: "Ran 6k",
      source: "user",
      milestone_id: "m2",
      created_at: "2026-10-12T09:00:00Z",
    });
    render(<GoalsPage />);

    const plan = await openPlan("Run a 10k");
    const log = () => within(plan.getByRole("list", { name: "Progress log for Run a 10k" }));
    const notes = () =>
      log()
        .getAllByRole("listitem")
        .map((row) => [within(row).getByText(/^(You|Crawler)$/).textContent, row.querySelector("p")?.textContent]);
    expect(notes()).toEqual([
      ["Crawler", "Planned the week"],
      ["You", "Ran 5k"],
    ]);
    expect(log().getAllByRole("listitem")[1]).toHaveTextContent("on “Run 5k”");

    const form = within(plan.getByRole("form", { name: "Add a note to Run a 10k" }));
    // A dropped milestone is no longer something to log against.
    expect(
      within(form.getByLabelText("About a milestone (optional)"))
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["The whole goal", "Run 5k", "Run 8k"]);
    fireEvent.change(form.getByLabelText("Note"), { target: { value: "Ran 6k " } });
    fireEvent.change(form.getByLabelText("About a milestone (optional)"), { target: { value: "m2" } });
    fireEvent.click(form.getByRole("button", { name: "Add note" }));

    await waitFor(() => expect(notes()[0]).toEqual(["You", "Ran 6k"]));
    expect(vi.mocked(addGoalEntry).mock.calls).toEqual([["g1", { note: "Ran 6k", milestone_id: "m2" }]]);
    expect(form.getByLabelText("Note")).toHaveValue("");
  });

  it("sends a note about the whole goal when its picked milestone was dropped meanwhile", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN]);
    vi.mocked(getGoal).mockResolvedValue(RUN_DETAIL);
    vi.mocked(updateGoal).mockResolvedValue({
      ...RUN_DETAIL,
      milestones: RUN_DETAIL.milestones.map((m) => (m.id === "m2" ? { ...m, state: "dropped" } : m)),
    });
    vi.mocked(addGoalEntry).mockResolvedValue({
      id: "e3",
      note: "Ran 6k",
      source: "user",
      milestone_id: null,
      created_at: "2026-10-12T09:00:00Z",
    });
    render(<GoalsPage />);

    const plan = await openPlan("Run a 10k");
    const form = within(plan.getByRole("form", { name: "Add a note to Run a 10k" }));
    const about = form.getByLabelText("About a milestone (optional)");
    fireEvent.change(form.getByLabelText("Note"), { target: { value: "Ran 6k" } });
    fireEvent.change(about, { target: { value: "m2" } });
    expect(about).toHaveValue("m2");

    fireEvent.click(plan.getByRole("button", { name: "Drop milestone: Run 8k" }));
    await plan.findByRole("button", { name: "Restore milestone: Run 8k" });
    expect(within(about).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "The whole goal",
      "Run 5k",
    ]);
    expect(about).toHaveValue("");
    fireEvent.click(form.getByRole("button", { name: "Add note" }));

    await waitFor(() => expect(addGoalEntry).toHaveBeenCalledTimes(1));
    expect(vi.mocked(addGoalEntry).mock.calls).toEqual([["g1", { note: "Ran 6k" }]]);
  });

  it("judges a change that answers after another filter was picked against the list shown now", async () => {
    vi.mocked(listGoals).mockResolvedValueOnce([RUN]).mockResolvedValueOnce([RUN, SAVE]);
    const answer = deferred<GoalDetail>();
    vi.mocked(updateGoal).mockReturnValue(answer.promise);
    render(<GoalsPage />);

    fireEvent.click(within(await card("Run a 10k")).getByRole("button", { name: "Pause goal: Run a 10k" }));
    fireEvent.click(within(screen.getByRole("group", { name: "Show goals" })).getByRole("button", { name: "All" }));
    await card("Save for a laptop");

    // The Pause sent on Active answers once All is on screen, where a paused goal still belongs.
    answer.resolve({ ...RUN_DETAIL, status: "paused" });
    const run = await card("Run a 10k");
    expect(await within(run).findByRole("button", { name: "Resume goal: Run a 10k" })).toBeInTheDocument();
    expect(screen.getAllByRole("article")).toHaveLength(2);
    expect(screen.getByRole("status")).toHaveTextContent("");
    expect(vi.mocked(listGoals).mock.calls).toEqual([["active"], ["all"]]);
  });

  it("pauses a goal, which leaves the Active list with a note saying so", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN, SAVE]);
    vi.mocked(updateGoal).mockResolvedValue({ ...RUN_DETAIL, status: "paused" });
    render(<GoalsPage />);

    fireEvent.click(within(await card("Run a 10k")).getByRole("button", { name: "Pause goal: Run a 10k" }));

    await waitFor(() => expect(screen.queryByRole("article", { name: "Run a 10k" })).not.toBeInTheDocument());
    expect(vi.mocked(updateGoal).mock.calls).toEqual([["g1", { status: "paused" }]]);
    expect(screen.getByRole("status")).toHaveTextContent("“Run a 10k” is now paused.");
    expect(screen.getByRole("article", { name: "Save for a laptop" })).toBeInTheDocument();
  });

  it("shows the server's reason beside the goal when a change is refused", async () => {
    vi.mocked(listGoals).mockResolvedValue([goal({ status: "paused" })]);
    vi.mocked(updateGoal).mockRejectedValue(
      new ApiError("You can have at most 25 active or paused goals.", 409),
    );
    render(<GoalsPage />);
    fireEvent.click(within(screen.getByRole("group", { name: "Show goals" })).getByRole("button", { name: "All" }));

    const run = await card("Run a 10k");
    expect(within(run).getByText("Paused")).toBeInTheDocument();
    fireEvent.click(within(run).getByRole("button", { name: "Resume goal: Run a 10k" }));

    expect(await within(run).findByRole("alert")).toHaveTextContent(
      "You can have at most 25 active or paused goals.",
    );
    expect(vi.mocked(updateGoal).mock.calls).toEqual([["g1", { status: "active" }]]);
  });

  it("asks before deleting, and deletes only when confirmed", async () => {
    vi.mocked(listGoals).mockResolvedValue([RUN, SAVE]);
    vi.mocked(deleteGoal)
      .mockRejectedValueOnce(new ApiError("Request failed: Internal Server Error", 500))
      .mockResolvedValueOnce(undefined);
    render(<GoalsPage />);
    const run = await card("Run a 10k");

    fireEvent.click(within(run).getByRole("button", { name: "Delete goal: Run a 10k" }));
    let dialog = within(screen.getByRole("dialog", { name: "Delete this goal?" }));
    expect(dialog.getByText(/“Run a 10k”, its milestones and its progress log/)).toBeInTheDocument();
    fireEvent.click(dialog.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(deleteGoal).not.toHaveBeenCalled();

    fireEvent.click(within(run).getByRole("button", { name: "Delete goal: Run a 10k" }));
    dialog = within(screen.getByRole("dialog", { name: "Delete this goal?" }));
    fireEvent.click(dialog.getByRole("button", { name: "Delete goal" }));
    // A failure keeps the dialog open with the reason, and the goal on the page.
    expect(await dialog.findByRole("alert")).toHaveTextContent("Request failed: Internal Server Error");
    expect(screen.getByRole("article", { name: "Run a 10k" })).toBeInTheDocument();

    fireEvent.click(dialog.getByRole("button", { name: "Delete goal" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(screen.queryByRole("article", { name: "Run a 10k" })).not.toBeInTheDocument();
    expect(vi.mocked(deleteGoal).mock.calls).toEqual([["g1"], ["g1"]]);
    expect(screen.getByRole("status")).toHaveTextContent("Deleted “Run a 10k”.");
    expect(screen.getByRole("article", { name: "Save for a laptop" })).toBeInTheDocument();
  });

  it("reports a failed load with a way to try again", async () => {
    vi.mocked(listGoals)
      .mockRejectedValueOnce(new Error("Request failed: Bad Gateway"))
      .mockResolvedValueOnce([RUN]);
    render(<GoalsPage />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed: Bad Gateway");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await card("Run a 10k")).toBeInTheDocument();
    expect(listGoals).toHaveBeenCalledTimes(2);
  });
});
