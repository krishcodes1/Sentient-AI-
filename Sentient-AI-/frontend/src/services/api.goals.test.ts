/**
 * Tests for the Goals and Skills calls: each hits its /api route with the right verb and body,
 * every id or name in a path is URL-encoded, the list filters default to `active`, a 204 delete
 * reads no body, and a 409 or 422 comes back as an ApiError carrying the server's own message
 * without signing anyone out.
 *
 * Why it exists: The Goals page and Settings ▸ Skills show the server's reason for a refusal as
 * is, so the message must survive the trip; and an unencoded id could reach a different route than
 * the one the click meant (a "/" or "?" in a path segment).
 */

import { beforeEach, describe, expect, it } from "vitest";
import {
  addGoalEntry,
  createGoal,
  deleteGoal,
  getGoal,
  getSkill,
  listGoals,
  listSkills,
  setSkillEnabled,
  updateGoal,
} from "@/services/api";
import { jsonResponse, mockFetch, stubLocation } from "@/test/http";
import type { Goal, GoalDetail, GoalEntry, SkillDetail, SkillInfo } from "@/types";

const GOAL: Goal = {
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
  progress: { done: 1, total: 3 },
};

const DETAIL: GoalDetail = { ...GOAL, milestones: [], entries: [] };

const SKILL: SkillInfo = {
  name: "wide-research",
  title: "Wide research",
  description: "Research a question across many sources.",
  category: "research",
  version: "1.0",
  license: null,
  source: "bundled",
  sha256: "a".repeat(64),
  status: "ok",
  status_reason: null,
  enabled: true,
  tools: ["web.search"],
  requires: { connectors: [], capabilities: ["web_browsing"] },
  findings: [],
};

/** A 204 whose body must never be read. */
function noContent(): Response {
  return {
    ok: true,
    status: 204,
    statusText: "No Content",
    json: async () => {
      throw new Error("204 has no body to parse");
    },
  } as unknown as Response;
}

function call(fetchMock: ReturnType<typeof mockFetch>, index = 0) {
  const [url, init] = fetchMock.mock.calls[index];
  return {
    url,
    method: init?.method,
    body: init?.body === undefined ? undefined : JSON.parse(String(init.body)),
  };
}

describe("goals api", () => {
  beforeEach(() => {
    stubLocation("/goals");
    localStorage.clear();
  });

  it("lists active goals by default and passes any other status through", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, [GOAL]));

    await expect(listGoals()).resolves.toEqual([GOAL]);
    await listGoals("all");
    await listGoals("paused");

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/goals?status=active",
      "/api/goals?status=all",
      "/api/goals?status=paused",
    ]);
    expect(call(fetchMock).method).toBeUndefined();
  });

  it("reads one goal by its encoded id", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, DETAIL));

    await expect(getGoal("g1")).resolves.toEqual(DETAIL);
    await getGoal("a/b?c");

    expect(call(fetchMock).url).toBe("/api/goals/g1");
    expect(call(fetchMock, 1).url).toBe("/api/goals/a%2Fb%3Fc");
    expect(call(fetchMock, 1).method).toBeUndefined();
  });

  it("creates a goal with a POST of exactly the body it was given", async () => {
    const fetchMock = mockFetch(() => jsonResponse(201, DETAIL));
    const body = {
      title: "Run a 10k",
      category: "health" as const,
      target_date: "2026-12-01",
      milestones: [{ title: "Run 5k", due_date: "2026-10-31" }, { title: "Run 8k" }],
    };

    await expect(createGoal(body)).resolves.toEqual(DETAIL);

    expect(call(fetchMock)).toEqual({ url: "/api/goals", method: "POST", body });
  });

  it("updates a goal with a PATCH to its encoded id", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, DETAIL));

    await updateGoal("g 1", { status: "paused", complete_milestones: ["m1"] });

    expect(call(fetchMock)).toEqual({
      url: "/api/goals/g%201",
      method: "PATCH",
      body: { status: "paused", complete_milestones: ["m1"] },
    });
  });

  it("adds a progress note with a POST to the goal's entries", async () => {
    const entry: GoalEntry = {
      id: "e1",
      note: "Ran 6k",
      source: "user",
      milestone_id: "m1",
      created_at: "2026-10-12T09:00:00Z",
    };
    const fetchMock = mockFetch(() => jsonResponse(201, entry));

    await expect(addGoalEntry("g/1", { note: "Ran 6k", milestone_id: "m1" })).resolves.toEqual(
      entry,
    );

    expect(call(fetchMock)).toEqual({
      url: "/api/goals/g%2F1/entries",
      method: "POST",
      body: { note: "Ran 6k", milestone_id: "m1" },
    });
  });

  it("deletes a goal with DELETE and no body, reading nothing from the 204", async () => {
    const fetchMock = mockFetch(() => noContent());

    await expect(deleteGoal("g1")).resolves.toBeUndefined();

    expect(call(fetchMock)).toEqual({ url: "/api/goals/g1", method: "DELETE", body: undefined });
  });

  it("hands back the server's 409 and 422 messages without signing the user out", async () => {
    const { replace } = stubLocation("/goals");
    localStorage.setItem("auth_token", "still-valid");
    mockFetch(() =>
      jsonResponse(409, { detail: "You already have an active goal with this title; update it instead." }),
    );

    await expect(createGoal({ title: "Run a 10k" })).rejects.toMatchObject({
      name: "ApiError",
      status: 409,
      message: "You already have an active goal with this title; update it instead.",
    });

    mockFetch(() => jsonResponse(422, { detail: "Crawler never saves passwords in a goal." }));
    await expect(addGoalEntry("g1", { note: "A note it refuses" })).rejects.toMatchObject({
      status: 422,
      message: "Crawler never saves passwords in a goal.",
    });
    expect(replace).not.toHaveBeenCalled();
    expect(localStorage.getItem("auth_token")).toBe("still-valid");
  });
});

describe("skills api", () => {
  beforeEach(() => {
    stubLocation("/settings");
    localStorage.clear();
  });

  it("lists the skills with a plain GET", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, [SKILL]));

    await expect(listSkills()).resolves.toEqual([SKILL]);

    expect(call(fetchMock)).toEqual({ url: "/api/skills", method: undefined, body: undefined });
  });

  it("reads one skill by its encoded name", async () => {
    const detail: SkillDetail = { ...SKILL, files: [{ path: "SKILL.md", text: "# Wide research" }] };
    const fetchMock = mockFetch(() => jsonResponse(200, detail));

    await expect(getSkill("wide-research")).resolves.toEqual(detail);
    await getSkill("../x y");

    expect(call(fetchMock).url).toBe("/api/skills/wide-research");
    expect(call(fetchMock, 1).url).toBe("/api/skills/..%2Fx%20y");
  });

  it("switches a skill with a PATCH whose body is only the new state", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, { ...SKILL, enabled: false }));

    await expect(setSkillEnabled("wide-research", false)).resolves.toMatchObject({ enabled: false });

    expect(call(fetchMock)).toEqual({
      url: "/api/skills/wide-research",
      method: "PATCH",
      body: { enabled: false },
    });
  });

  it("hands back the 409 for a skill that cannot be switched on", async () => {
    mockFetch(() => jsonResponse(409, { detail: "This skill is blocked and cannot be enabled." }));

    await expect(setSkillEnabled("bad-skill", true)).rejects.toMatchObject({
      name: "ApiError",
      status: 409,
      message: "This skill is blocked and cannot be enabled.",
    });
  });
});
