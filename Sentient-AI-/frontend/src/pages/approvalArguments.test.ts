/**
 * Tests for shownArguments: a desktop.act card leaves out the screen the backend stored with it,
 * and every other tool's arguments are shown whole.
 *
 * Why it exists: Guards against the reserved "_screen" key cluttering the card a person approves
 * from, and against the rule spreading to tools where a key starting with "_" could be a real
 * argument the person would then approve without seeing.
 */

import { describe, expect, it } from "vitest";
import { shownArguments } from "@/pages/approvalArguments";
import type { PendingApproval } from "@/types";

function approval(tool_name: string, args: Record<string, unknown>): PendingApproval {
  return { action_id: "a1", tool_name, arguments: args, reason: "r" };
}

describe("shownArguments", () => {
  it("leaves the stored screen out of a desktop.act card", () => {
    const shown = shownArguments(
      approval("desktop.act", {
        action: "click",
        ref: "d3",
        _screen: { app: "Mail", outline: "9f2c1a" },
      }),
    );
    expect(shown).toEqual({ action: "click", ref: "d3" });
  });

  it("shows every argument of any other tool", () => {
    const args = { query: "x", _private_flag: true };
    expect(shownArguments(approval("mcp.github.search", args))).toEqual(args);
  });

  it("copes with a card that has no arguments", () => {
    const bare = { action_id: "a2", tool_name: "desktop.act", reason: "r" } as PendingApproval;
    expect(shownArguments(bare)).toEqual({});
  });
});
