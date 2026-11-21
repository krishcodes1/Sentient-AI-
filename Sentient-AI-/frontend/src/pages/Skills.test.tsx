/**
 * Tests for the Skills page: the name field keeps to the server's slug form, a new skill is sent
 * trimmed and appears in the list, the switch turns a skill off, and a refused save shows the
 * server's own sentence.
 *
 * Why it exists: the server refuses a name that is not a slug and text that looks like an attack,
 * so the form must send what the server accepts and say plainly why a save failed.
 */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CapabilityStatus, Skill } from "@/types";

vi.mock("@/services/api", () => ({
  getCapabilities: vi.fn(),
  listSkills: vi.fn(),
  createSkill: vi.fn(),
  updateSkill: vi.fn(),
  deleteSkill: vi.fn(),
}));

import Skills from "@/pages/Skills";
import * as api from "@/services/api";

const mocked = vi.mocked(api);

const SKILL: Skill = {
  id: "s1",
  name: "weekly-canvas",
  description: "When I ask what's due",
  instructions: "Group by course.",
  enabled: true,
  created_at: "2026-11-20T12:00:00Z",
  updated_at: "2026-11-20T12:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  mocked.getCapabilities.mockResolvedValue([]);
  mocked.listSkills.mockResolvedValue([]);
});

function fill() {
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Weekly Canvas!" } });
  fireEvent.change(screen.getByLabelText("When should Crawler use it?"), { target: { value: " When I ask what's due " } });
  fireEvent.change(screen.getByLabelText("Instructions"), { target: { value: "Group by course." } });
}

describe("Skills page", () => {
  it("sends a slug name and trimmed text, then lists the skill", async () => {
    mocked.createSkill.mockResolvedValue(SKILL);
    render(<Skills />);
    await screen.findByText("No skills yet. Add one above.");
    fill();
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("weekly-canvas-");
    fireEvent.click(screen.getByRole("button", { name: /Save skill/ }));

    await waitFor(() =>
      expect(mocked.createSkill).toHaveBeenCalledWith({
        name: "weekly-canvas",
        description: "When I ask what's due",
        instructions: "Group by course.",
      }),
    );
    expect(await screen.findByText("weekly-canvas")).toBeTruthy();
  });

  it("turns a skill off with its switch", async () => {
    mocked.listSkills.mockResolvedValue([SKILL]);
    mocked.updateSkill.mockResolvedValue({ ...SKILL, enabled: false });
    render(<Skills />);
    fireEvent.click(await screen.findByRole("switch", { name: "Use weekly-canvas" }));
    await waitFor(() => expect(mocked.updateSkill).toHaveBeenCalledWith("s1", { enabled: false }));
    await waitFor(() =>
      expect(screen.getByRole("switch", { name: "Use weekly-canvas" }).getAttribute("aria-checked")).toBe("false"),
    );
  });

  it("says so when the owner turned skills off", async () => {
    mocked.getCapabilities.mockResolvedValue([
      { key: "skills", effective: "off", when_denied: "Skills are turned off." } as CapabilityStatus,
    ]);
    render(<Skills />);
    expect(await screen.findByText("Skills are turned off.")).toBeTruthy();
  });

  it("shows why a save was refused", async () => {
    mocked.createSkill.mockRejectedValue(new Error("Part of this skill looks like an attempt to change Crawler's instructions."));
    render(<Skills />);
    await screen.findByText("No skills yet. Add one above.");
    fill();
    fireEvent.click(screen.getByRole("button", { name: /Save skill/ }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByText(/looks like an attempt to change/)).toBeTruthy();
  });
});
