import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { User } from "@/types";

vi.mock("@/services/api", () => ({
  changePassword: vi.fn(),
  createTelegramLink: vi.fn(),
  deleteAccount: vi.fn(),
  exportAccount: vi.fn(),
  getCapabilities: vi.fn(async () => []),
  getMe: vi.fn(),
  getTelegramStatus: vi.fn(async () => ({ configured: false, linked: false })),
  installCapability: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  requestCapabilityAccess: vi.fn(),
  unlinkTelegram: vi.fn(),
  updateCapabilities: vi.fn(),
  updateProfile: vi.fn(),
  updateSettings: vi.fn(),
}));

import Settings from "@/pages/Settings";
import { getMe, updateSettings } from "@/services/api";

function user(overrides: Partial<User> = {}): User {
  return {
    id: "u1",
    email: "me@example.com",
    name: "Me",
    created_at: "2026-09-23T00:00:00Z",
    default_permission_tier: "user_confirm",
    rate_limit: 60,
    llm_provider: null,
    llm_model: null,
    ...overrides,
  };
}

const DEFAULT_OPTION = "Use this Crawler's default";

describe("Settings LLM provider", () => {
  afterEach(() => {
    vi.mocked(getMe).mockReset();
    vi.mocked(updateSettings).mockReset();
  });

  it("selects the install default for an account with no provider of its own", async () => {
    vi.mocked(getMe).mockResolvedValue(user());
    render(<Settings />);

    const option = await screen.findByRole("radio", { name: new RegExp(DEFAULT_OPTION) });
    await waitFor(() => expect(option).toHaveAttribute("aria-checked", "true"));
    expect(screen.getByRole("radio", { name: /^openai/i })).toHaveAttribute(
      "aria-checked",
      "false",
    );
    // No model to pick while following the install.
    expect(screen.queryByLabelText("Model")).not.toBeInTheDocument();
  });

  it("returns a pinned account to the install default by sending nulls", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ llm_provider: "openai", llm_model: "gpt-5-mini" }));
    vi.mocked(updateSettings).mockResolvedValue(user());
    render(<Settings />);

    const openai = await screen.findByRole("radio", { name: /^openai/i });
    await waitFor(() => expect(openai).toHaveAttribute("aria-checked", "true"));
    expect(screen.getByLabelText("Model")).toHaveValue("gpt-5-mini");

    fireEvent.click(screen.getByRole("radio", { name: new RegExp(DEFAULT_OPTION) }));
    fireEvent.click(screen.getByRole("button", { name: /save llm settings/i }));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({ llm_provider: null, llm_model: null }),
    );
  });

  it("pins a provider with its model", async () => {
    vi.mocked(getMe).mockResolvedValue(user());
    vi.mocked(updateSettings).mockResolvedValue(
      user({ llm_provider: "gemini", llm_model: "gemini-3.5-flash-lite" }),
    );
    render(<Settings />);

    fireEvent.click(await screen.findByRole("radio", { name: /^gemini/i }));
    fireEvent.click(screen.getByRole("button", { name: /save llm settings/i }));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        llm_provider: "gemini",
        llm_model: "gemini-3.5-flash-lite",
      }),
    );
  });
});
