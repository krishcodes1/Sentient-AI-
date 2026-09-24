import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { User } from "@/types";

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
    removeTelegramToken: vi.fn(),
    requestCapabilityAccess: vi.fn(),
    saveTelegram: vi.fn(),
    testTelegram: vi.fn(),
    unlinkTelegram: vi.fn(),
    updateCapabilities: vi.fn(),
    updateProfile: vi.fn(),
    updateSettings: vi.fn(),
  };
});

import Settings from "@/pages/Settings";
import {
  ApiError,
  deleteAccount,
  getMe,
  getTelegramStatus,
  logout,
  removeTelegramToken,
  saveTelegram,
  testTelegram,
  updateSettings,
} from "@/services/api";

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

describe("Settings account deletion", () => {
  afterEach(() => {
    vi.mocked(getMe).mockReset();
    vi.mocked(deleteAccount).mockReset();
    vi.mocked(logout).mockReset();
  });

  it("refuses to delete without the current password", async () => {
    vi.mocked(getMe).mockResolvedValue(user());
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Delete Account" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete everything" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Enter your current password to continue.",
    );
    expect(deleteAccount).not.toHaveBeenCalled();
  });

  it("sends the entered password and signs out on success", async () => {
    vi.mocked(getMe).mockResolvedValue(user());
    vi.mocked(deleteAccount).mockResolvedValue(undefined);
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Delete Account" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Current password"), {
      target: { value: "correct-horse-9" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete everything" }));

    await waitFor(() =>
      expect(deleteAccount).toHaveBeenCalledWith({ current_password: "correct-horse-9" }),
    );
    await waitFor(() => expect(logout).toHaveBeenCalled());
  });

  it("shows the backend's 409 message inline when the last owner tries to leave", async () => {
    vi.mocked(getMe).mockResolvedValue(user());
    vi.mocked(deleteAccount).mockRejectedValue(
      new ApiError("Transfer ownership before deleting the last owner account", 409),
    );
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Delete Account" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Current password"), {
      target: { value: "correct-horse-9" },
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete everything" }));

    expect(
      await within(dialog).findByText("Transfer ownership before deleting the last owner account"),
    ).toBeInTheDocument();
  });
});

describe("Settings Telegram bot token", () => {
  afterEach(() => {
    vi.mocked(getMe).mockReset();
    vi.mocked(getTelegramStatus).mockReset();
    vi.mocked(saveTelegram).mockReset();
    vi.mocked(testTelegram).mockReset();
    vi.mocked(removeTelegramToken).mockReset();
  });

  it("hides the bot token block from a non-admin and tells them to ask the owner", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: false }));
    vi.mocked(getTelegramStatus).mockResolvedValue({ configured: false, linked: false });
    render(<Settings />);

    await screen.findByText("Ask the owner to add a bot token.");
    expect(screen.queryByText("Bot token")).not.toBeInTheDocument();
  });

  it("lets an admin test and save a bot token, warning when the poller could not start", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getTelegramStatus)
      .mockResolvedValueOnce({ configured: false, linked: false })
      .mockResolvedValueOnce({ configured: true, linked: false, bot_username: "crawler_bot" });
    vi.mocked(testTelegram).mockResolvedValue({ ok: true, bot_username: "crawler_bot" });
    vi.mocked(saveTelegram).mockResolvedValue({ bot_username: "crawler_bot", running: false });
    render(<Settings />);

    await screen.findByText("Bot token");
    fireEvent.change(screen.getByPlaceholderText("123456789:AA…"), {
      target: { value: "123456789:AA-fake-token" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Test" }));
    expect(await screen.findByText(/the token works/i)).toBeInTheDocument();
    expect(testTelegram).toHaveBeenCalledWith("123456789:AA-fake-token");

    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(
      await screen.findByText("Saved. The bot could not start yet — check the token or try again."),
    ).toBeInTheDocument();
    expect(saveTelegram).toHaveBeenCalledWith("123456789:AA-fake-token");
  });

  it("shows the server's env-managed message and stops offering to save", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getTelegramStatus).mockResolvedValue({
      configured: true,
      linked: false,
      bot_username: "env_bot",
    });
    vi.mocked(saveTelegram).mockRejectedValue(
      new ApiError("Provided by server configuration; remove it from .env to manage it here.", 409),
    );
    render(<Settings />);

    await screen.findByText("Bot token");
    fireEvent.change(
      screen.getByPlaceholderText("A token is saved — paste a new one to replace it"),
      { target: { value: "123456789:AA-another-token" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(
      await screen.findByText(
        "Provided by server configuration; remove it from .env to manage it here.",
      ),
    ).toBeInTheDocument();
    // The input/Test/Save controls are replaced by the notice — nothing
    // left here would ever be used server-side.
    expect(screen.queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
  });

  it("removes a stored token", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getTelegramStatus)
      .mockResolvedValueOnce({ configured: true, linked: false, bot_username: "crawler_bot" })
      .mockResolvedValueOnce({ configured: false, linked: false });
    vi.mocked(removeTelegramToken).mockResolvedValue(undefined);
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));

    expect(await screen.findByText("Bot token removed.")).toBeInTheDocument();
    expect(removeTelegramToken).toHaveBeenCalled();
  });
});
