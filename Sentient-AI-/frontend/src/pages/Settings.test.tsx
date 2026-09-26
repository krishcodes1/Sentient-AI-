/**
 * Tests for Settings: they prove the LLM provider choice sends nulls to follow the install
 * default, deletion requires the password and signs out, the Telegram bot token is admin-only, the
 * Server and Payment card sections are owner-only, and a changed purchase cap saves through
 * updateCapabilitySettings.
 *
 * Why it exists: Guards against saving a provider the user never tested, deleting an account
 * without its password, or showing a non-owner controls the server would refuse.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CapabilityStatus, SetupProviders, SetupStatus, User } from "@/types";

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
    updateCapabilitySettings: vi.fn(),
    updateProfile: vi.fn(),
    updateSettings: vi.fn(),
    // Owner-only Payment card section: an install with a vault and no card.
    getVaultItems: vi.fn(async () => ({ items: [], available: true, reason: "" })),
    saveVaultCard: vi.fn(),
    deleteVaultItem: vi.fn(),
    // Owner-only Server section. Defaults describe a finished install on
    // gemini with sign-ups closed; tests override per case.
    getSetupStatus: vi.fn(async () => ({
      needs_setup: false,
      has_owner: true,
      provider_configured: true,
      setup_completed: true,
      secrets_unreadable: false,
      registration_open: false,
      registration_env_locked: false,
    })),
    getSetupProviders: vi.fn(async () => ({
      providers: [
        { name: "anthropic", key_from_env: false, key_stored: false, models: ["claude-sonnet-5"] },
        { name: "gemini", key_from_env: false, key_stored: true, models: ["gemini-3.5-flash-lite"] },
      ],
      current: { provider: "gemini", model: "gemini-3.5-flash-lite" },
    })),
    testProvider: vi.fn(),
    saveProvider: vi.fn(),
    clearStoredSecrets: vi.fn(),
    updateRegistration: vi.fn(),
  };
});

import Settings from "@/pages/Settings";
import {
  ApiError,
  clearStoredSecrets,
  deleteAccount,
  getCapabilities,
  getMe,
  getSetupProviders,
  getSetupStatus,
  getTelegramStatus,
  getVaultItems,
  logout,
  removeTelegramToken,
  saveProvider,
  saveTelegram,
  testProvider,
  testTelegram,
  updateCapabilitySettings,
  updateRegistration,
  updateSettings,
} from "@/services/api";

const SERVER_STATUS: SetupStatus = {
  needs_setup: false,
  has_owner: true,
  provider_configured: true,
  setup_completed: true,
  secrets_unreadable: false,
  registration_open: false,
  registration_env_locked: false,
};

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

describe("Settings Server section", () => {
  afterEach(() => {
    vi.mocked(getMe).mockReset();
  });

  /** The owner-only section; a <section> with a heading is a named region. */
  const serverSection = async () => within(await screen.findByRole("region", { name: "Server" }));

  it("shows the owner this Crawler's current provider and who can create accounts", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    render(<Settings />);

    const server = await serverSection();
    expect(await server.findByText(/current default/i)).toHaveTextContent(
      "gemini · gemini-3.5-flash-lite",
    );
    const signups = await server.findByRole("switch", { name: /allow other people to create accounts/i });
    expect(signups).toHaveAttribute("aria-checked", "false");
    expect(signups).toBeEnabled();
  });

  it("never shows the section, or asks for its data, for an account that is not the owner", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: false }));
    render(<Settings />);

    // Wait for the account itself, so the check below is not just racing it.
    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue("Me"));
    expect(screen.queryByRole("region", { name: "Server" })).not.toBeInTheDocument();
    expect(screen.queryByText("AI provider for this Crawler")).not.toBeInTheDocument();
    expect(getSetupStatus).not.toHaveBeenCalled();
    expect(getSetupProviders).not.toHaveBeenCalled();
  });

  it("opens sign-ups through updateRegistration", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(updateRegistration).mockResolvedValue(undefined);
    render(<Settings />);

    const server = await serverSection();
    const signups = await server.findByRole("switch", { name: /allow other people to create accounts/i });
    fireEvent.click(signups);

    await waitFor(() => expect(updateRegistration).toHaveBeenCalledWith(true));
    await waitFor(() => expect(signups).toHaveAttribute("aria-checked", "true"));
  });

  it("renders the switch disabled when ALLOW_REGISTRATION=false in .env locks it", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getSetupStatus).mockResolvedValue({ ...SERVER_STATUS, registration_env_locked: true });
    render(<Settings />);

    const server = await serverSection();
    const signups = await server.findByRole("switch", { name: /allow other people to create accounts/i });
    expect(signups).toBeDisabled();
    expect(signups).toHaveAttribute("aria-checked", "false");
    expect(server.getByText("Locked closed by ALLOW_REGISTRATION=false in .env")).toBeInTheDocument();
    fireEvent.click(signups);
    expect(updateRegistration).not.toHaveBeenCalled();
  });

  it("shows the server's lock message verbatim and locks the switch when the PUT is refused", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(updateRegistration).mockRejectedValue(
      new ApiError("ALLOW_REGISTRATION=false in .env keeps registration closed.", 409),
    );
    render(<Settings />);

    const server = await serverSection();
    const signups = await server.findByRole("switch", { name: /allow other people to create accounts/i });
    fireEvent.click(signups);

    expect(
      await server.findByText("ALLOW_REGISTRATION=false in .env keeps registration closed."),
    ).toBeInTheDocument();
    expect(signups).toHaveAttribute("aria-checked", "false");
    expect(signups).toBeDisabled();
  });

  it("reuses the wizard's Test-then-Save flow to change this Crawler's provider", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(testProvider).mockResolvedValue({ ok: true, reply: "OK" });
    vi.mocked(saveProvider).mockResolvedValue(undefined);
    render(<Settings />);

    const server = await serverSection();
    fireEvent.click(await server.findByRole("radio", { name: /anthropic/i }));
    const save = server.getByRole("button", { name: "Save provider" });
    fireEvent.change(server.getByLabelText("API key"), { target: { value: "sk-ant-test" } });
    expect(save).toBeDisabled();

    fireEvent.click(server.getByRole("button", { name: "Test provider" }));
    await waitFor(() => expect(save).toBeEnabled());
    expect(testProvider).toHaveBeenCalledWith({
      provider: "anthropic",
      model: "claude-sonnet-5",
      api_key: "sk-ant-test",
    });

    fireEvent.click(save);
    await waitFor(() =>
      expect(saveProvider).toHaveBeenCalledWith({
        provider: "anthropic",
        model: "claude-sonnet-5",
        api_key: "sk-ant-test",
      }),
    );
    expect(await server.findByText(/current default/i)).toHaveTextContent("anthropic · claude-sonnet-5");
    // The key went to the server; nothing of it stays in the form.
    expect(server.getByLabelText("API key")).toHaveValue("");
  });

  it("hides the key field for an .env key and shows a save 409 verbatim", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getSetupProviders).mockResolvedValue({
      providers: [{ name: "gemini", key_from_env: true, key_stored: false, models: ["gemini-3.5-flash-lite"] }],
      current: { provider: "gemini", model: "gemini-3.5-flash-lite" },
    } satisfies SetupProviders);
    vi.mocked(testProvider).mockResolvedValue({ ok: true, reply: "OK" });
    vi.mocked(saveProvider).mockRejectedValue(
      new ApiError("The gemini key comes from the server's .env and cannot be changed here.", 409),
    );
    render(<Settings />);

    const server = await serverSection();
    expect(await server.findByText("Provided by server configuration")).toBeInTheDocument();
    expect(server.queryByLabelText("API key")).not.toBeInTheDocument();

    fireEvent.click(server.getByRole("button", { name: "Test provider" }));
    const save = server.getByRole("button", { name: "Save provider" });
    await waitFor(() => expect(save).toBeEnabled());
    fireEvent.click(save);

    expect(
      await server.findByText("The gemini key comes from the server's .env and cannot be changed here."),
    ).toBeInTheDocument();
  });

  it("offers to clear stored keys the server can no longer decrypt, then re-reads the status", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getSetupStatus)
      .mockResolvedValueOnce({ ...SERVER_STATUS, secrets_unreadable: true })
      .mockResolvedValueOnce(SERVER_STATUS);
    vi.mocked(clearStoredSecrets).mockResolvedValue(undefined);
    render(<Settings />);

    const server = await serverSection();
    fireEvent.click(await server.findByRole("button", { name: "Clear stored keys" }));

    await waitFor(() => expect(clearStoredSecrets).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(server.queryByRole("button", { name: "Clear stored keys" })).not.toBeInTheDocument(),
    );
  });
});

describe("Settings Payment card", () => {
  afterEach(() => {
    vi.mocked(getMe).mockReset();
  });

  it("shows the owner the Payment card section and reads the vault", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    render(<Settings />);

    const section = within(await screen.findByRole("region", { name: "Payment card" }));
    expect(await section.findByText(/no card is stored/i)).toBeInTheDocument();
    expect(section.getByText(/stored encrypted/i)).toBeInTheDocument();
    expect(section.getByLabelText("Card number")).toHaveValue("");
    expect(getVaultItems).toHaveBeenCalled();
  });

  it("never shows the section, or asks for the vault, for an account that is not the owner", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: false }));
    render(<Settings />);

    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue("Me"));
    expect(screen.queryByRole("region", { name: "Payment card" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Card number")).not.toBeInTheDocument();
    expect(getVaultItems).not.toHaveBeenCalled();
  });
});

describe("Settings purchase caps", () => {
  const PURCHASES: CapabilityStatus = {
    key: "purchases",
    label: "Buy things for me",
    description: "Book tickets and make small purchases with the card you stored.",
    risk: "high",
    enabled: true,
    default_enabled: false,
    available: true,
    availability_reason: "",
    probe_state: "not_required",
    probe_detail: "",
    fix_url: null,
    fix_steps: [],
    effective: "on",
    reason: "",
    can_request_access: false,
    install: null,
    install_size_hint: null,
    when_denied: "Buying things is off. Turn on 'Buy things for me' in Permissions.",
    tools: ["browser.checkout"],
    settings: { per_purchase_cap_usd: 25, per_day_cap_usd: 50 },
  };

  afterEach(() => {
    vi.mocked(getMe).mockReset();
    vi.mocked(getCapabilities).mockReset();
    vi.mocked(getCapabilities).mockResolvedValue([]);
    vi.mocked(updateCapabilitySettings).mockReset();
  });

  it("saves a changed cap through updateCapabilitySettings and shows the list the server returns", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getCapabilities).mockResolvedValue([PURCHASES]);
    vi.mocked(updateCapabilitySettings).mockResolvedValue([
      { ...PURCHASES, settings: { per_purchase_cap_usd: 40, per_day_cap_usd: 50 } },
    ]);
    render(<Settings />);

    const perPurchase = await screen.findByLabelText("Per purchase (USD)");
    await waitFor(() => expect(perPurchase).toBeEnabled());
    fireEvent.change(perPurchase, { target: { value: "40" } });
    fireEvent.blur(perPurchase);

    await waitFor(() =>
      expect(updateCapabilitySettings).toHaveBeenCalledWith("purchases", { per_purchase_cap_usd: 40 }),
    );
    expect(updateCapabilitySettings).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByLabelText("Per purchase (USD)")).toHaveValue(40));
    await waitFor(() => expect(screen.getByLabelText("Per purchase (USD)")).toBeEnabled());
  });

  it("shows the server's refusal and the stored value again", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getCapabilities).mockResolvedValue([PURCHASES]);
    // The server's 422 as installation.py words it (SETTINGS_OUT_OF_BOUNDS).
    vi.mocked(updateCapabilitySettings).mockRejectedValue(
      new ApiError("Caps must be between $1 and $10,000.", 422),
    );
    render(<Settings />);

    const perDay = await screen.findByLabelText("Per day (USD)");
    await waitFor(() => expect(perDay).toBeEnabled());
    fireEvent.change(perDay, { target: { value: "9000" } });
    fireEvent.blur(perDay);

    expect(await screen.findByText("Caps must be between $1 and $10,000.")).toBeInTheDocument();
    expect(screen.getByLabelText("Per day (USD)")).toHaveValue(50);
  });

  it("refuses a cap over $10,000 on the page, before the server sees it", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: true }));
    vi.mocked(getCapabilities).mockResolvedValue([PURCHASES]);
    render(<Settings />);

    const perDay = await screen.findByLabelText("Per day (USD)");
    await waitFor(() => expect(perDay).toBeEnabled());
    fireEvent.change(perDay, { target: { value: "20000" } });
    fireEvent.blur(perDay);

    expect(await screen.findByText("Enter a whole number of dollars between $1 and $10,000.")).toBeInTheDocument();
    expect(updateCapabilitySettings).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Per day (USD)")).toHaveValue(50);
  });

  it("keeps the caps read-only for an account that is not the owner", async () => {
    vi.mocked(getMe).mockResolvedValue(user({ is_admin: false }));
    vi.mocked(getCapabilities).mockResolvedValue([PURCHASES]);
    render(<Settings />);

    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue("Me"));
    expect(screen.getByLabelText("Per purchase (USD)")).toBeDisabled();
  });
});
