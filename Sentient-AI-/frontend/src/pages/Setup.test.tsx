import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CapabilityStatus, SetupProviders } from "@/types";

vi.mock("@/services/api", () => ({
  getSetupStatus: vi.fn(),
  createOwner: vi.fn(),
  getSetupProviders: vi.fn(),
  testProvider: vi.fn(),
  saveProvider: vi.fn(),
  testTelegram: vi.fn(),
  saveTelegram: vi.fn(),
  createTelegramLink: vi.fn(),
  completeSetup: vi.fn(),
  clearStoredSecrets: vi.fn(),
  getCapabilities: vi.fn(),
  updateCapabilities: vi.fn(),
  requestCapabilityAccess: vi.fn(),
  installCapability: vi.fn(),
}));

import Setup from "@/pages/Setup";
import * as api from "@/services/api";
import { ThemeProvider } from "@/theme";

function cap(overrides: Partial<CapabilityStatus> & Pick<CapabilityStatus, "key" | "label">): CapabilityStatus {
  return {
    description: "",
    risk: "low",
    enabled: true,
    default_enabled: true,
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
    when_denied: "",
    tools: [],
    ...overrides,
  };
}

const CAPS: CapabilityStatus[] = [
  cap({ key: "web_browsing", label: "Browse the web", risk: "medium" }),
  cap({
    key: "screen",
    label: "See my screen",
    risk: "high",
    effective: "blocked",
    probe_state: "denied",
    reason: "macOS has not granted Screen Recording to /usr/bin/python3.",
    can_request_access: true,
  }),
  cap({
    key: "reminders",
    label: "Reminders",
    enabled: false,
    default_enabled: false,
    effective: "off",
    when_denied: "I can't set reminders for you.",
  }),
];

function providers(overrides: Partial<Record<"gemini" | "anthropic", boolean>> = {}): SetupProviders {
  return {
    providers: [
      { name: "anthropic", key_from_env: overrides.anthropic ?? false, key_stored: false, models: ["claude-sonnet-5"] },
      { name: "gemini", key_from_env: overrides.gemini ?? false, key_stored: false, models: ["gemini-2.5-flash", "gemini-2.5-pro"] },
    ],
    current: { provider: "", model: "" },
  };
}

function renderSetup() {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={["/setup"]}>
        <Routes>
          <Route path="/setup" element={<Setup />} />
          <Route path="/" element={<h1>Home page</h1>} />
          <Route path="/login" element={<h1>Login page</h1>} />
        </Routes>
      </MemoryRouter>
    </ThemeProvider>,
  );
}

/** Start the wizard as a signed-in owner, i.e. on the provider step. */
function asSignedInOwner() {
  localStorage.setItem("auth_token", "owner-token");
  vi.mocked(api.getSetupStatus).mockResolvedValue({
    needs_setup: true,
    has_owner: true,
    provider_configured: false,
    setup_completed: false,
    secrets_unreadable: false,
  });
}

/**
 * The provider step's heading renders before its list arrives; wait for the
 * list itself, or a query for its buttons races the request.
 */
async function providerListLoaded() {
  await screen.findByRole("heading", { name: "AI provider" });
  await screen.findByRole("radiogroup", { name: "Provider" });
}

/** Walk from the provider step to the telegram step with an .env key. */
async function goToTelegram(user: ReturnType<typeof userEvent.setup>) {
  vi.mocked(api.getSetupProviders).mockResolvedValue(providers({ gemini: true }));
  renderSetup();
  await providerListLoaded();
  await user.click(screen.getByRole("button", { name: "Test" }));
  const save = screen.getByRole("button", { name: "Save & continue" });
  await waitFor(() => expect(save).toBeEnabled());
  await user.click(save);
  await screen.findByRole("heading", { name: /telegram/i });
}

/** Walk from the provider step to the permissions step with an .env key. */
async function goToPermissions(user: ReturnType<typeof userEvent.setup>) {
  await goToTelegram(user);
  await user.click(screen.getByRole("button", { name: "Skip" }));
  await screen.findByRole("heading", { name: "Permissions" });
}

describe("Setup wizard", () => {
  beforeEach(() => {
    // Drop queued once-values too, so a test that fails half-way cannot
    // hand its leftovers to the next one.
    vi.resetAllMocks();
    vi.mocked(api.getSetupStatus).mockResolvedValue({
      needs_setup: true,
      has_owner: false,
      provider_configured: false,
      setup_completed: false,
      secrets_unreadable: false,
    });
    vi.mocked(api.createOwner).mockResolvedValue({ access_token: "t", token_type: "bearer" });
    vi.mocked(api.getSetupProviders).mockResolvedValue(providers());
    vi.mocked(api.testProvider).mockResolvedValue({ ok: true, reply: "OK" });
    vi.mocked(api.saveProvider).mockResolvedValue(undefined);
    vi.mocked(api.getCapabilities).mockResolvedValue(CAPS);
    vi.mocked(api.updateCapabilities).mockImplementation(async (patch) =>
      CAPS.map((c) => (c.key in patch ? { ...c, enabled: patch[c.key] } : c)),
    );
    vi.mocked(api.completeSetup).mockResolvedValue(undefined);
    vi.mocked(api.clearStoredSecrets).mockResolvedValue(undefined);
  });

  it("(a) creates the owner account first, then moves on to the AI provider", async () => {
    const user = userEvent.setup();
    renderSetup();

    expect(await screen.findByRole("heading", { name: "Create the owner account" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Your name"), "Krish");
    await user.type(screen.getByLabelText("Email"), "krish@example.com");
    await user.type(screen.getByLabelText("Password"), "correct-horse-9");
    await user.click(screen.getByRole("button", { name: "Create owner account" }));

    expect(api.createOwner).toHaveBeenCalledWith({
      name: "Krish",
      email: "krish@example.com",
      password: "correct-horse-9",
    });
    expect(await screen.findByRole("heading", { name: "AI provider" })).toBeInTheDocument();
  });

  it("shows the owner-step error and stays put when the account cannot be created", async () => {
    vi.mocked(api.createOwner).mockRejectedValue(new Error("An owner account already exists."));
    const user = userEvent.setup();
    renderSetup();

    await screen.findByRole("heading", { name: "Create the owner account" });
    await user.type(screen.getByLabelText("Your name"), "Krish");
    await user.type(screen.getByLabelText("Email"), "krish@example.com");
    await user.type(screen.getByLabelText("Password"), "correct-horse-9");
    await user.click(screen.getByRole("button", { name: "Create owner account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("An owner account already exists.");
    expect(screen.getByRole("heading", { name: "Create the owner account" })).toBeInTheDocument();
  });

  it("sends an existing owner without a session to sign in", async () => {
    vi.mocked(api.getSetupStatus).mockResolvedValue({
      needs_setup: true,
      has_owner: true,
      provider_configured: false,
      setup_completed: false,
      secrets_unreadable: false,
    });
    renderSetup();

    expect(await screen.findByRole("heading", { name: "Sign in to finish setup" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
  });

  it("leaves the wizard once setup is already complete", async () => {
    vi.mocked(api.getSetupStatus).mockResolvedValue({
      needs_setup: false,
      has_owner: true,
      provider_configured: true,
      setup_completed: true,
      secrets_unreadable: false,
    });
    renderSetup();

    expect(await screen.findByRole("heading", { name: "Home page" })).toBeInTheDocument();
  });

  it("(b) keeps Save disabled until a provider test passes", async () => {
    asSignedInOwner();
    vi.mocked(api.testProvider)
      .mockResolvedValueOnce({ ok: false, error: "API key not valid." })
      .mockResolvedValueOnce({ ok: true, reply: "OK" });
    const user = userEvent.setup();
    renderSetup();

    await providerListLoaded();
    // Gemini is the preselected default, with its first suggested model.
    expect(screen.getByRole("radio", { name: /gemini/i })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByLabelText("Model")).toHaveValue("gemini-2.5-flash");

    const save = screen.getByRole("button", { name: "Save & continue" });
    expect(save).toBeDisabled();

    await user.type(screen.getByLabelText("API key"), "bad-key");
    expect(save).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Test" }));
    expect(await screen.findByText("API key not valid.")).toBeInTheDocument();
    expect(save).toBeDisabled();

    await user.clear(screen.getByLabelText("API key"));
    await user.type(screen.getByLabelText("API key"), "good-key");
    await user.click(screen.getByRole("button", { name: "Test" }));
    expect(await screen.findByText(/replied/i)).toBeInTheDocument();
    expect(save).toBeEnabled();
    expect(api.testProvider).toHaveBeenLastCalledWith({
      provider: "gemini",
      model: "gemini-2.5-flash",
      api_key: "good-key",
    });

    // Editing the key after a pass invalidates it: the new key is untested.
    await user.type(screen.getByLabelText("API key"), "x");
    expect(save).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Test" }));
    await waitFor(() => expect(save).toBeEnabled());

    await user.click(save);
    expect(api.saveProvider).toHaveBeenCalledWith({
      provider: "gemini",
      model: "gemini-2.5-flash",
      api_key: "good-keyx",
    });
    expect(await screen.findByRole("heading", { name: /telegram/i })).toBeInTheDocument();
  });

  it("(c) says the key is provided by the server and hides the key field", async () => {
    asSignedInOwner();
    vi.mocked(api.getSetupProviders).mockResolvedValue(providers({ anthropic: true }));
    const user = userEvent.setup();
    renderSetup();

    await providerListLoaded();
    expect(screen.getByLabelText("API key")).toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: /anthropic/i }));
    expect(screen.getByText("Provided by server configuration")).toBeInTheDocument();
    expect(screen.queryByLabelText("API key")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Model")).toHaveValue("claude-sonnet-5");

    await user.click(screen.getByRole("button", { name: "Test" }));
    expect(api.testProvider).toHaveBeenCalledWith({ provider: "anthropic", model: "claude-sonnet-5" });
  });

  it("(d) renders the capability list on the Permissions step and saves a toggle", async () => {
    asSignedInOwner();
    const user = userEvent.setup();
    await goToPermissions(user);

    const web = await screen.findByRole("switch", { name: "Browse the web" });
    expect(web).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("switch", { name: "See my screen" })).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Reminders" })).toHaveAttribute("aria-checked", "false");

    await user.click(web);
    expect(api.updateCapabilities).toHaveBeenCalledWith({ web_browsing: false });
    await waitFor(() =>
      expect(screen.getByRole("switch", { name: "Browse the web" })).toHaveAttribute("aria-checked", "false"),
    );
  });

  it("(e) summarises what works and finishes with registration off", async () => {
    asSignedInOwner();
    const assign = vi.fn();
    const user = userEvent.setup();
    await goToPermissions(user);
    await screen.findByRole("switch", { name: "Browse the web" });
    await user.click(screen.getByRole("button", { name: "Next" }));

    await screen.findByRole("heading", { name: "Summary" });
    const row = async (name: string) => within(await screen.findByRole("row", { name: new RegExp(name) }));
    expect((await row("Browse the web")).getByText("Works")).toBeInTheDocument();
    expect((await row("See my screen")).getByText("Not available")).toBeInTheDocument();
    expect((await row("Reminders")).getByText("Off")).toBeInTheDocument();

    const allow = screen.getByRole("checkbox", { name: /allow other people to create accounts/i });
    expect(allow).not.toBeChecked();
    expect(screen.getByText(/crawler never/i)).toBeInTheDocument();

    vi.stubGlobal("location", { ...window.location, pathname: "/setup", assign });
    await user.click(screen.getByRole("button", { name: "Finish" }));

    expect(api.completeSetup).toHaveBeenCalledWith({ allow_registration: false });
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
  });

  it("(f) focuses the owner step's first field on initial mount", async () => {
    renderSetup();

    const name = await screen.findByLabelText("Your name");
    await waitFor(() => expect(document.activeElement).toBe(name));
  });

  it("(g) moves focus into the next step's card when advancing from the owner step", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByRole("heading", { name: "Create the owner account" });
    await user.type(screen.getByLabelText("Your name"), "Krish");
    await user.type(screen.getByLabelText("Email"), "krish@example.com");
    await user.type(screen.getByLabelText("Password"), "correct-horse-9");
    await user.click(screen.getByRole("button", { name: "Create owner account" }));

    const heading = await screen.findByRole("heading", { name: "AI provider" });
    await waitFor(() => {
      expect(heading === document.activeElement || heading.contains(document.activeElement)).toBe(true);
    });
  });

  it("(h) shows a disabled Back button on the provider step, since the owner account can't be re-created", async () => {
    asSignedInOwner();
    renderSetup();
    await providerListLoaded();

    const back = screen.getByRole("button", { name: "Back" });
    expect(back).toBeDisabled();
    expect(back).toHaveAttribute("title", "The owner account is already created");
  });

  it("(i) marks a failed provider test as an alert and a passed one as a status", async () => {
    asSignedInOwner();
    vi.mocked(api.testProvider)
      .mockResolvedValueOnce({ ok: false, error: "API key not valid." })
      .mockResolvedValueOnce({ ok: true, reply: "OK" });
    const user = userEvent.setup();
    renderSetup();

    await providerListLoaded();
    await user.type(screen.getByLabelText("API key"), "bad-key");
    await user.click(screen.getByRole("button", { name: "Test" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("API key not valid.");

    await user.clear(screen.getByLabelText("API key"));
    await user.type(screen.getByLabelText("API key"), "good-key");
    await user.click(screen.getByRole("button", { name: "Test" }));
    expect(await screen.findByRole("status")).toHaveTextContent(/replied/i);
  });

  it("(j) toggles the registration checkbox by clicking its description text", async () => {
    asSignedInOwner();
    const user = userEvent.setup();
    await goToPermissions(user);
    await screen.findByRole("switch", { name: "Browse the web" });
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByRole("heading", { name: "Summary" });

    const checkbox = screen.getByRole("checkbox", { name: /allow other people to create accounts/i });
    expect(checkbox).not.toBeChecked();
    await user.click(screen.getByText(/leave this off unless someone else/i));
    expect(checkbox).toBeChecked();
  });

  it("(k) tells the owner the bot could not start yet when the save reports running: false", async () => {
    asSignedInOwner();
    vi.mocked(api.saveTelegram).mockResolvedValue({ bot_username: "crawler_bot", running: false });
    const user = userEvent.setup();
    await goToTelegram(user);

    await user.type(screen.getByLabelText("Bot token"), "123456789:AA-fake-token");
    await user.click(screen.getByRole("button", { name: "Save" }));

    // The token was still accepted and stored (an alert, since it needs
    // attention), so the wizard can still continue past this step.
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Saved. The bot could not start yet — check the token or try again.",
    );
    expect(screen.getByRole("button", { name: "Continue" })).toBeInTheDocument();
  });

  it("(l) shows the success message when the save reports running: true", async () => {
    asSignedInOwner();
    vi.mocked(api.saveTelegram).mockResolvedValue({ bot_username: "crawler_bot", running: true });
    const user = userEvent.setup();
    await goToTelegram(user);

    await user.type(screen.getByLabelText("Bot token"), "123456789:AA-fake-token");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("status")).toHaveTextContent(
      "Saved. Crawler now answers as @crawler_bot.",
    );
  });

  it("(m) offers to clear stored keys when the provider step reports secrets_unreadable, and reloads status after clearing", async () => {
    localStorage.setItem("auth_token", "owner-token");
    vi.mocked(api.getSetupStatus)
      .mockResolvedValueOnce({
        needs_setup: true,
        has_owner: true,
        provider_configured: false,
        setup_completed: false,
        secrets_unreadable: true,
      })
      .mockResolvedValueOnce({
        needs_setup: true,
        has_owner: true,
        provider_configured: false,
        setup_completed: false,
        secrets_unreadable: false,
      });
    const user = userEvent.setup();
    renderSetup();

    await providerListLoaded();
    expect(screen.getByRole("alert")).toHaveTextContent(/stored provider keys can.t be read/i);

    await user.click(screen.getByRole("button", { name: "Clear stored keys" }));

    expect(api.clearStoredSecrets).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(api.getSetupStatus).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.queryByText(/stored provider keys can.t be read/i)).not.toBeInTheDocument(),
    );
  });

  it("(n) surfaces a failure to clear stored keys inline instead of silently doing nothing", async () => {
    localStorage.setItem("auth_token", "owner-token");
    vi.mocked(api.getSetupStatus).mockResolvedValue({
      needs_setup: true,
      has_owner: true,
      provider_configured: false,
      setup_completed: false,
      secrets_unreadable: true,
    });
    vi.mocked(api.clearStoredSecrets).mockRejectedValue(new Error("The server refused."));
    const user = userEvent.setup();
    renderSetup();

    await providerListLoaded();
    await user.click(screen.getByRole("button", { name: "Clear stored keys" }));

    expect(await screen.findByText("The server refused.")).toBeInTheDocument();
    // The notice itself is still up — clearing did not silently succeed.
    expect(screen.getByRole("button", { name: "Clear stored keys" })).toBeInTheDocument();
  });
});
