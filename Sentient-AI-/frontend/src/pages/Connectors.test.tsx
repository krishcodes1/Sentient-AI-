/**
 * Tests for the catalog-driven Connectors page: catalog cards and icons, the pasted-token form's
 * request body, browser and device sign-ins through the OAuth broker (start, open, poll, stop),
 * the "not set up on this server" fallback, unavailable rows, Reconnect and Grant more access,
 * Slack DM linking, and MCP servers staying creatable; plus the pure helpers behind them.
 *
 * Why it exists: the page is built from GET /connectors/types, so a wrong body, a poll that never
 * stops, or a sign-in offered when the server cannot run it would break connecting a service.
 * The API module is mocked at the "@/services/api" boundary; no network.
 */

import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Connector, ConnectorScopeInfo, ConnectorTypeInfo } from "@/types";

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
    createConnector: vi.fn(),
    createSlackLink: vi.fn(),
    deleteConnector: vi.fn(),
    getConnectorTypes: vi.fn(),
    getConnectors: vi.fn(),
    // The account default the tier select compares against (permission tiers).
    getMe: vi.fn(async () => ({ default_permission_tier: "user_confirm" })),
    getOAuthStatus: vi.fn(),
    getSlackLinkStatus: vi.fn(),
    searchCanvasSchools: vi.fn(),
    startDeviceOAuth: vi.fn(),
    startOAuth: vi.fn(),
    testConnector: vi.fn(),
    unlinkSlack: vi.fn(),
    updateConnector: vi.fn(),
  };
});

import Connectors from "@/pages/Connectors";
import {
  ApiError,
  createConnector,
  createSlackLink,
  getConnectorTypes,
  getConnectors,
  getMe,
  getOAuthStatus,
  getSlackLinkStatus,
  searchCanvasSchools,
  startDeviceOAuth,
  startOAuth,
  testConnector,
  unlinkSlack,
  updateConnector,
} from "@/services/api";
import {
  EXPIRY_GRACE_MS,
  MCP_ENTRY,
  buildCredentials,
  catalogEntries,
  clampRateLimit,
  connectOptions,
  externalUrl,
  fieldError,
  isExpired,
  isPastDeadline,
  orderedSelection,
  pollDelayMs,
  rowKind,
  scopeView,
} from "@/pages/connectorCatalog";
import { connectorIcon } from "@/components/connectorIcons";
import { Plug, Slack } from "lucide-react";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function scope(
  name: string,
  category: ConnectorScopeInfo["category"] = "read",
  alwaysConfirm = false,
): ConnectorScopeInfo {
  return { scope: name, category, always_confirm: alwaysConfirm, actions: [`act_${name}`] };
}

function entry(overrides: Partial<ConnectorTypeInfo> & Pick<ConnectorTypeInfo, "key" | "label">): ConnectorTypeInfo {
  return {
    description: `${overrides.label} description.`,
    icon: "plug",
    docs_url: "",
    creatable: true,
    auth: {
      methods: ["token"],
      fields: [
        { key: "access_token", label: "Access token", type: "password", required: true, placeholder: "", hint: "" },
      ],
      provider: null,
      oauth_configured: false,
      token_auth_method: "bearer_token",
      notes: "",
    },
    scopes: { read: [], write: [] },
    ...overrides,
  };
}

const CANVAS = entry({
  key: "canvas",
  label: "Canvas LMS",
  icon: "graduation-cap",
  docs_url: "https://canvas.example.edu/doc/api",
  auth: {
    methods: ["token"],
    fields: [
      { key: "base_url", label: "Canvas URL", type: "url", required: true, placeholder: "https://school", hint: "" },
      { key: "access_token", label: "Access token", type: "password", required: true, placeholder: "", hint: "" },
      { key: "refresh_token", label: "Refresh token", type: "password", required: false, placeholder: "", hint: "" },
    ],
    provider: null,
    oauth_configured: false,
    token_auth_method: "bearer_token",
    notes: "Your school's Canvas address, for example https://myschool.instructure.com",
    token_url: "{base_url}/profile/settings",
    token_url_label: "Open your Canvas token page",
  },
  scopes: {
    read: [scope("courses.read"), scope("grades.read")],
    write: [scope("submissions.write", "write", true)],
  },
});

const GOOGLE_PLAYGROUND_URL = "https://developers.google.com/oauthplayground/";

function google(oauthConfigured = true): ConnectorTypeInfo {
  return entry({
    key: "google_workspace",
    label: "Google Workspace",
    icon: "mail",
    auth: {
      methods: ["oauth", "token"],
      fields: [
        { key: "access_token", label: "OAuth access token", type: "password", required: true, placeholder: "", hint: "" },
      ],
      provider: "google",
      oauth_configured: oauthConfigured,
      token_auth_method: "oauth2",
      notes: "",
      token_url: GOOGLE_PLAYGROUND_URL,
      token_url_label: "Get a token in the OAuth Playground",
      client_setup_url: "https://console.cloud.google.com/auth/clients",
      client_id_setting: "GOOGLE_OAUTH_CLIENT_ID",
      client_secret_setting: "GOOGLE_OAUTH_CLIENT_SECRET",
    },
    scopes: {
      read: [scope("gmail.read"), scope("calendar.read")],
      write: [scope("gmail.send", "write", true), scope("calendar.write", "delete", true)],
    },
  });
}

const GITHUB_TOKEN_URL =
  "https://github.com/settings/personal-access-tokens/new?name=Crawler%20AI&contents=read&metadata=read";

const GITHUB = entry({
  key: "github",
  label: "GitHub",
  icon: "github",
  auth: {
    methods: ["device", "token"],
    fields: [
      { key: "access_token", label: "Personal access token", type: "password", required: true, placeholder: "", hint: "" },
    ],
    provider: "github",
    oauth_configured: true,
    token_auth_method: "bearer_token",
    notes: "",
    token_url: GITHUB_TOKEN_URL,
    token_url_label: "Create a GitHub token",
  },
  scopes: { read: [scope("repos.read")], write: [scope("issues.write", "write")] },
});

const MICROSOFT_CLIENT_SETUP_URL =
  "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade";

function microsoft(oauthConfigured: boolean): ConnectorTypeInfo {
  return entry({
    key: "microsoft",
    label: "Microsoft 365",
    icon: "briefcase",
    auth: {
      methods: ["oauth", "device"],
      fields: [],
      provider: "microsoft",
      oauth_configured: oauthConfigured,
      token_auth_method: "oauth2",
      notes: "",
      client_setup_url: MICROSOFT_CLIENT_SETUP_URL,
      client_id_setting: "MICROSOFT_OAUTH_CLIENT_ID",
      client_secret_setting: "",
    },
    scopes: { read: [scope("mail.read")], write: [scope("mail.send", "write", true)] },
  });
}

const SLACK = entry({
  key: "slack",
  label: "Slack",
  icon: "slack",
  docs_url: "https://docs.slack.dev/authentication/tokens/",
  auth: {
    methods: ["token"],
    fields: [
      { key: "bot_token", label: "Bot token", type: "password", required: true, placeholder: "xoxb-", hint: "" },
      { key: "app_token", label: "App-level token", type: "password", required: false, placeholder: "xapp-", hint: "" },
    ],
    provider: null,
    oauth_configured: false,
    token_auth_method: "bearer_token",
    notes: "Slack notes from the catalog.",
    token_url: "https://api.slack.com/apps?new_app=1",
    token_url_label: "Create the Crawler Slack app",
  },
  scopes: { read: [scope("messages.read")], write: [scope("messages.send", "write", true)] },
});

const MYSTERY = entry({ key: "mystery", label: "Mystery Box", icon: "no-such-icon" });

function row(overrides: Partial<Connector> & Pick<Connector, "id" | "connector_type">): Connector {
  return {
    user_id: "u-1",
    display_name: `${overrides.connector_type} row`,
    is_active: true,
    auth_method: "bearer_token",
    granted_scopes: [],
    permission_tier: "user_confirm",
    rate_limit_per_minute: 30,
    created_at: "2026-09-01T00:00:00Z",
    updated_at: "2026-09-01T00:00:00Z",
    available: true,
    ...overrides,
  };
}

const inTenMinutes = () => new Date(Date.now() + 10 * 60 * 1000).toISOString();

/** A promise the test settles by hand, for a request still in flight. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function setup(types: ConnectorTypeInfo[], rows: Connector[] = []) {
  vi.mocked(getConnectorTypes).mockResolvedValue(types);
  vi.mocked(getConnectors).mockResolvedValue(rows);
  const user = userEvent.setup();
  const view = render(<Connectors />);
  return { user, ...view };
}

async function openConnect(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(await screen.findByRole("button", { name: `Connect ${label}` }));
  return screen.getByRole("dialog");
}

/** Let resolved promises and React updates settle under fake timers. */
async function flush(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

function useFakeClock() {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
}

/** Put text into a field in one input event (typing it key by key is slow
 * enough to time out when the whole suite runs in parallel). */
async function fill(user: ReturnType<typeof userEvent.setup>, field: HTMLElement, text: string) {
  await user.click(field);
  await user.paste(text);
}

// The modal tests click through a whole form; under a parallel full-suite
// run jsdom can be several times slower than alone, so allow headroom.
vi.setConfig({ testTimeout: 15_000 });

beforeEach(() => {
  vi.mocked(getSlackLinkStatus).mockResolvedValue({ linked: false, channel_running: true });
  // The check that runs once a new connector is saved.
  vi.mocked(testConnector).mockResolvedValue({ ok: true, detail: "Connection verified." });
});

/** Open the connect dialog's folded "More settings" (name, approval policy, rate limit). */
async function openMoreSettings(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement) {
  await user.click(within(dialog).getByRole("button", { name: "More settings" }));
}

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Page behaviour
// ---------------------------------------------------------------------------

describe("Connectors catalog", () => {
  it("renders a card per catalog entry plus MCP, with icons and an unknown-icon fallback", async () => {
    setup([CANVAS, { ...MYSTERY, docs_url: "https://mystery.example/doc" }]);

    const canvas = await screen.findByRole("article", { name: "Canvas LMS" });
    expect(canvas.querySelector("svg.lucide-graduation-cap")).not.toBeNull();
    expect(within(canvas).getByText("Canvas LMS description.")).toBeInTheDocument();
    // A guided service walks through its pages in the dialog, so its card has no links.
    expect(within(canvas).queryByRole("link")).not.toBeInTheDocument();

    const mystery = screen.getByRole("article", { name: "Mystery Box" });
    expect(mystery.querySelector("svg.lucide-plug")).not.toBeNull();
    const docs = within(mystery).getByRole("link", { name: /setup guide/i });
    expect(docs).toHaveAttribute("href", "https://mystery.example/doc");
    expect(docs).toHaveAttribute("target", "_blank");
    expect(docs.getAttribute("rel")).toContain("noopener");

    const mcp = screen.getByRole("article", { name: "MCP server" });
    expect(mcp.querySelector("svg.lucide-server")).not.toBeNull();
    expect(screen.getByText("No connectors yet")).toBeInTheDocument();
  });

  it("keeps the rows and MCP when the catalog fails to load", async () => {
    vi.mocked(getConnectorTypes).mockRejectedValue(new Error("catalog down"));
    vi.mocked(getConnectors).mockResolvedValue([row({ id: "c-1", connector_type: "canvas", display_name: "School" })]);
    render(<Connectors />);

    expect(await screen.findByRole("article", { name: "School" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("catalog down");
    expect(screen.getByRole("button", { name: "Connect MCP server" })).toBeEnabled();
  });
});

describe("guided connect", () => {
  it("finds the school, links its Canvas settings, posts the credentials and says who it connected as", async () => {
    const { user } = setup([CANVAS]);
    vi.mocked(searchCanvasSchools).mockResolvedValue([
      { name: "NYIT", domain: "nyit.instructure.com" },
      { name: "Sneaky", domain: "javascript:alert(1)" },
    ]);
    vi.mocked(createConnector).mockImplementation(async (body) =>
      row({ id: "c-new", connector_type: body.connector_type, display_name: body.display_name }),
    );
    vi.mocked(testConnector).mockResolvedValue({
      ok: true,
      detail: "Connection verified.",
      account: "nyit.instructure.com",
      user: "Rafi Hossain",
    });
    const dialog = await openConnect(user, "Canvas LMS");
    expect(within(dialog).getByRole("list", { name: "Steps to connect Canvas" })).toBeInTheDocument();
    const submit = within(dialog).getByRole("button", { name: "Connect" });
    expect(within(dialog).getByText("Find your school in step 1 first. The button appears here.")).toBeInTheDocument();
    // The steps stand in for the catalog's note.
    expect(within(dialog).queryByText(/for example https:\/\/myschool/)).not.toBeInTheDocument();

    await fill(user, within(dialog).getByLabelText("School name"), "nyit");
    const pick = await within(dialog).findByRole("button", { name: /nyit\.instructure\.com/ });
    expect(searchCanvasSchools).toHaveBeenCalledWith("nyit");
    // A result whose domain is not a plain host name is never offered.
    expect(within(dialog).queryByRole("button", { name: /Sneaky/ })).not.toBeInTheDocument();
    await user.click(pick);

    const link = within(dialog).getByRole("link", { name: "Open my Canvas settings (opens in a new tab)" });
    expect(link).toHaveAttribute("href", "https://nyit.instructure.com/profile/settings");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link.getAttribute("rel")).toContain("noopener");
    const code = within(dialog).getByLabelText("Canvas code");
    expect(code).toHaveAttribute("type", "password");
    expect(submit).toBeDisabled();
    await fill(user, code, "1234~abcdefghijklmnopqrstuvwxyz");
    expect(within(dialog).getByText("Looks like a Canvas code.")).toBeInTheDocument();

    expect(within(dialog).getByRole("button", { name: /courses\.read/ })).toHaveAttribute("aria-pressed", "true");
    expect(within(dialog).getByRole("button", { name: /grades\.read/ })).toHaveAttribute("aria-pressed", "true");
    const write = within(dialog).getByRole("button", { name: /submissions\.write/ });
    expect(write).toHaveAttribute("aria-pressed", "false");
    expect(write).toHaveTextContent("(write)");
    expect(write).toHaveTextContent("always asks before running");
    await user.click(write);

    await user.click(submit);

    expect(createConnector).toHaveBeenCalledWith({
      connector_type: "canvas",
      display_name: "Canvas (NYIT)",
      auth_method: "bearer_token",
      credentials: { base_url: "https://nyit.instructure.com", access_token: "1234~abcdefghijklmnopqrstuvwxyz" },
      granted_scopes: ["courses.read", "grades.read", "submissions.write"],
      permission_tier: "user_confirm",
      rate_limit_per_minute: 30,
    });
    expect(testConnector).toHaveBeenCalledWith("c-new");
    expect(await within(dialog).findByText("Connected to NYIT as Rafi Hossain")).toBeInTheDocument();
    expect(screen.getByRole("article", { name: "Canvas (NYIT)" })).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Done" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // The page keeps the news once the dialog is gone.
    expect(screen.getByText("Connected to NYIT as Rafi Hossain")).toBeInTheDocument();
  });

  it("takes a typed address for a school the search does not have, and folds the extras away", async () => {
    const { user } = setup([CANVAS]);
    vi.mocked(searchCanvasSchools).mockResolvedValue([]);
    const dialog = await openConnect(user, "Canvas LMS");

    await fill(user, within(dialog).getByLabelText("School name"), "tiny college");
    expect(
      await within(dialog).findByText("No schools found. Try another spelling, or use your school's own address."),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "My school uses its own address" }));

    const url = within(dialog).getByLabelText("Your school's Canvas address");
    await fill(user, url, "javascript:alert(1)");
    expect(within(dialog).getByText(/Enter a full web address/)).toBeInTheDocument();
    expect(url).toHaveAttribute("aria-invalid", "true");
    expect(within(dialog).queryByRole("link", { name: /Open my Canvas settings/ })).not.toBeInTheDocument();
    await user.clear(url);
    // A page address pasted from the browser bar still links to the settings page.
    await fill(user, url, "https://canvas.school.edu/courses?x=1");
    expect(within(dialog).getByRole("link", { name: /Open my Canvas settings/ })).toHaveAttribute(
      "href",
      "https://canvas.school.edu/profile/settings",
    );

    // The renewal extras stay folded until asked for.
    expect(within(dialog).queryByLabelText(/Refresh code/)).not.toBeInTheDocument();
    const advanced = within(dialog).getByRole("button", { name: "Advanced (optional)" });
    expect(advanced).toHaveAttribute("aria-expanded", "false");
    await user.click(advanced);
    expect(advanced).toHaveAttribute("aria-expanded", "true");
    expect(within(dialog).getByLabelText(/Refresh code/)).toHaveAttribute("type", "password");
  });

  it("says when the school search is down and offers the address field", async () => {
    const { user } = setup([CANVAS]);
    vi.mocked(searchCanvasSchools).mockRejectedValue(
      new Error("School search is not working right now. Type your school's Canvas address instead."),
    );
    const dialog = await openConnect(user, "Canvas LMS");
    await fill(user, within(dialog).getByLabelText("School name"), "nyit");
    expect(await within(dialog).findByText(/School search is not working right now/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "My school uses its own address" }));
    expect(within(dialog).getByLabelText("Your school's Canvas address")).toBeInTheDocument();
  });

  it("explains a refused code plainly and saves the fix to the same connector", async () => {
    const { user } = setup([{ ...GITHUB, auth: { ...GITHUB.auth, oauth_configured: false } }]);
    vi.mocked(createConnector).mockImplementation(async (body) =>
      row({ id: "c-gh", connector_type: body.connector_type, display_name: body.display_name }),
    );
    vi.mocked(updateConnector).mockImplementation(async (id, body) =>
      row({ id, connector_type: "github", display_name: body.display_name ?? "GitHub" }),
    );
    vi.mocked(testConnector)
      .mockResolvedValueOnce({ ok: false, detail: "Authentication failed: Bad credentials" })
      .mockResolvedValueOnce({ ok: true, detail: "Connection verified.", user: "octocat" });
    const dialog = await openConnect(user, "GitHub");
    expect(within(dialog).getByRole("link", { name: "Open the GitHub form (opens in a new tab)" })).toHaveAttribute(
      "href",
      GITHUB_TOKEN_URL,
    );

    const code = within(dialog).getByLabelText("GitHub code");
    await fill(user, code, "xoxb-not-github");
    expect(within(dialog).getByText("This looks like a Slack bot code, not one from GitHub.")).toBeInTheDocument();
    await user.clear(code);
    await fill(user, code, "github_pat_first");
    expect(within(dialog).getByText("Looks like a GitHub code.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "GitHub did not accept that code. Make a new one with the form in step 1 and paste it.",
    );
    expect(within(dialog).getByText("What GitHub said: Authentication failed: Bad credentials")).toBeInTheDocument();
    // Saved anyway: its card is on the page behind the dialog.
    expect(screen.getByRole("button", { name: "Edit GitHub" })).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Change what I entered" }));
    const again = within(dialog).getByLabelText("GitHub code");
    expect(again).toHaveValue("github_pat_first");
    expect(within(dialog).getByLabelText("Service")).toBeDisabled();
    await user.clear(again);
    await fill(user, again, "github_pat_second");
    await user.click(within(dialog).getByRole("button", { name: "Save and check again" }));

    expect(createConnector).toHaveBeenCalledTimes(1);
    expect(updateConnector).toHaveBeenCalledWith("c-gh", {
      display_name: "GitHub",
      credentials: { access_token: "github_pat_second" },
      granted_scopes: ["repos.read"],
      permission_tier: "user_confirm",
      rate_limit_per_minute: 30,
    });
    expect(await within(dialog).findByText("Connected to GitHub as octocat")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Edit GitHub" })).toHaveLength(1);
  });

  it("closing after a failed check leaves the connector saved and says what to do", async () => {
    const { user } = setup([{ ...GITHUB, auth: { ...GITHUB.auth, oauth_configured: false } }]);
    vi.mocked(createConnector).mockResolvedValue(row({ id: "c-gh", connector_type: "github", display_name: "GitHub" }));
    vi.mocked(testConnector).mockRejectedValue(new Error("The check could not reach GitHub."));
    const dialog = await openConnect(user, "GitHub");
    await fill(user, within(dialog).getByLabelText("GitHub code"), "github_pat_abc");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Crawler could not reach GitHub. Check your internet connection, then try again.",
    );
    await user.click(within(dialog).getByRole("button", { name: "Close for now" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText(/GitHub is saved, but the check with GitHub did not pass/)).toBeInTheDocument();
  });

  it("closing while the check runs leaves no stale message and reports the real result later", async () => {
    const { user } = setup([{ ...GITHUB, auth: { ...GITHUB.auth, oauth_configured: false } }]);
    vi.mocked(createConnector).mockResolvedValue(row({ id: "c-gh", connector_type: "github", display_name: "GitHub" }));
    const pending = deferred<Awaited<ReturnType<typeof testConnector>>>();
    vi.mocked(testConnector).mockReturnValue(pending.promise);
    const dialog = await openConnect(user, "GitHub");
    await fill(user, within(dialog).getByLabelText("GitHub code"), "github_pat_abc");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    expect(await within(dialog).findByText(/Checking with GitHub/)).toBeInTheDocument();

    // The dialog's own X; the footer's Close does the same.
    await user.click(within(dialog).getAllByRole("button", { name: "Close" })[0]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByText(/is saved/)).not.toBeInTheDocument();

    await act(async () => pending.resolve({ ok: true, detail: "Connection verified.", user: "octocat" }));
    expect(await screen.findByText("Connected to GitHub as octocat")).toBeInTheDocument();
  });

  it("locks the way to connect once a code is saved, so a retry fixes that connector", async () => {
    const { user } = setup([GITHUB]);
    vi.mocked(createConnector).mockResolvedValue(row({ id: "c-gh", connector_type: "github", display_name: "GitHub" }));
    vi.mocked(testConnector).mockResolvedValue({ ok: false, detail: "Authentication failed: Bad credentials" });
    const dialog = await openConnect(user, "GitHub");
    await user.click(within(dialog).getByRole("radio", { name: "Paste a code" }));
    await fill(user, within(dialog).getByLabelText("GitHub code"), "github_pat_abc");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    await user.click(await within(dialog).findByRole("button", { name: "Change what I entered" }));

    // Focus stays in the dialog, on what went wrong.
    expect(document.activeElement).toHaveTextContent("GitHub did not accept that code");
    expect(within(dialog).getByRole("radio", { name: "Sign in with a code" })).toBeDisabled();
    expect(within(dialog).getByRole("radio", { name: "Paste a code" })).toBeChecked();
  });

  it("keeps the school, focus and typed values when going back after a failed check", async () => {
    const { user } = setup([CANVAS]);
    vi.mocked(searchCanvasSchools).mockResolvedValue([{ name: "NYIT", domain: "nyit.instructure.com" }]);
    vi.mocked(createConnector).mockResolvedValue(row({ id: "c-c", connector_type: "canvas", display_name: "Canvas (NYIT)" }));
    vi.mocked(testConnector).mockResolvedValue({
      ok: false,
      detail: "The address answered, but not like this service. Check the address.",
    });
    const dialog = await openConnect(user, "Canvas LMS");
    await fill(user, within(dialog).getByLabelText("School name"), "nyit");
    expect(await within(dialog).findByText("1 school found. Pick yours.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: /nyit\.instructure\.com/ }));
    // The picked school replaces the result that was clicked; focus moves with it.
    expect(within(dialog).getByRole("button", { name: "Change school" })).toHaveFocus();
    await fill(user, within(dialog).getByLabelText("Canvas code"), "1234~abcdefghijklmnopqrstuvwxyz");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "That address is not your school's Canvas. Find your school again in step 1, or check the address you typed.",
    );
    await user.click(within(dialog).getByRole("button", { name: "Change what I entered" }));
    expect(within(dialog).getByText("NYIT")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Canvas code")).toHaveValue("1234~abcdefghijklmnopqrstuvwxyz");

    await user.click(within(dialog).getByRole("button", { name: "Change school" }));
    expect(within(dialog).getByLabelText("School name")).toHaveFocus();
    await user.click(within(dialog).getByRole("button", { name: "My school uses its own address" }));
    expect(within(dialog).getByLabelText("Your school's Canvas address")).toHaveFocus();
  });

  it("keeps a custom name and the approval policy under More settings", async () => {
    const { user } = setup([CANVAS]);
    const dialog = await openConnect(user, "Canvas LMS");
    expect(within(dialog).queryByLabelText("Approval policy")).not.toBeInTheDocument();
    await openMoreSettings(user, dialog);
    expect(within(dialog).getByLabelText(/Name in Crawler/)).toHaveAttribute("placeholder", "Canvas LMS");
    expect(within(dialog).getByLabelText("Approval policy")).toHaveValue("user_confirm");
    expect(within(dialog).getByRole("link", { name: "Technical guide for Canvas LMS (opens in a new tab)" })).toHaveAttribute(
      "href",
      "https://canvas.example.edu/doc/api",
    );
  });

  it("clamps the rate limit to 1 to 600", async () => {
    const { user } = setup([CANVAS]);
    const dialog = await openConnect(user, "Canvas LMS");
    await openMoreSettings(user, dialog);
    const rate = within(dialog).getByLabelText("Most actions per minute");
    expect(rate).toHaveValue(30);
    await user.clear(rate);
    await user.type(rate, "1000");
    expect(rate).toHaveValue(600);
  });
});

describe("token links", () => {
  it("keeps the GitHub card plain and opens the prefilled form from the paste step", async () => {
    const { user } = setup([{ ...GITHUB, docs_url: "https://docs.github.com/pat" }]);
    const card = await screen.findByRole("article", { name: "GitHub" });
    expect(within(card).queryByRole("link")).not.toBeInTheDocument();

    const dialog = await openConnect(user, "GitHub");
    // Device sign-in is the default method: no paste step, no link to the form.
    expect(within(dialog).queryByRole("link", { name: /Open the GitHub form/ })).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("radio", { name: "Paste a code" }));
    expect(within(dialog).getByRole("link", { name: /Open the GitHub form/ })).toHaveAttribute(
      "href",
      GITHUB_TOKEN_URL,
    );
  });

  it("tells people sign-in needs the owner's setup, with the owner's steps one click away", async () => {
    const { user } = setup([microsoft(false), google(false)]);
    const ms = await screen.findByRole("article", { name: "Microsoft 365" });
    expect(within(ms).getByRole("button", { name: "Connect Microsoft 365" })).toBeDisabled();
    expect(within(ms).getByText("Needs a one-time setup by whoever runs this Crawler.")).toBeInTheDocument();
    expect(within(ms).queryByRole("link")).not.toBeInTheDocument();
    await user.click(within(ms).getByRole("button", { name: "How to set it up" }));
    expect(
      within(ms).getByRole("link", { name: "Register a sign-in app for Microsoft 365 (opens in a new tab)" }),
    ).toHaveAttribute("href", MICROSOFT_CLIENT_SETUP_URL);
    expect(within(ms).getByText(/Add its client ID to/)).toHaveTextContent(
      "Add its client ID to backend/.env as MICROSOFT_OAUTH_CLIENT_ID.",
    );
    expect(within(ms).getByText("Restart the backend.")).toBeInTheDocument();

    // Google can still be connected with a code, so its card stays plain.
    const gw = screen.getByRole("article", { name: "Google Workspace" });
    expect(within(gw).queryByRole("link")).not.toBeInTheDocument();

    const dialog = await openConnect(user, "Google Workspace");
    expect(within(dialog).getByText(/needs a one-time setup/)).toHaveTextContent(
      "Sign-in with Google needs a one-time setup by whoever runs this Crawler. Until then, connect with a code from Google below.",
    );
    await user.click(within(dialog).getByRole("button", { name: "How to set it up" }));
    expect(within(dialog).getByText(/Add its client ID and secret/)).toHaveTextContent(
      "Add its client ID and secret to backend/.env as GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET.",
    );
    expect(
      within(dialog).getByRole("link", { name: "Register a sign-in app for Google Workspace (opens in a new tab)" }),
    ).toHaveAttribute("href", "https://console.cloud.google.com/auth/clients");
    expect(within(dialog).getByRole("link", { name: "Open Google's test page (opens in a new tab)" })).toHaveAttribute(
      "href",
      GOOGLE_PLAYGROUND_URL,
    );
  });

  it("does not lead with Google's test page when Google sign-in is ready", async () => {
    const signedIn = row({ id: "c-g", connector_type: "google_workspace", auth_method: "oauth2", display_name: "Mail" });
    const { user } = setup([google()], [signedIn]);
    const card = await screen.findByRole("article", { name: "Google Workspace" });
    expect(within(card).queryByRole("link")).not.toBeInTheDocument();

    // Editing a signed-in row: the advice is Reconnect, so the code link is a small inline link.
    await user.click(screen.getByRole("button", { name: "Edit Mail" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/use Reconnect on the card instead/)).toBeInTheDocument();
    const link = within(dialog).getByRole("link", { name: /Open Google's test page/ });
    expect(link).toHaveAttribute("href", GOOGLE_PLAYGROUND_URL);
    expect(link).toHaveClass("underline");
    expect(within(dialog).queryByText(/Follow the steps there/)).not.toBeInTheDocument();
  });

  it("Edit links the Canvas settings page once the replacement address is typed", async () => {
    const { user } = setup([CANVAS], [row({ id: "c-canvas", connector_type: "canvas", display_name: "School" })]);
    await user.click(await screen.findByRole("button", { name: "Edit School" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByRole("link", { name: /Open my Canvas settings/ })).not.toBeInTheDocument();
    await fill(user, within(dialog).getByLabelText("Your school's Canvas address"), "http://canvas.school.test");
    expect(within(dialog).getByRole("link", { name: /Open my Canvas settings/ })).toHaveAttribute(
      "href",
      "http://canvas.school.test/profile/settings",
    );
  });
});

describe("browser sign-in (OAuth)", () => {
  function startGoogle() {
    vi.mocked(startOAuth).mockResolvedValue({
      flow_id: "flow-1",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=test",
      expires_at: inTenMinutes(),
    });
    return vi.spyOn(window, "open").mockReturnValue(null);
  }

  it("starts the flow, opens the consent page, and stops polling once complete", async () => {
    const open = startGoogle();
    const { user } = setup([google()]);
    vi.mocked(getOAuthStatus)
      .mockResolvedValueOnce({ status: "pending" })
      .mockResolvedValueOnce({ status: "complete", connector_id: "c-g" });
    const dialog = await openConnect(user, "Google Workspace");
    expect(within(dialog).getByRole("radio", { name: "Sign in with Google Workspace" })).toBeChecked();
    expect(within(dialog).queryByLabelText("OAuth access token")).not.toBeInTheDocument();

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();

    expect(startOAuth).toHaveBeenCalledWith("google", {
      display_name: undefined,
      granted_scopes: ["gmail.read", "calendar.read"],
      permission_tier: "user_confirm",
      rate_limit_per_minute: 30,
    });
    expect(open).toHaveBeenCalledWith(
      "https://accounts.google.com/o/oauth2/v2/auth?client_id=test",
      "_blank",
      "noopener,noreferrer",
    );
    expect(screen.getByRole("link", { name: /Open the sign-in page/ })).toHaveAttribute("rel", "noopener noreferrer");
    expect(getOAuthStatus).not.toHaveBeenCalled();

    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);
    expect(getOAuthStatus).toHaveBeenCalledWith("google", "flow-1");
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(2);

    await flush(20_000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("Google Workspace is connected.")).toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(2);
  });

  it("stops polling when the page unmounts", async () => {
    startGoogle();
    const { user, unmount } = setup([google()]);
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "pending" });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);

    unmount();
    await flush(30_000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);
  });

  it("stops when the server reports the flow expired and offers to start again", async () => {
    startGoogle();
    const { user } = setup([google()]);
    vi.mocked(getOAuthStatus)
      .mockResolvedValueOnce({ status: "pending" })
      .mockResolvedValueOnce({ status: "expired", error: "The sign-in expired. Start again." });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    await flush(3000);
    await flush(3000);
    await flush(30_000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("alert")).toHaveTextContent(/expired/);
    expect(screen.getByRole("button", { name: "Start again" })).toBeInTheDocument();
  });

  it("a device clock running ahead of the server does not cut the sign-in short", async () => {
    startGoogle();
    const { user } = setup([google()]);
    vi.mocked(getOAuthStatus)
      .mockResolvedValueOnce({ status: "pending" })
      .mockResolvedValueOnce({ status: "complete", connector_id: "c-g" });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    // By this device's clock the flow expired half an hour ago; the server
    // still says it is pending, and the server is what counts.
    vi.mocked(startOAuth).mockResolvedValue({
      flow_id: "flow-skew",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
      expires_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("Google Workspace is connected.")).toBeInTheDocument();
  });

  it("gives up when the server stays unreachable past expiry plus the clock grace", async () => {
    startGoogle();
    const { user } = setup([google()]);
    vi.mocked(getOAuthStatus).mockRejectedValue(new Error("network down"));
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    vi.mocked(startOAuth).mockResolvedValue({
      flow_id: "flow-2",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
      expires_at: new Date(Date.now() + 5000).toISOString(),
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    await flush(9000);
    // Past expires_at but inside the grace: a blip, keep waiting.
    expect(getOAuthStatus).toHaveBeenCalledTimes(3);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await flush(EXPIRY_GRACE_MS);
    const calls = vi.mocked(getOAuthStatus).mock.calls.length;
    await flush(30_000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(calls);
    expect(screen.getByRole("alert")).toHaveTextContent(/expired/);
    expect(screen.getByRole("button", { name: "Start again" })).toBeInTheDocument();
  });

  it("shows why the sign-in could not start, and clears it on switching service", async () => {
    const { user } = setup([google(), CANVAS]);
    vi.mocked(startOAuth).mockRejectedValue(
      new ApiError("Sign-in with Google is not configured on this server.", 503),
    );
    const dialog = await openConnect(user, "Google Workspace");
    await user.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));

    expect(within(dialog).getByRole("alert")).toHaveTextContent(
      "Sign-in with Google is not configured on this server.",
    );
    expect(within(dialog).queryByText(/Finish signing in/)).not.toBeInTheDocument();

    await user.selectOptions(within(dialog).getByLabelText("Service"), "canvas");
    expect(within(dialog).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("locks the service and method while the sign-in is starting", async () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    const { user } = setup([google(), CANVAS]);
    const pendingStart = deferred<Awaited<ReturnType<typeof startOAuth>>>();
    vi.mocked(startOAuth).mockReturnValue(pendingStart.promise);
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "pending" });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    expect(within(dialog).getByLabelText("Service")).toBeDisabled();
    expect(within(dialog).getByRole("radio", { name: "Paste a code" })).toBeDisabled();

    pendingStart.resolve({
      flow_id: "flow-1",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
      expires_at: inTenMinutes(),
    });
    await flush();
    expect(open).toHaveBeenCalledTimes(1);
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledWith("google", "flow-1");
  });

  it("keeps watching a sign-in after its dialog closes and refreshes the list when it completes", async () => {
    startGoogle();
    const { user } = setup([google()]);
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "pending" });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);

    fireEvent.click(within(dialog).getAllByRole("button", { name: "Close" })[0]);
    await flush();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(1);

    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "complete", connector_id: "c-g" });
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(2);
    expect(getOAuthStatus).toHaveBeenLastCalledWith("google", "flow-1");
    expect(screen.getByText("Google Workspace is connected.")).toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(2);

    await flush(30_000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(2);
  });

  it("watches a sign-in whose dialog closed while the start request was in flight", async () => {
    vi.spyOn(window, "open").mockReturnValue(null);
    const { user } = setup([google()]);
    const pendingStart = deferred<Awaited<ReturnType<typeof startOAuth>>>();
    vi.mocked(startOAuth).mockReturnValue(pendingStart.promise);
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "complete", connector_id: "c-g" });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await flush();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    pendingStart.resolve({
      flow_id: "flow-late",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
      expires_at: inTenMinutes(),
    });
    await flush();
    await flush(3000);
    expect(getOAuthStatus).toHaveBeenCalledWith("google", "flow-late");
    expect(screen.getByText("Google Workspace is connected.")).toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(2);
  });

  it("a closed sign-in that fails ends quietly", async () => {
    startGoogle();
    const { user } = setup([google()]);
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "pending" });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    fireEvent.click(within(dialog).getAllByRole("button", { name: "Close" })[0]);
    await flush();

    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "error", error: "Access was denied." });
    await flush(3000);
    await flush(30_000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(1);
  });

  it("shows the server's error when the flow fails", async () => {
    startGoogle();
    const { user } = setup([google()]);
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "error", error: "Access was denied." });
    const dialog = await openConnect(user, "Google Workspace");

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    await flush(3000);
    await flush(9000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("alert")).toHaveTextContent("Access was denied.");
  });

  it("says when sign-in is not set up and falls back to the token form", async () => {
    const { user } = setup([google(false), microsoft(false)]);
    vi.mocked(createConnector).mockResolvedValue(
      row({ id: "c-g", connector_type: "google_workspace", auth_method: "oauth2", display_name: "Mail" }),
    );

    const ms = await screen.findByRole("article", { name: "Microsoft 365" });
    expect(within(ms).getByText(/one-time setup/)).toBeInTheDocument();
    expect(within(ms).getByRole("button", { name: "Connect Microsoft 365" })).toBeDisabled();

    const dialog = await openConnect(user, "Google Workspace");
    expect(within(dialog).getByText(/needs a one-time setup/)).toHaveTextContent(
      "Until then, connect with a code from Google below.",
    );
    expect(within(dialog).queryByRole("radio")).not.toBeInTheDocument();
    await openMoreSettings(user, dialog);
    await fill(user, within(dialog).getByLabelText(/Name in Crawler/), "Mail");
    await fill(user, within(dialog).getByLabelText("Google code"), "ya29.test-token");
    expect(within(dialog).getByText("Looks like a Google code.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));

    expect(startOAuth).not.toHaveBeenCalled();
    expect(createConnector).toHaveBeenCalledWith(
      expect.objectContaining({
        connector_type: "google_workspace",
        auth_method: "oauth2",
        display_name: "Mail",
        credentials: { access_token: "ya29.test-token" },
        granted_scopes: ["gmail.read", "calendar.read"],
      }),
    );
    expect(await within(dialog).findByText("Connected to Google")).toBeInTheDocument();
  });
});

describe("device sign-in", () => {
  it("shows the user code with a copy button and the verification link, then polls at the provider's interval", async () => {
    const { user } = setup([GITHUB]);
    vi.mocked(startDeviceOAuth).mockResolvedValue({
      flow_id: "flow-d",
      user_code: "WDJB-MJHT",
      verification_uri: "https://github.com/login/device",
      expires_at: inTenMinutes(),
      interval: 5,
    });
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "pending" });
    const dialog = await openConnect(user, "GitHub");
    expect(within(dialog).getByRole("radio", { name: "Sign in with a code" })).toBeChecked();

    useFakeClock();
    fireEvent.click(within(dialog).getByRole("button", { name: "Get a sign-in code" }));
    await flush();
    expect(startDeviceOAuth).toHaveBeenCalledWith(
      "github",
      expect.objectContaining({ granted_scopes: ["repos.read"], rate_limit_per_minute: 30 }),
    );
    expect(screen.getByLabelText("Sign-in code")).toHaveTextContent("WDJB-MJHT");
    expect(screen.getByRole("link", { name: /github\.com\/login\/device/ })).toHaveAttribute(
      "href",
      "https://github.com/login/device",
    );

    // Polls at the provider's interval (5 s), not the default 3 s.
    await flush(3000);
    expect(getOAuthStatus).not.toHaveBeenCalled();
    await flush(2000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(1);
    expect(getOAuthStatus).toHaveBeenCalledWith("github", "flow-d");
    await flush(5000);
    expect(getOAuthStatus).toHaveBeenCalledTimes(2);

    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    fireEvent.click(screen.getByRole("button", { name: "Copy sign-in code" }));
    await flush();
    expect(writeText).toHaveBeenCalledWith("WDJB-MJHT");
    expect(screen.getByRole("button", { name: "Copy sign-in code" })).toHaveTextContent("Copied");
  });

  it("offers the token form as the other method", async () => {
    const { user } = setup([GITHUB]);
    const dialog = await openConnect(user, "GitHub");
    await user.click(within(dialog).getByRole("radio", { name: "Paste a code" }));
    expect(within(dialog).getByLabelText("GitHub code")).toHaveAttribute("type", "password");
    expect(within(dialog).getByRole("button", { name: "Connect" })).toBeDisabled();
  });
});

describe("existing rows", () => {
  it("renders unavailable rows as unavailable with only Remove", async () => {
    setup([CANVAS], [
      row({ id: "c-old", connector_type: "retired_service", display_name: "Old thing", available: false }),
    ]);
    const card = await screen.findByRole("article", { name: "Old thing" });
    expect(within(card).getByText("unavailable")).toBeInTheDocument();
    expect(within(card).getByText(/no longer available on this server/)).toBeInTheDocument();
    expect(within(card).queryByRole("button", { name: /^Test/ })).not.toBeInTheDocument();
    expect(within(card).queryByRole("button", { name: /^Edit/ })).not.toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "Remove Old thing" })).toBeInTheDocument();
  });

  it("shows needs reconnect on a row whose sign-in the provider refused, and highlights Reconnect", async () => {
    setup([google()], [
      row({
        id: "c-dead",
        connector_type: "google_workspace",
        auth_method: "oauth2",
        display_name: "Dead mail",
        needs_reconnect: true,
      }),
      row({ id: "c-ok", connector_type: "google_workspace", auth_method: "oauth2", display_name: "Live mail" }),
    ]);
    const dead = await screen.findByRole("article", { name: "Dead mail" });
    expect(within(dead).getByText("needs reconnect")).toBeInTheDocument();
    expect(within(dead).queryByText("active")).not.toBeInTheDocument();
    expect(within(dead).getByRole("status")).toHaveTextContent(/Press Reconnect to sign in again/);
    expect(within(dead).getByRole("button", { name: "Reconnect Dead mail" })).toHaveStyle({
      color: "var(--accent-warning)",
    });

    const live = screen.getByRole("article", { name: "Live mail" });
    expect(within(live).getByText("active")).toBeInTheDocument();
    expect(within(live).queryByText("needs reconnect")).not.toBeInTheDocument();
    expect(within(live).queryByRole("status")).not.toBeInTheDocument();
  });

  it("a dead sign-in on a disabled row reads inactive, and no Reconnect means no Reconnect hint", async () => {
    setup([google(false)], [
      row({
        id: "c-off",
        connector_type: "google_workspace",
        auth_method: "oauth2",
        display_name: "Off mail",
        is_active: false,
        needs_reconnect: true,
      }),
      row({
        id: "c-noauth",
        connector_type: "google_workspace",
        auth_method: "oauth2",
        display_name: "No sign-in mail",
        needs_reconnect: true,
      }),
    ]);
    const off = await screen.findByRole("article", { name: "Off mail" });
    expect(within(off).getByText("inactive")).toBeInTheDocument();
    expect(within(off).queryByText("needs reconnect")).not.toBeInTheDocument();

    const noAuth = screen.getByRole("article", { name: "No sign-in mail" });
    expect(within(noAuth).getByText("needs reconnect")).toBeInTheDocument();
    expect(within(noAuth).queryByText(/Press Reconnect/)).not.toBeInTheDocument();
    expect(within(noAuth).getByText(/needs a one-time setup by whoever runs this Crawler; ask them/)).toBeInTheDocument();
  });

  it("testing a signed-in row reloads the list, so a refused refresh shows needs reconnect", async () => {
    const signedIn = row({
      id: "c-g",
      connector_type: "google_workspace",
      auth_method: "oauth2",
      display_name: "Work mail",
    });
    const { user } = setup([google()], [signedIn]);
    const card = await screen.findByRole("article", { name: "Work mail" });
    expect(within(card).getByText("active")).toBeInTheDocument();

    vi.mocked(testConnector).mockResolvedValue({
      ok: false,
      detail: "Authentication failed: Google Workspace needs to be reconnected. Reconnect it in Connectors.",
    });
    vi.mocked(getConnectors).mockResolvedValue([{ ...signedIn, needs_reconnect: true }]);
    await user.click(within(card).getByRole("button", { name: "Test Work mail" }));

    expect(await within(card).findByText("needs reconnect")).toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(2);
  });

  it("testing a pasted-token row does not reload the list", async () => {
    const { user } = setup([CANVAS], [row({ id: "c-c", connector_type: "canvas", display_name: "School" })]);
    const card = await screen.findByRole("article", { name: "School" });
    vi.mocked(testConnector).mockResolvedValue({ ok: true, detail: "Connection verified." });
    await user.click(within(card).getByRole("button", { name: "Test School" }));
    expect(await within(card).findByText("Connection verified.")).toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(1);
  });

  it("Reconnect and Grant more access start the sign-in with connector_id", async () => {
    vi.spyOn(window, "open").mockReturnValue(null);
    vi.mocked(startOAuth).mockResolvedValue({
      flow_id: "flow-r",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
      expires_at: inTenMinutes(),
    });
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "pending" });
    const { user } = setup([google()], [
      row({
        id: "c-google",
        connector_type: "google_workspace",
        auth_method: "oauth2",
        display_name: "Work mail",
        granted_scopes: ["gmail.read"],
      }),
    ]);

    await user.click(await screen.findByRole("button", { name: "Reconnect Work mail" }));
    let dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    expect(startOAuth).toHaveBeenLastCalledWith("google", {
      connector_id: "c-google",
      granted_scopes: ["gmail.read"],
    });
    // The header X and the footer both read "Close" while the sign-in waits.
    await user.click(within(screen.getByRole("dialog")).getAllByRole("button", { name: "Close" })[0]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Grant more access to Work mail" }));
    dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByRole("button", { name: /gmail\.read/ })).not.toBeInTheDocument();
    const submit = within(dialog).getByRole("button", { name: "Continue to Google Workspace" });
    expect(submit).toBeDisabled();
    await user.click(within(dialog).getByRole("button", { name: /gmail\.send/ }));
    await user.click(submit);
    expect(startOAuth).toHaveBeenLastCalledWith("google", {
      connector_id: "c-google",
      granted_scopes: ["gmail.send"],
    });
  });

  it("Reconnect closes, shows the notice and reloads the list once the sign-in completes", async () => {
    vi.spyOn(window, "open").mockReturnValue(null);
    vi.mocked(startOAuth).mockResolvedValue({
      flow_id: "flow-r",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
      expires_at: inTenMinutes(),
    });
    vi.mocked(getOAuthStatus).mockResolvedValue({ status: "complete", connector_id: "c-google" });
    setup([google()], [
      row({
        id: "c-google",
        connector_type: "google_workspace",
        auth_method: "oauth2",
        display_name: "Work mail",
        granted_scopes: ["gmail.read"],
      }),
    ]);
    const reconnect = await screen.findByRole("button", { name: "Reconnect Work mail" });

    useFakeClock();
    fireEvent.click(reconnect);
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue to Google Workspace" }));
    await flush();
    expect(getConnectors).toHaveBeenCalledTimes(1);
    await flush(3000);

    expect(getOAuthStatus).toHaveBeenCalledWith("google", "flow-r");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("Work mail is reconnected.")).toBeInTheDocument();
    expect(getConnectors).toHaveBeenCalledTimes(2);
  });

  it("a legacy pasted-token Google row is told to renew in Edit when sign-in is not set up", async () => {
    setup([google(false), microsoft(false)], [
      row({ id: "c-google", connector_type: "google_workspace", auth_method: "oauth2", display_name: "Mail" }),
      row({ id: "c-ms", connector_type: "microsoft", auth_method: "oauth2", display_name: "Outlook" }),
    ]);
    const mail = await screen.findByRole("article", { name: "Mail" });
    expect(within(mail).getByText(/entering a new code in Edit/)).toBeInTheDocument();
    expect(within(mail).queryByText(/cannot be renewed from here/)).not.toBeInTheDocument();
    expect(within(mail).queryByRole("button", { name: "Reconnect Mail" })).not.toBeInTheDocument();

    const outlook = screen.getByRole("article", { name: "Outlook" });
    expect(within(outlook).getByText(/cannot be renewed from here/)).toBeInTheDocument();
  });

  it("a signed-in row's Edit has no credential fields and only removes scopes", async () => {
    const { user } = setup([microsoft(true)], [
      row({
        id: "c-ms",
        connector_type: "microsoft",
        auth_method: "oauth2",
        display_name: "Outlook",
        granted_scopes: ["mail.read"],
      }),
    ]);
    await user.click(await screen.findByRole("button", { name: "Edit Outlook" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByText(/Replace saved codes/)).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: /mail\.send/ })).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: /mail\.read/ })).toHaveAttribute("aria-pressed", "true");
  });

  it("Edit of a pasted-token row replaces credentials only when all required fields are set", async () => {
    vi.mocked(updateConnector).mockImplementation(async (id, body) =>
      row({ id, connector_type: "canvas", display_name: body.display_name ?? "School" }),
    );
    const { user } = setup([CANVAS], [
      row({ id: "c-canvas", connector_type: "canvas", display_name: "School", granted_scopes: ["courses.read"] }),
    ]);
    await user.click(await screen.findByRole("button", { name: "Edit School" }));
    const dialog = screen.getByRole("dialog");
    const save = within(dialog).getByRole("button", { name: "Save changes" });
    await fill(user, within(dialog).getByLabelText("Canvas code"), "new-test-token");
    expect(save).toBeDisabled();
    await fill(user, within(dialog).getByLabelText("Your school's Canvas address"), "https://school.instructure.com");
    await user.click(save);
    expect(updateConnector).toHaveBeenCalledWith("c-canvas", {
      display_name: "School",
      is_active: true,
      granted_scopes: ["courses.read"],
      permission_tier: "user_confirm",
      rate_limit_per_minute: 30,
      credentials: { base_url: "https://school.instructure.com", access_token: "new-test-token" },
    });
  });
});

describe("Slack", () => {
  it("walks through the Slack app, sorts pasted codes into their fields and says what each adds", async () => {
    const { user } = setup([SLACK]);
    vi.mocked(createConnector).mockImplementation(async (body) =>
      row({ id: "c-slack", connector_type: body.connector_type, display_name: body.display_name }),
    );
    vi.mocked(testConnector).mockResolvedValue({ ok: true, detail: "Connection verified.", account: "Acme", user: "crawler" });
    const card = await screen.findByRole("article", { name: "Slack" });
    expect(within(card).queryByRole("link")).not.toBeInTheDocument();

    const dialog = await openConnect(user, "Slack");
    expect(within(dialog).getByRole("link", { name: "Open Slack app setup (opens in a new tab)" })).toHaveAttribute(
      "href",
      "https://api.slack.com/apps?new_app=1",
    );
    // One set of instructions: the steps stand in for auth.notes.
    expect(within(dialog).queryByText("Slack notes from the catalog.")).not.toBeInTheDocument();
    expect(within(dialog).getByText(/Invite the app to a channel/)).toBeInTheDocument();

    const box = within(dialog).getByLabelText("Slack codes");
    expect(box).toHaveAttribute("type", "password");
    const found = within(dialog).getByRole("list", { name: "Codes found" });
    expect(found).toHaveTextContent("Bot code needed (xoxb-)");
    expect(found).toHaveTextContent("App code (optional): chat in Slack DMs");
    // The fixture's catalog has no user code field, so the box does not offer one.
    expect(found).not.toHaveTextContent("User code");

    // A password box drops line breaks, so two codes pasted on two lines arrive run together.
    await fill(user, box, "xoxb-1-bot-codexapp-1-A1-app-code");
    expect(found).toHaveTextContent("Bot code added");
    expect(found).toHaveTextContent("App code added: chat in Slack DMs");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));

    expect(createConnector).toHaveBeenCalledWith(
      expect.objectContaining({
        connector_type: "slack",
        display_name: "Slack",
        credentials: { bot_token: "xoxb-1-bot-code", app_token: "xapp-1-A1-app-code" },
      }),
    );
    expect(await within(dialog).findByText("Connected to Acme as crawler")).toBeInTheDocument();
  });

  it("warns about pasted text that is not a Slack code, and about a second code of a kind", async () => {
    const { user } = setup([SLACK]);
    const dialog = await openConnect(user, "Slack");
    const box = within(dialog).getByLabelText("Slack codes");
    await fill(user, box, "hello xoxb-1-first xoxb-2-second");
    expect(within(dialog).getByText(/Part of what you pasted is not a Slack code/)).toBeInTheDocument();
    expect(within(dialog).getByText(/the first one is used/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Connect" })).toBeEnabled();
  });

  it("links Slack DMs with a one-time code, polls until linked, and unlinks", async () => {
    setup([SLACK], [row({ id: "c-slack", connector_type: "slack", display_name: "Team" })]);
    vi.mocked(createSlackLink).mockResolvedValue({ code: "link-code-123", expires_at: inTenMinutes() });
    vi.mocked(unlinkSlack).mockResolvedValue(undefined);
    const card = await screen.findByRole("article", { name: "Team" });
    const linkButton = await within(card).findByRole("button", { name: "Link Slack DMs" });
    expect(getSlackLinkStatus).toHaveBeenCalledTimes(1);
    vi.mocked(getSlackLinkStatus)
      .mockResolvedValueOnce({
        linked: false,
        channel_running: true,
        pending_code_expires_at: inTenMinutes(),
        has_app_token: true,
      })
      .mockResolvedValueOnce({ linked: true, slack_user_id: "U123", channel_running: true, has_app_token: true });

    useFakeClock();
    fireEvent.click(linkButton);
    await flush();
    expect(createSlackLink).toHaveBeenCalledWith("c-slack");
    expect(within(card).getByLabelText("Slack link code")).toHaveTextContent("link-code-123");
    expect(within(card).getByText(/direct message to the Crawler bot/)).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "Copy Slack link code" })).toBeInTheDocument();

    await flush(3000);
    expect(getSlackLinkStatus).toHaveBeenCalledTimes(2);
    await flush(3000);
    expect(getSlackLinkStatus).toHaveBeenCalledTimes(3);
    expect(within(card).getByText(/Linked to Slack user U123/)).toBeInTheDocument();
    await flush(15_000);
    expect(getSlackLinkStatus).toHaveBeenCalledTimes(3);

    fireEvent.click(within(card).getByRole("button", { name: "Unlink" }));
    await flush();
    expect(unlinkSlack).toHaveBeenCalledWith("c-slack");
    expect(within(card).getByText("Slack DMs are unlinked.")).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "Link Slack DMs" })).toBeInTheDocument();
  });

  it("waits for the Slack code by the server's clock and stops when the server says it expired", async () => {
    setup([SLACK], [row({ id: "c-slack", connector_type: "slack", display_name: "Team" })]);
    const card = await screen.findByRole("article", { name: "Team" });
    const linkButton = await within(card).findByRole("button", { name: "Link Slack DMs" });

    useFakeClock();
    // By this device's clock the code expired long ago; the server still
    // holds it as pending, so the wait goes on until the server says no.
    vi.mocked(createSlackLink).mockResolvedValue({
      code: "link-code-9",
      expires_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    });
    vi.mocked(getSlackLinkStatus)
      .mockResolvedValueOnce({ linked: false, channel_running: true, pending_code_expires_at: inTenMinutes() })
      .mockResolvedValueOnce({ linked: false, channel_running: true, pending_code_expires_at: null });
    fireEvent.click(linkButton);
    await flush();
    await flush(3000);
    expect(getSlackLinkStatus).toHaveBeenCalledTimes(2);
    expect(within(card).getByLabelText("Slack link code")).toHaveTextContent("link-code-9");
    await flush(3000);
    await flush(15_000);
    expect(getSlackLinkStatus).toHaveBeenCalledTimes(3);
    expect(within(card).getByText(/code expired/)).toBeInTheDocument();
    expect(within(card).queryByLabelText("Slack link code")).not.toBeInTheDocument();
  });

  it("stops waiting for the Slack code when the server stays unreachable past its expiry", async () => {
    setup([SLACK], [row({ id: "c-slack", connector_type: "slack", display_name: "Team" })]);
    const card = await screen.findByRole("article", { name: "Team" });
    const linkButton = await within(card).findByRole("button", { name: "Link Slack DMs" });

    useFakeClock();
    vi.mocked(createSlackLink).mockResolvedValue({
      code: "link-code-9",
      expires_at: new Date(Date.now() + 4000).toISOString(),
    });
    vi.mocked(getSlackLinkStatus).mockRejectedValue(new Error("network down"));
    fireEvent.click(linkButton);
    await flush();
    await flush(6000);
    expect(within(card).getByLabelText("Slack link code")).toBeInTheDocument();
    await flush(EXPIRY_GRACE_MS);
    const calls = vi.mocked(getSlackLinkStatus).mock.calls.length;
    await flush(15_000);
    expect(getSlackLinkStatus).toHaveBeenCalledTimes(calls);
    expect(within(card).getByText(/code expired/)).toBeInTheDocument();
  });

  it("offers linking only when the connector has an app-level token", async () => {
    vi.mocked(getSlackLinkStatus).mockResolvedValue({
      linked: false,
      channel_running: false,
      pending_code_expires_at: null,
      has_app_token: false,
    });
    setup([SLACK], [row({ id: "c-slack", connector_type: "slack", display_name: "Team" })]);
    const card = await screen.findByRole("article", { name: "Team" });
    expect(await within(card).findByText(/Add Slack's app code \(it starts with xapp-\) in Edit/)).toBeInTheDocument();
    expect(within(card).queryByRole("button", { name: "Link Slack DMs" })).not.toBeInTheDocument();
    expect(createSlackLink).not.toHaveBeenCalled();
  });

  it("shows the server's reason when a link code is refused (409) and switches to the Edit hint", async () => {
    setup([SLACK], [row({ id: "c-slack", connector_type: "slack", display_name: "Team" })]);
    vi.mocked(createSlackLink).mockRejectedValue(
      new ApiError("This Slack connector has no app-level token (xapp-...).", 409),
    );
    const card = await screen.findByRole("article", { name: "Team" });
    const linkButton = await within(card).findByRole("button", { name: "Link Slack DMs" });

    fireEvent.click(linkButton);
    expect(await within(card).findByRole("alert")).toHaveTextContent("no app-level token");
    expect(within(card).getByText(/Add Slack's app code \(it starts with xapp-\) in Edit/)).toBeInTheDocument();
    expect(within(card).queryByRole("button", { name: "Link Slack DMs" })).not.toBeInTheDocument();
    expect(within(card).queryByLabelText("Slack link code")).not.toBeInTheDocument();
  });

  it("hides DM linking on a server without it", async () => {
    vi.mocked(getSlackLinkStatus).mockRejectedValue(new ApiError("Not Found", 404));
    setup([SLACK], [row({ id: "c-slack", connector_type: "slack", display_name: "Team" })]);
    const card = await screen.findByRole("article", { name: "Team" });
    await act(async () => {});
    expect(within(card).queryByText("Slack DMs")).not.toBeInTheDocument();
    expect(within(card).queryByRole("button", { name: "Link Slack DMs" })).not.toBeInTheDocument();
  });
});

describe("MCP", () => {
  it("is still creatable, with headers parsed from JSON", async () => {
    const { user } = setup([CANVAS]);
    vi.mocked(createConnector).mockResolvedValue(row({ id: "c-mcp", connector_type: "mcp", display_name: "Tools" }));
    const dialog = await openConnect(user, "MCP server");
    expect(within(dialog).getByText(/MCP servers are third-party tools/)).toBeInTheDocument();

    await openMoreSettings(user, dialog);
    await fill(user, within(dialog).getByLabelText(/Name in Crawler/), "Tools");
    await fill(user, within(dialog).getByLabelText("Server URL"), "https://mcp.example.com/mcp");
    const headers = within(dialog).getByLabelText(/Headers \(optional JSON\)/);
    await user.click(headers);
    await user.paste("{bad json");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Headers must be valid JSON.");
    expect(createConnector).not.toHaveBeenCalled();

    await user.clear(headers);
    await user.paste('{"X-Test": "1"}');
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    expect(createConnector).toHaveBeenCalledWith({
      connector_type: "mcp",
      display_name: "Tools",
      auth_method: "bearer_token",
      credentials: { url: "https://mcp.example.com/mcp", headers: { "X-Test": "1" } },
      granted_scopes: [],
      permission_tier: "user_confirm",
      rate_limit_per_minute: 30,
    });
    // MCP is checked once saved too.
    expect(await within(dialog).findByText("Connected to MCP server")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe("connectorCatalog helpers", () => {
  it("catalogEntries keeps creatable entries and appends MCP once", () => {
    const hidden = { ...MYSTERY, key: "hidden", creatable: false };
    expect(catalogEntries([CANVAS, hidden]).map((e) => e.key)).toEqual(["canvas", "mcp"]);
    expect(catalogEntries([MCP_ENTRY]).map((e) => e.key)).toEqual(["mcp"]);
  });

  it("connectOptions only offers sign-ins the server can run", () => {
    expect(connectOptions(google(true))).toEqual({ methods: ["oauth", "token"], signInUnavailable: false });
    expect(connectOptions(google(false))).toEqual({ methods: ["token"], signInUnavailable: true });
    expect(connectOptions(microsoft(false))).toEqual({ methods: [], signInUnavailable: true });
    expect(connectOptions(microsoft(true)).methods).toEqual(["oauth", "device"]);
    expect(connectOptions(CANVAS)).toEqual({ methods: ["token"], signInUnavailable: false });
  });

  it("rowKind tells signed-in, ambiguous, token, MCP and unavailable rows apart", () => {
    const base = { id: "r", granted_scopes: [] };
    expect(rowKind(row({ ...base, connector_type: "x", available: false }), undefined)).toBe("unavailable");
    expect(rowKind(row({ ...base, connector_type: "mcp" }), MCP_ENTRY)).toBe("mcp");
    expect(rowKind(row({ ...base, connector_type: "microsoft", auth_method: "oauth2" }), microsoft(true))).toBe("oauth");
    expect(rowKind(row({ ...base, connector_type: "github", auth_method: "oauth2" }), GITHUB)).toBe("oauth");
    expect(rowKind(row({ ...base, connector_type: "github" }), GITHUB)).toBe("token");
    expect(rowKind(row({ ...base, connector_type: "google_workspace", auth_method: "oauth2" }), google())).toBe(
      "oauth_or_token",
    );
    expect(rowKind(row({ ...base, connector_type: "canvas" }), CANVAS)).toBe("token");
  });

  it("orders scopes by the catalog and describes unknown ones by guess", () => {
    expect(orderedSelection(CANVAS, ["submissions.write", "x.custom", "courses.read", "courses.read"])).toEqual([
      "courses.read",
      "submissions.write",
      "x.custom",
    ]);
    expect(scopeView(CANVAS, "submissions.write")).toMatchObject({ risk: "write", alwaysConfirm: true, known: true });
    expect(scopeView(google(), "calendar.write")).toMatchObject({ risk: "delete", category: "delete" });
    expect(scopeView(undefined, "crypto.trade")).toMatchObject({ risk: "financial", known: false });
  });

  it("validates URL fields and builds credentials", () => {
    const urlField = CANVAS.auth.fields[0];
    expect(fieldError(urlField, "")).toMatch(/required/);
    expect(fieldError(urlField, "javascript:alert(1)")).toMatch(/web address/);
    expect(fieldError(urlField, "https://school.instructure.com")).toBeNull();
    expect(
      buildCredentials(CANVAS.auth.fields, { base_url: " https://s.edu ", access_token: "t", refresh_token: "  " }),
    ).toEqual({ base_url: "https://s.edu", access_token: "t" });
    expect(() => buildCredentials(MCP_ENTRY.auth.fields, { url: "https://m", headers_json: "{" })).toThrow(SyntaxError);
  });

  it("bounds rate limits, poll delays, expiry and external URLs", () => {
    expect(clampRateLimit(0)).toBe(1);
    expect(clampRateLimit(Number.NaN)).toBe(1);
    expect(clampRateLimit(601)).toBe(600);
    expect(clampRateLimit(45)).toBe(45);
    expect(pollDelayMs(undefined)).toBe(3000);
    expect(pollDelayMs(5)).toBe(5000);
    expect(pollDelayMs(0)).toBe(3000);
    expect(pollDelayMs(999)).toBe(30_000);
    expect(isExpired("2000-01-01T00:00:00Z")).toBe(true);
    expect(isExpired(inTenMinutes())).toBe(false);
    expect(isExpired("not a date")).toBe(false);
    const now = Date.parse("2026-09-25T12:00:00Z");
    expect(isPastDeadline("2026-09-25T11:59:00Z", now)).toBe(false);
    expect(isPastDeadline(new Date(now - EXPIRY_GRACE_MS).toISOString(), now)).toBe(true);
    expect(isPastDeadline(null, now)).toBe(false);
    expect(externalUrl("https://example.com/x")).toBe("https://example.com/x");
    expect(externalUrl("javascript:alert(1)")).toBeNull();
    expect(externalUrl("")).toBeNull();
  });

  it("connectorIcon maps known names and falls back to Plug", () => {
    expect(connectorIcon("slack")).toBe(Slack);
    expect(connectorIcon("no-such-icon")).toBe(Plug);
    expect(connectorIcon("constructor")).toBe(Plug);
    expect(connectorIcon(undefined)).toBe(Plug);
  });
});

describe("Allow low-risk changes (permission tiers)", () => {
  const LOW_GITHUB = entry({
    ...GITHUB,
    low_risk: [{ action: "mark_notification_read", note: "mark GitHub notifications read" }],
  });

  it("offers the tier and says what it covers for this connector", async () => {
    vi.mocked(getMe).mockResolvedValue({ default_permission_tier: "low_risk" } as never);
    const { user } = setup([LOW_GITHUB]);
    const dialog = await openConnect(user, "GitHub");
    await openMoreSettings(user, dialog);
    const policy = within(dialog).getByLabelText("Approval policy");
    expect(within(policy).getByRole("option", { name: "Allow low-risk changes" })).toBeInTheDocument();

    await user.selectOptions(policy, "low_risk");

    expect(
      within(dialog).getByText(
        "Low-risk here: mark GitHub notifications read. Sends, deletes, sharing and anything other people see still ask.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(/Capped by your account setting/)).not.toBeInTheDocument();
  });

  it("says when the account default caps the tier chosen here", async () => {
    vi.mocked(getMe).mockResolvedValue({ default_permission_tier: "user_confirm" } as never);
    const { user } = setup([LOW_GITHUB]);
    const dialog = await openConnect(user, "GitHub");
    await openMoreSettings(user, dialog);

    await user.selectOptions(within(dialog).getByLabelText("Approval policy"), "low_risk");

    expect(
      await within(dialog).findByText("Capped by your account setting (User Confirm) in Settings."),
    ).toBeInTheDocument();
  });

  it("says a connector with no low-risk actions still asks for every change", async () => {
    vi.mocked(getMe).mockResolvedValue({ default_permission_tier: "auto_approve" } as never);
    const { user } = setup([CANVAS]);
    const dialog = await openConnect(user, "Canvas LMS");
    await openMoreSettings(user, dialog);

    await user.selectOptions(within(dialog).getByLabelText("Approval policy"), "low_risk");

    expect(
      within(dialog).getByText("This connector has no low-risk actions: every change still asks."),
    ).toBeInTheDocument();
  });

  it("labels a row on the tier", async () => {
    setup([LOW_GITHUB], [row({ id: "g1", connector_type: "github", display_name: "Work GitHub", permission_tier: "low_risk" })]);

    const card = await screen.findByRole("article", { name: "Work GitHub" });
    expect(within(card).getByText("Allow low-risk changes")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Robinhood key pair
// ---------------------------------------------------------------------------

const ROBINHOOD = entry({
  key: "robinhood",
  label: "Robinhood (read-only)",
  icon: "trending-up",
  auth: {
    ...SLACK.auth,
    fields: [
      { key: "api_key", label: "API key", type: "password", required: true, placeholder: "rh-api-...", hint: "" },
      { key: "api_secret", label: "Private key (base64)", type: "password", required: true, placeholder: "", hint: "" },
    ],
    token_auth_method: "api_key",
    token_url: "https://robinhood.com/account/crypto",
    token_url_label: "Open Robinhood crypto API keys",
  },
  scopes: { read: [scope("crypto.read")], write: [] },
});

// 32 bytes in base64.
const BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/;

describe("Robinhood key pair", () => {
  it("fills the private key, shows the public key to register, and posts the generated key", async () => {
    const { user } = setup([ROBINHOOD]);
    vi.mocked(createConnector).mockImplementation(async (body) =>
      row({ id: "c-rh", connector_type: body.connector_type, display_name: body.display_name }),
    );
    const dialog = await openConnect(user, "Robinhood (read-only)");
    expect(within(dialog).queryByLabelText("Public key for Robinhood")).not.toBeInTheDocument();
    // Someone with their own key pair can paste its private key; it starts folded away.
    expect(within(dialog).queryByLabelText("Private key")).not.toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Generate a key pair" }));

    const publicKey = await within(dialog).findByLabelText<HTMLInputElement>("Public key for Robinhood");
    expect(publicKey.value).toMatch(BASE64_KEY);
    expect(publicKey).toHaveAttribute("readonly");
    expect(within(dialog).getByRole("button", { name: "Copy public key" })).toBeInTheDocument();
    expect(
      within(dialog).getByRole("link", { name: "Open Robinhood crypto settings (opens in a new tab)" }),
    ).toHaveAttribute("href", "https://robinhood.com/account/crypto");

    await user.click(within(dialog).getByRole("button", { name: "I already have a key pair" }));
    const secret = within(dialog).getByLabelText<HTMLInputElement>("Private key");
    expect(secret.value).toMatch(BASE64_KEY);
    expect(secret.value).not.toBe(publicKey.value);
    expect(secret).toHaveAttribute("type", "password");
    const generated = secret.value;

    await fill(user, within(dialog).getByLabelText("Robinhood API key"), "rh-api-test");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));

    expect(createConnector).toHaveBeenCalledWith(
      expect.objectContaining({
        connector_type: "robinhood",
        display_name: "Robinhood (read-only)",
        auth_method: "api_key",
        credentials: { api_key: "rh-api-test", api_secret: generated },
      }),
    );
  });

  it("still shows the public key that was registered after a failed check", async () => {
    const { user } = setup([ROBINHOOD]);
    vi.mocked(createConnector).mockResolvedValue(row({ id: "c-rh", connector_type: "robinhood", display_name: "Crypto" }));
    vi.mocked(testConnector).mockResolvedValue({ ok: false, detail: "Authentication failed: Robinhood rejected the API key." });
    const dialog = await openConnect(user, "Robinhood (read-only)");
    await user.click(within(dialog).getByRole("button", { name: "Generate a key pair" }));
    const publicKey = (await within(dialog).findByLabelText<HTMLInputElement>("Public key for Robinhood")).value;
    await fill(user, within(dialog).getByLabelText("Robinhood API key"), "rh-api-wrong");
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    await user.click(await within(dialog).findByRole("button", { name: "Change what I entered" }));

    expect(within(dialog).getByLabelText<HTMLInputElement>("Public key for Robinhood").value).toBe(publicKey);
    expect(within(dialog).getByRole("button", { name: "Copy public key" })).toBeInTheDocument();
  });

  it("hides the public key once the private key is edited by hand", async () => {
    const { user } = setup([ROBINHOOD]);
    const dialog = await openConnect(user, "Robinhood (read-only)");
    await user.click(within(dialog).getByRole("button", { name: "Generate a key pair" }));
    expect(await within(dialog).findByLabelText("Public key for Robinhood")).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "I already have a key pair" }));
    await fill(user, within(dialog).getByLabelText("Private key"), "x");

    expect(within(dialog).queryByLabelText("Public key for Robinhood")).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Generate a key pair" })).toBeInTheDocument();
  });

  it("says why when the browser cannot make the key, and leaves the field empty", async () => {
    const spy = vi
      .spyOn(crypto.subtle, "generateKey")
      .mockRejectedValue(new DOMException("nope", "NotSupportedError"));
    try {
      const { user } = setup([ROBINHOOD]);
      const dialog = await openConnect(user, "Robinhood (read-only)");
      await user.click(within(dialog).getByRole("button", { name: "Generate a key pair" }));

      expect(await within(dialog).findByRole("alert")).toHaveTextContent("cannot make Ed25519 keys");
      await user.click(within(dialog).getByRole("button", { name: "I already have a key pair" }));
      expect(within(dialog).getByLabelText("Private key")).toHaveValue("");
    } finally {
      spy.mockRestore();
    }
  });

  it("is offered when replacing a Robinhood row's credentials, and only there", async () => {
    const { user } = setup([ROBINHOOD, CANVAS], [
      row({ id: "c-rh", connector_type: "robinhood", display_name: "Crypto", auth_method: "api_key" }),
    ]);
    await user.click(await screen.findByRole("button", { name: "Edit Crypto" }));
    const dialog = screen.getByRole("dialog");

    await user.click(within(dialog).getByRole("button", { name: "Generate a key pair" }));

    expect(await within(dialog).findByLabelText("Public key for Robinhood")).toBeInTheDocument();
    expect(within(dialog).getByLabelText<HTMLInputElement>("Private key").value).toMatch(BASE64_KEY);
    // A new pair needs the new API key Robinhood issues for it.
    expect(within(dialog).getByRole("button", { name: "Save changes" })).toBeDisabled();

    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));
    const canvas = await openConnect(user, "Canvas LMS");
    expect(within(canvas).queryByRole("button", { name: "Generate a key pair" })).not.toBeInTheDocument();
  });
});
