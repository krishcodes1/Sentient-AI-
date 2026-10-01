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
    notes: "base_url is your school's Canvas instance.",
  },
  scopes: {
    read: [scope("courses.read"), scope("grades.read")],
    write: [scope("submissions.write", "write", true)],
  },
});

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
    },
    scopes: {
      read: [scope("gmail.read"), scope("calendar.read")],
      write: [scope("gmail.send", "write", true), scope("calendar.write", "delete", true)],
    },
  });
}

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
  },
  scopes: { read: [scope("repos.read")], write: [scope("issues.write", "write")] },
});

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
    },
    scopes: { read: [scope("mail.read")], write: [scope("mail.send", "write", true)] },
  });
}

const SLACK = entry({
  key: "slack",
  label: "Slack",
  icon: "slack",
  docs_url: "https://api.slack.com/apps?new_app=1",
  auth: {
    methods: ["token"],
    fields: [
      { key: "bot_token", label: "Bot token", type: "password", required: true, placeholder: "xoxb-", hint: "" },
      { key: "app_token", label: "App-level token", type: "password", required: false, placeholder: "xapp-", hint: "" },
    ],
    provider: null,
    oauth_configured: false,
    token_auth_method: "bearer_token",
    notes: "",
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
});

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Page behaviour
// ---------------------------------------------------------------------------

describe("Connectors catalog", () => {
  it("renders a card per catalog entry plus MCP, with icons and an unknown-icon fallback", async () => {
    setup([CANVAS, MYSTERY]);

    const canvas = await screen.findByRole("article", { name: "Canvas LMS" });
    expect(canvas.querySelector("svg.lucide-graduation-cap")).not.toBeNull();
    expect(within(canvas).getByText("Canvas LMS description.")).toBeInTheDocument();
    const docs = within(canvas).getByRole("link", { name: /setup guide/i });
    expect(docs).toHaveAttribute("href", "https://canvas.example.edu/doc/api");
    expect(docs).toHaveAttribute("target", "_blank");
    expect(docs.getAttribute("rel")).toContain("noopener");

    const mystery = screen.getByRole("article", { name: "Mystery Box" });
    expect(mystery.querySelector("svg.lucide-plug")).not.toBeNull();

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

describe("pasted-token connect", () => {
  it("posts auth_method, credentials from the fields, and read scopes preselected with write opt-in", async () => {
    const { user } = setup([CANVAS]);
    vi.mocked(createConnector).mockImplementation(async (body) =>
      row({ id: "c-new", connector_type: body.connector_type, display_name: body.display_name }),
    );
    const dialog = await openConnect(user, "Canvas LMS");
    const submit = within(dialog).getByRole("button", { name: "Create connector" });

    await fill(user, within(dialog).getByLabelText("Display name"), "School");
    const url = within(dialog).getByLabelText("Canvas URL");
    await fill(user, url, "not a url");
    expect(within(dialog).getByText(/Enter a full web address/)).toBeInTheDocument();
    expect(url).toHaveAttribute("aria-invalid", "true");
    await user.clear(url);
    await fill(user, url, "https://school.instructure.com");
    const token = within(dialog).getByLabelText("Access token");
    expect(token).toHaveAttribute("type", "password");
    expect(submit).toBeDisabled();
    await fill(user, token, "canvas-test-token");

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
      display_name: "School",
      auth_method: "bearer_token",
      credentials: { base_url: "https://school.instructure.com", access_token: "canvas-test-token" },
      granted_scopes: ["courses.read", "grades.read", "submissions.write"],
      permission_tier: "user_confirm",
      rate_limit_per_minute: 30,
    });
    expect(await screen.findByRole("article", { name: "School" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("clamps the rate limit to 1 to 600", async () => {
    const { user } = setup([CANVAS]);
    const dialog = await openConnect(user, "Canvas LMS");
    const rate = within(dialog).getByLabelText("Rate limit (/min)");
    expect(rate).toHaveValue(30);
    await user.clear(rate);
    await user.type(rate, "1000");
    expect(rate).toHaveValue(600);
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
    expect(within(dialog).getByRole("radio", { name: "Paste a token" })).toBeDisabled();

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
    expect(within(ms).getByText(/not set up on this server/)).toBeInTheDocument();
    expect(within(ms).getByRole("button", { name: "Connect Microsoft 365" })).toBeDisabled();

    const dialog = await openConnect(user, "Google Workspace");
    expect(within(dialog).getByText(/not set up on this server/)).toHaveTextContent("You can paste a token instead.");
    expect(within(dialog).queryByRole("radio")).not.toBeInTheDocument();
    await fill(user, within(dialog).getByLabelText("Display name"), "Mail");
    await fill(user, within(dialog).getByLabelText("OAuth access token"), "ya29.test-token");
    await user.click(within(dialog).getByRole("button", { name: "Create connector" }));

    expect(startOAuth).not.toHaveBeenCalled();
    expect(createConnector).toHaveBeenCalledWith(
      expect.objectContaining({
        connector_type: "google_workspace",
        auth_method: "oauth2",
        credentials: { access_token: "ya29.test-token" },
        granted_scopes: ["gmail.read", "calendar.read"],
      }),
    );
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
    await user.click(within(dialog).getByRole("radio", { name: "Paste a token" }));
    expect(within(dialog).getByLabelText("Personal access token")).toHaveAttribute("type", "password");
    expect(within(dialog).getByRole("button", { name: "Create connector" })).toBeDisabled();
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
    expect(within(noAuth).getByText(/ask the administrator/)).toBeInTheDocument();
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
    expect(within(mail).getByText(/pasting a new token in Edit/)).toBeInTheDocument();
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
    expect(within(dialog).queryByText(/Replace credentials/)).not.toBeInTheDocument();
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
    await fill(user, within(dialog).getByLabelText("Access token"), "new-test-token");
    expect(save).toBeDisabled();
    await fill(user, within(dialog).getByLabelText("Canvas URL"), "https://school.instructure.com");
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
  it("links the manifest and explains the three tokens", async () => {
    const { user } = setup([SLACK]);
    const card = await screen.findByRole("article", { name: "Slack" });
    expect(within(card).getByRole("link", { name: /app manifest/i })).toHaveAttribute(
      "href",
      "https://api.slack.com/apps?new_app=1",
    );
    const dialog = await openConnect(user, "Slack");
    expect(within(dialog).getByText(/app-level token/)).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: /manifest/ })).toBeInTheDocument();
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
    expect(await within(card).findByText(/Add an app-level token \(xapp-\) in Edit/)).toBeInTheDocument();
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
    expect(within(card).getByText(/Add an app-level token \(xapp-\) in Edit/)).toBeInTheDocument();
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

    await fill(user, within(dialog).getByLabelText("Display name"), "Tools");
    await fill(user, within(dialog).getByLabelText("Server URL"), "https://mcp.example.com/mcp");
    const headers = within(dialog).getByLabelText(/Headers \(optional JSON\)/);
    await user.click(headers);
    await user.paste("{bad json");
    await user.click(within(dialog).getByRole("button", { name: "Create connector" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Headers must be valid JSON.");
    expect(createConnector).not.toHaveBeenCalled();

    await user.clear(headers);
    await user.paste('{"X-Test": "1"}');
    await user.click(within(dialog).getByRole("button", { name: "Create connector" }));
    expect(createConnector).toHaveBeenCalledWith({
      connector_type: "mcp",
      display_name: "Tools",
      auth_method: "bearer_token",
      credentials: { url: "https://mcp.example.com/mcp", headers: { "X-Test": "1" } },
      granted_scopes: [],
      permission_tier: "user_confirm",
      rate_limit_per_minute: 30,
    });
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

    await user.selectOptions(within(dialog).getByLabelText("Approval policy"), "low_risk");

    expect(
      await within(dialog).findByText("Capped by your account setting (User Confirm) in Settings."),
    ).toBeInTheDocument();
  });

  it("says a connector with no low-risk actions still asks for every change", async () => {
    vi.mocked(getMe).mockResolvedValue({ default_permission_tier: "auto_approve" } as never);
    const { user } = setup([CANVAS]);
    const dialog = await openConnect(user, "Canvas LMS");

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
