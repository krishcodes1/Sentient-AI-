/**
 * Tests for Login's "Create one" link: they prove it shows while registration is open or the setup
 * status is unknown, gives way to a plain hint while the owner's switch or ALLOW_REGISTRATION=false
 * keeps new accounts off, and that a register attempt refused with 403 asks the status again and
 * shows the matching hint (closed, or setup still in progress) in a live region instead of the
 * server's error. A sign-in refused with 403 keeps its own error.
 *
 * Why it exists: Guards against offering a sign-up form that can only end in a 403.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SetupStatus } from "@/types";

vi.mock("@/services/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/services/api")>()),
  getSetupStatus: vi.fn(),
  login: vi.fn(),
  register: vi.fn(),
}));

import Login from "@/pages/Login";
import { ApiError, getSetupStatus, login, register } from "@/services/api";
import { ThemeProvider } from "@/theme";

const HINT = "New accounts are off. Ask the owner of this Crawler to turn them on.";

function status(open: boolean, envLocked = false): SetupStatus {
  return {
    needs_setup: false,
    has_owner: true,
    provider_configured: true,
    setup_completed: true,
    secrets_unreadable: false,
    registration_open: open,
    registration_env_locked: envLocked,
  };
}

function renderLogin() {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={["/login"]}>
        <Login />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

// Synchronous on purpose: the caller's next findBy/waitFor must start before
// the rejected request settles, or React warns about an update outside act.
function sendRegisterForm() {
  fireEvent.change(screen.getByLabelText("Full name"), { target: { value: "Friend" } });
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "friend@example.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "password-123" } });
  fireEvent.click(screen.getByRole("button", { name: "Create account" }));
}

afterEach(() => {
  vi.mocked(getSetupStatus).mockReset();
  vi.mocked(login).mockReset();
  vi.mocked(register).mockReset();
});

describe("Login registration link", () => {
  it("offers Create one while registration is open", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue(status(true));
    renderLogin();
    fireEvent.click(await screen.findByRole("button", { name: "Create one" }));
    expect(screen.getByRole("heading", { name: "Create account" })).toBeInTheDocument();
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
  });

  it.each([
    ["the owner's switch", status(false)],
    ["ALLOW_REGISTRATION=false", status(false, true)],
  ])("shows the hint instead of Create one while %s keeps it closed", async (_, closed) => {
    vi.mocked(getSetupStatus).mockResolvedValue(closed);
    renderLogin();
    expect(await screen.findByText(HINT)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create one" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("keeps Create one when the status is unknown", async () => {
    vi.mocked(getSetupStatus).mockRejectedValue(new Error("offline"));
    renderLogin();
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalled());
    expect(await screen.findByRole("button", { name: "Create one" })).toBeInTheDocument();
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
  });

  it("keeps Create one when the status has no registration_open", async () => {
    // A server from before the field: only an explicit false closes it.
    const older: Partial<SetupStatus> = status(true);
    delete older.registration_open;
    vi.mocked(getSetupStatus).mockResolvedValue(older as SetupStatus);
    renderLogin();
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalled());
    expect(await screen.findByRole("button", { name: "Create one" })).toBeInTheDocument();
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
  });

  it("keeps the setup hint while setup is in progress", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue({
      ...status(false),
      needs_setup: true,
      setup_completed: false,
    });
    renderLogin();
    expect(
      await screen.findByText("Setup is in progress — sign in as the owner to finish it."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create one" })).not.toBeInTheDocument();
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
  });

  it.each([
    // The owner closed it before the form was sent, and the second look says so.
    ["closed", status(false)],
    // The second look is itself stale; the server's 403 still wins.
    ["still open", status(true)],
  ])(
    "shows the hint, not the raw error, when register is refused with 403 (re-check: %s)",
    async (_, recheck) => {
      vi.mocked(getSetupStatus)
        .mockResolvedValueOnce(status(true))
        .mockResolvedValueOnce(recheck);
      vi.mocked(register).mockRejectedValue(
        new ApiError("Registration is disabled on this server", 403),
      );
      renderLogin();
      // The live region is there, empty, before the refusal, so the hint
      // that lands in it gets announced.
      const live = screen.getByRole("status");
      expect(live).toBeEmptyDOMElement();
      fireEvent.click(await screen.findByRole("button", { name: "Create one" }));
      sendRegisterForm();

      await waitFor(() => expect(live).toHaveTextContent(HINT));
      expect(register).toHaveBeenCalledTimes(1);
      expect(getSetupStatus).toHaveBeenCalledTimes(2);
      expect(
        screen.queryByText("Registration is disabled on this server"),
      ).not.toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      // Back to sign-in, with no way into a form the server refuses.
      expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Create one" })).not.toBeInTheDocument();
    },
  );

  it("points to setup when a 403 shows setup was never finished", async () => {
    // The backend was still starting when the page loaded, so the status is
    // unknown; by the time the form is sent it answers, and nobody has set
    // it up yet.
    vi.mocked(getSetupStatus)
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValueOnce({
        ...status(false),
        needs_setup: true,
        has_owner: false,
        setup_completed: false,
      });
    vi.mocked(register).mockRejectedValue(
      new ApiError("Registration is disabled until setup is complete", 403),
    );
    renderLogin();
    fireEvent.click(await screen.findByRole("button", { name: "Create one" }));
    sendRegisterForm();

    const live = screen.getByRole("status");
    const link = await within(live).findByRole("link", { name: "Set up this Crawler" });
    expect(link).toHaveAttribute("href", "/setup");
    expect(getSetupStatus).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("shows the server's reason when the re-check after a 403 fails too", async () => {
    vi.mocked(getSetupStatus).mockRejectedValue(new Error("offline"));
    vi.mocked(register).mockRejectedValue(
      new ApiError("Registration is disabled until setup is complete", 403),
    );
    renderLogin();
    fireEvent.click(await screen.findByRole("button", { name: "Create one" }));
    sendRegisterForm();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Registration is disabled until setup is complete",
    );
    expect(getSetupStatus).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Create account" })).toBeInTheDocument();
  });

  it("still shows other register errors as they are", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue(status(true));
    vi.mocked(register).mockRejectedValue(new ApiError("Email already registered", 400));
    renderLogin();
    fireEvent.click(await screen.findByRole("button", { name: "Create one" }));
    sendRegisterForm();

    expect(await screen.findByRole("alert")).toHaveTextContent("Email already registered");
    expect(getSetupStatus).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Create account" })).toBeInTheDocument();
  });

  it("shows a sign-in refused with 403 as it is and keeps Create one", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue(status(true));
    vi.mocked(login).mockRejectedValue(new ApiError("Account is deactivated", 403));
    renderLogin();
    await screen.findByRole("button", { name: "Create one" });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "friend@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "password-123" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue to gateway" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Account is deactivated");
    expect(login).toHaveBeenCalledTimes(1);
    expect(getSetupStatus).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create one" })).toBeInTheDocument();
  });
});
