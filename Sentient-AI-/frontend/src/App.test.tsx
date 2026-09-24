import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { SetupStatus } from "@/types";

vi.mock("@/services/api", () => ({
  getSetupStatus: vi.fn(),
  login: vi.fn(),
  register: vi.fn(),
}));

import App from "@/App";
import { getSetupStatus } from "@/services/api";
import { ThemeProvider } from "@/theme";

function status(needsSetup: boolean, hasOwner: boolean): SetupStatus {
  return {
    needs_setup: needsSetup,
    has_owner: hasOwner,
    provider_configured: !needsSetup,
    setup_completed: !needsSetup,
    secrets_unreadable: false,
  };
}

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

describe("SetupGate", () => {
  it.each(["/", "/login", "/settings"])("sends %s to /setup while the server needs setup", async (path) => {
    vi.mocked(getSetupStatus).mockResolvedValue(status(true, false));
    renderAt(path);
    // /setup is a lazy chunk; its first transform can outlast findBy's 1s
    // default when the whole suite is compiling in parallel.
    expect(
      await screen.findByRole("heading", { name: "Create the owner account" }, { timeout: 5000 }),
    ).toBeInTheDocument();
  });

  it("renders /login normally once setup is done", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue(status(false, true));
    renderAt("/login");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    // SetupGate asks once to decide routing; Login asks again on its own to
    // decide whether "Create one" is honest to show — see its setupStatus
    // effect.
    expect(getSetupStatus).toHaveBeenCalledTimes(2);
  });

  it("lets an existing owner reach /login to finish an interrupted setup", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue(status(true, true));
    renderAt("/login");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("does not lock the app when the status check fails", async () => {
    vi.mocked(getSetupStatus).mockRejectedValue(new Error("404"));
    renderAt("/login");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});
