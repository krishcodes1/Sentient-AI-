/**
 * Whole-window tests: first run walks through all four steps to the status screen, an
 * installed app opens on the status screen, keys already set skip step 2, a running install is
 * resumed, and Windows gets Windows wording.
 *
 * Why it exists: The steps are tested one by one elsewhere; this proves they are wired together
 * in the right order with the right gates.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { installBridge, mocked, readyReport, type BridgeHarness } from "./test/bridge";

vi.mock("./bridge");

let bridge: BridgeHarness;

beforeEach(() => {
  bridge = installBridge();
});

function step(title: string) {
  const heading = screen.getByRole("heading", { name: title });
  return heading.closest("li") as HTMLElement;
}

describe("App", () => {
  it("walks a first run from Check to the status screen", async () => {
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Set up Crawler AI on this Mac" })).toBeInTheDocument();
    expect(step("Check this computer")).toHaveAttribute("data-state", "active");
    expect(step("Security keys")).toHaveAttribute("data-state", "locked");

    await user.click(await screen.findByRole("button", { name: "Continue" }));
    expect(step("Check this computer")).toHaveAttribute("data-state", "done");
    expect(within(step("Check this computer")).getByText("Docker Desktop is running (Compose 2.39.2).")).toBeInTheDocument();
    expect(step("Security keys")).toHaveAttribute("data-state", "active");
    expect(screen.getByRole("heading", { name: "Security keys" })).toHaveFocus();

    await user.click(screen.getByRole("button", { name: "Save keys" }));
    await user.click(await screen.findByRole("button", { name: "Next" }));
    expect(step("Install & start")).toHaveAttribute("data-state", "active");

    // "Replace keys" goes back to step 2 until the install starts.
    expect(screen.getByRole("button", { name: "Replace keys" })).toBeInTheDocument();
    await waitFor(() => expect(bridge.listeners()).toBe(2));
    await user.click(screen.getByRole("button", { name: "Install & start Crawler AI" }));
    await screen.findByLabelText("Install output");
    expect(screen.queryByRole("button", { name: "Replace keys" })).not.toBeInTheDocument();

    bridge.emitPhase({ phase: "healthy", elapsed_s: 321 });
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(step("Open Crawler AI")).toHaveAttribute("data-state", "active");

    await user.click(within(step("Open Crawler AI")).getByRole("button", { name: "Open Crawler AI" }));
    expect(mocked.openCrawler).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("heading", { name: "Crawler AI is installed" })).toBeInTheDocument();
  });

  it("skips the keys step when keys are already set", async () => {
    const user = userEvent.setup();
    mocked.preflight.mockResolvedValue(readyReport({ env_keys_set: true }));
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Continue to Install" }));
    expect(step("Security keys")).toHaveAttribute("data-state", "done");
    expect(within(step("Security keys")).getByText("Keys already set on this computer.")).toBeInTheDocument();
    expect(step("Install & start")).toHaveAttribute("data-state", "active");
    expect(mocked.saveKeys).not.toHaveBeenCalled();
  });

  it("lets people go back and replace keys before installing", async () => {
    const user = userEvent.setup();
    mocked.preflight.mockResolvedValue(readyReport({ env_keys_set: true }));
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Continue to Install" }));
    await user.click(screen.getByRole("button", { name: "Replace keys" }));
    expect(step("Security keys")).toHaveAttribute("data-state", "active");
    expect(step("Install & start")).toHaveAttribute("data-state", "locked");
  });

  it("opens on the status screen once installed", async () => {
    mocked.appInfo.mockResolvedValue({ version: "0.3.1", platform: "mac", installed: true });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Crawler AI is installed" })).toBeInTheDocument();
    expect(screen.getByText(/Version 0.3.1/)).toBeInTheDocument();
    expect(mocked.preflight).not.toHaveBeenCalled();
  });

  it("resumes a running install straight into step 3", async () => {
    mocked.installStatus.mockResolvedValue({ phase: "building", elapsed_s: 42 });
    render(<App />);
    expect(await screen.findByText("Building images…")).toBeInTheDocument();
    expect(step("Install & start")).toHaveAttribute("data-state", "active");
    expect(mocked.startInstall).not.toHaveBeenCalled();
  });

  it("uses Windows wording on Windows", async () => {
    mocked.appInfo.mockResolvedValue({ version: "0.1.0", platform: "windows", installed: false });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Set up Crawler AI on this PC" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Docker Desktop for Windows" })).toBeInTheDocument();
    expect(screen.getByText(/Docker Desktop needs WSL 2/)).toBeInTheDocument();
  });

  it("falls back to setup when app_info fails", async () => {
    mocked.appInfo.mockRejectedValue("no app");
    render(<App />);
    expect(await screen.findByRole("heading", { name: /Set up Crawler AI on this/ })).toBeInTheDocument();
  });
});
