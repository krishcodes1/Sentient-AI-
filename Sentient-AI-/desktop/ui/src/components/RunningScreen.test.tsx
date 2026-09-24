/**
 * Status-screen tests: every button calls the matching bridge command, status follows phase
 * events, logs show streamed output, and update results are explained with a safe link.
 *
 * Why it exists: This screen is the app's everyday control panel; a button wired to the wrong
 * command (Stop that starts, Open that stops) is the kind of bug that only shows up for users.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppInfo } from "../bridge";
import { WORDS } from "../platform";
import { installBridge, mocked, type BridgeHarness } from "../test/bridge";
import { RunningScreen } from "./RunningScreen";

vi.mock("../bridge");

const INFO: AppInfo = { version: "0.1.0", platform: "mac", installed: true };
let bridge: BridgeHarness;

beforeEach(() => {
  bridge = installBridge({ appInfo: INFO });
});

function renderScreen(onSetupAgain = vi.fn()) {
  render(<RunningScreen info={INFO} words={WORDS.mac} onSetupAgain={onSetupAgain} />);
  return onSetupAgain;
}

describe("RunningScreen", () => {
  it("Open Crawler AI calls open_crawler", async () => {
    const user = userEvent.setup();
    renderScreen();
    await user.click(screen.getByRole("button", { name: "Open Crawler AI" }));
    expect(mocked.openCrawler).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("Opened Crawler AI.")).toBeInTheDocument();
    expect(mocked.stackStart).not.toHaveBeenCalled();
    expect(mocked.stackStop).not.toHaveBeenCalled();
  });

  it("Start calls stack_start and Stop calls stack_stop", async () => {
    const user = userEvent.setup();
    renderScreen();
    await user.click(screen.getByRole("button", { name: "Start" }));
    expect(mocked.stackStart).toHaveBeenCalledTimes(1);
    expect(mocked.stackStop).not.toHaveBeenCalled();
    expect(await screen.findByText("Crawler AI is starting. It’s ready in a few seconds.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stop" }));
    expect(mocked.stackStop).toHaveBeenCalledTimes(1);
    expect(mocked.stackStart).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/Crawler AI is stopped/)).toBeInTheDocument();
    expect(screen.getByText("Stopped")).toBeInTheDocument();
  });

  it("shows Rust's error when Start fails", async () => {
    const user = userEvent.setup();
    mocked.stackStart.mockRejectedValueOnce("Docker Desktop isn't running");
    renderScreen();
    await user.click(screen.getByRole("button", { name: "Start" }));
    expect(await screen.findByText("Couldn’t start Crawler AI: Docker Desktop isn't running")).toBeInTheDocument();
  });

  it("status follows install_status and then phase events", async () => {
    mocked.installStatus.mockResolvedValue({ phase: "healthy", elapsed_s: 0 });
    renderScreen();
    expect(await screen.findByText("Running")).toBeInTheDocument();
    await waitFor(() => expect(bridge.listeners()).toBe(2));
    bridge.emitPhase({ phase: "stopping", elapsed_s: 0 });
    expect(screen.getByText("Stopping…")).toBeInTheDocument();
    bridge.emitPhase({ phase: "stopped", elapsed_s: 0 });
    expect(screen.getByText("Stopped")).toBeInTheDocument();
  });

  it("Show logs reveals streamed output and Hide logs hides it", async () => {
    const user = userEvent.setup();
    renderScreen();
    await waitFor(() => expect(bridge.listeners()).toBe(2));
    const toggle = screen.getByRole("button", { name: "Show logs" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(screen.getByText(/No output yet/)).toBeVisible();

    bridge.emitLog("backend-1  | INFO:     Application startup complete.");
    const log = await screen.findByLabelText("Crawler AI output");
    expect(log).toHaveTextContent("Application startup complete.");
    expect(screen.getByRole("button", { name: "Hide logs" })).toHaveAttribute("aria-expanded", "true");

    await user.click(screen.getByRole("button", { name: "Hide logs" }));
    expect(log).not.toBeVisible();
  });

  it("the tray's Show logs opens the logs panel", async () => {
    renderScreen();
    await waitFor(() => expect(mocked.onShowLogs).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: "Show logs" })).toHaveAttribute("aria-expanded", "false");
    bridge.emitShowLogs();
    expect(await screen.findByRole("button", { name: "Hide logs" })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/No output yet/)).toBeVisible();
  });

  it("Check for updates reports a newer version with a download link", async () => {
    const user = userEvent.setup();
    mocked.checkUpdates.mockResolvedValueOnce({
      latest: "0.2.0",
      url: "https://github.com/example/crawler-ai/releases/tag/desktop-v0.2.0",
      newer: true,
    });
    renderScreen();
    await user.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(mocked.checkUpdates).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/Crawler AI 0.2.0 is available \(you have 0.1.0\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download the update" })).toHaveAttribute(
      "href",
      "https://github.com/example/crawler-ai/releases/tag/desktop-v0.2.0",
    );
  });

  it("Check for updates says when you're up to date, and when it couldn't check", async () => {
    const user = userEvent.setup();
    mocked.checkUpdates
      .mockResolvedValueOnce({ latest: "0.1.0", url: "https://github.com/", newer: false })
      .mockRejectedValueOnce("offline");
    renderScreen();
    await user.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(await screen.findByText("You’re on the latest version (0.1.0).")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(
      await screen.findByText("Couldn’t check for updates. Check your internet connection, then try again."),
    ).toBeInTheDocument();
  });

  it("never links to a non-https update URL", async () => {
    const user = userEvent.setup();
    mocked.checkUpdates.mockResolvedValueOnce({ latest: "9.9.9", url: "http://evil.example/", newer: true });
    renderScreen();
    await user.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(await screen.findByText(/Crawler AI 9.9.9 is available/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Download the update" })).not.toBeInTheDocument();
  });

  it("shows the version and can go back to setup", async () => {
    const user = userEvent.setup();
    const onSetupAgain = renderScreen();
    expect(screen.getByText(/Version 0.1.0 · macOS/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run setup again" }));
    expect(onSetupAgain).toHaveBeenCalled();
  });
});
