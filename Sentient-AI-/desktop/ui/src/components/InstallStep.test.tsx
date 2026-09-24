/**
 * Step 3 tests: output streams into the log as events arrive, phases drive the progress line,
 * success offers Next, failure shows the reason and the last lines with a working Retry.
 *
 * Why it exists: The install is the long, failure-prone part of setup; the screen must reflect
 * exactly what Rust reports and always leave a way forward.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { installBridge, mocked, type BridgeHarness } from "../test/bridge";
import { InstallStep } from "./InstallStep";

vi.mock("../bridge");

let bridge: BridgeHarness;

beforeEach(() => {
  bridge = installBridge();
});

async function startInstall(props: Partial<Parameters<typeof InstallStep>[0]> = {}) {
  const user = userEvent.setup();
  const onStarted = vi.fn();
  const onNext = vi.fn();
  const view = render(<InstallStep resume={null} onStarted={onStarted} onNext={onNext} {...props} />);
  await waitFor(() => expect(bridge.listeners()).toBe(2));
  await user.click(screen.getByRole("button", { name: "Install & start Crawler AI" }));
  await screen.findByLabelText("Install output");
  return { user, onStarted, onNext, view };
}

describe("InstallStep", () => {
  it("streams log lines and phases, then offers Next when healthy", async () => {
    const { onStarted, onNext, user } = await startInstall();
    expect(mocked.startInstall).toHaveBeenCalledTimes(1);
    expect(onStarted).toHaveBeenCalled();
    expect(screen.getByText("Preparing Crawler AI’s files…")).toBeInTheDocument();

    bridge.emitPhase({ phase: "building", elapsed_s: 65 });
    expect(screen.getByText("Building images…")).toBeInTheDocument();
    expect(screen.getByText("1:05")).toBeInTheDocument();

    bridge.emitLog("#5 [backend 3/6] RUN pip install -r requirements.txt");
    bridge.emitLog("\u001b[32m#14 exporting to image\u001b[0m");
    const log = screen.getByLabelText("Install output");
    await waitFor(() => expect(log).toHaveTextContent("#5 [backend 3/6] RUN pip install -r requirements.txt"));
    expect(log).toHaveTextContent("#14 exporting to image");
    expect(log.textContent).not.toContain("\u001b");

    bridge.emitPhase({ phase: "healthy", elapsed_s: 400 });
    expect(screen.getByText("Crawler AI is running ✓")).toBeInTheDocument();
    const next = screen.getByRole("button", { name: "Next" });
    expect(next).toHaveFocus();
    await user.click(next);
    expect(onNext).toHaveBeenCalled();
  });

  it("shows the failure reason and last lines, and Retry starts the install again", async () => {
    const { user } = await startInstall();
    bridge.emitLog("#11 [frontend 4/5] RUN npm ci");
    bridge.emitLog("npm ERR! network timeout");
    bridge.emitPhase({ phase: "failed", elapsed_s: 200, error: "Docker Compose stopped while building the web app." });

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("The install stopped")).toBeInTheDocument();
    expect(within(alert).getByText("Docker Compose stopped while building the web app.")).toBeInTheDocument();
    await waitFor(() =>
      expect(within(alert).getByLabelText("Last lines of output")).toHaveTextContent("npm ERR! network timeout"),
    );
    expect(screen.queryByRole("button", { name: "Next" })).not.toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(mocked.startInstall).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(screen.getByText("Preparing Crawler AI’s files…")).toBeInTheDocument();

    bridge.emitPhase({ phase: "healthy", elapsed_s: 90 });
    expect(screen.getByRole("button", { name: "Next" })).toBeInTheDocument();
  });

  it("uses a generic reason when Rust sends none", async () => {
    await startInstall();
    bridge.emitPhase({ phase: "failed", elapsed_s: 3 });
    expect(await screen.findByText("Something went wrong. The output above says why.")).toBeInTheDocument();
  });

  it("says so when the install can't start, and the button stays usable", async () => {
    const user = userEvent.setup();
    mocked.startInstall.mockResolvedValueOnce({ ok: false });
    render(<InstallStep resume={null} onStarted={vi.fn()} onNext={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Install & start Crawler AI" }));
    expect(
      await screen.findByText("The install couldn’t start. Click the button to try again."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Install & start Crawler AI" })).toBeEnabled();
  });

  it("follows an install that is already running instead of failing", async () => {
    const user = userEvent.setup();
    mocked.startInstall.mockResolvedValueOnce({ ok: false });
    mocked.installStatus.mockResolvedValue({ phase: "building", elapsed_s: 30 });
    render(<InstallStep resume={null} onStarted={vi.fn()} onNext={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Install & start Crawler AI" }));
    expect(await screen.findByText("Building images…")).toBeInTheDocument();
  });

  it("resumes an install that was running when the window opened", async () => {
    render(<InstallStep resume={{ phase: "waiting_backend", elapsed_s: 125 }} onStarted={vi.fn()} onNext={vi.fn()} />);
    expect(screen.getByText("Waiting for the backend…")).toBeInTheDocument();
    expect(screen.getByText("2:05")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Install & start Crawler AI" })).not.toBeInTheDocument();
    expect(mocked.startInstall).not.toHaveBeenCalled();
  });

  it("ignores phase events from before the install was started", async () => {
    render(<InstallStep resume={null} onStarted={vi.fn()} onNext={vi.fn()} />);
    await waitFor(() => expect(bridge.listeners()).toBe(2));
    bridge.emitPhase({ phase: "failed", elapsed_s: 0, error: "old" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Install & start Crawler AI" })).toBeInTheDocument();
  });

  it("unsubscribes from events when it goes away", async () => {
    const { view } = await startInstall();
    expect(bridge.listeners()).toBe(2);
    view.unmount();
    expect(bridge.listeners()).toBe(0);
  });
});
