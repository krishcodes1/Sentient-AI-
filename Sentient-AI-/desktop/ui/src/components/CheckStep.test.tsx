/**
 * Step 1 tests: Continue stays disabled until the preflight says ready, Re-check re-runs it,
 * Open Docker Desktop calls the bridge, and the wording follows the OS.
 *
 * Why it exists: Letting someone continue with Docker stopped guarantees a failed install ten
 * minutes later; this gate is the step's whole job.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { installBridge, mocked, readyReport } from "../test/bridge";
import { CheckStep } from "./CheckStep";

vi.mock("../bridge");

beforeEach(() => {
  installBridge();
});

describe("CheckStep", () => {
  it("keeps Continue disabled until the computer is ready, then enables it after Re-check", async () => {
    const user = userEvent.setup();
    mocked.preflight.mockResolvedValueOnce(readyReport({ docker_running: false, ready: false }));
    const onContinue = vi.fn();
    render(<CheckStep platform="mac" onContinue={onContinue} />);

    expect(screen.getByText("Checking your Mac…")).toBeInTheDocument();
    expect(await screen.findByText("Fix the red items above, then click Re-check.")).toBeInTheDocument();
    const cont = screen.getByRole("button", { name: "Continue" });
    expect(cont).toBeDisabled();
    await user.click(cont);
    expect(onContinue).not.toHaveBeenCalled();

    mocked.preflight.mockResolvedValueOnce(readyReport());
    await user.click(screen.getByRole("button", { name: "Re-check" }));
    expect(await screen.findByText("Everything looks good.")).toBeInTheDocument();
    expect(mocked.preflight).toHaveBeenCalledTimes(2);

    const enabled = screen.getByRole("button", { name: "Continue" });
    expect(enabled).toBeEnabled();
    await user.click(enabled);
    expect(onContinue).toHaveBeenCalledWith(expect.objectContaining({ ready: true }));
  });

  it("offers to skip to Install when keys are already set", async () => {
    mocked.preflight.mockResolvedValueOnce(readyReport({ env_keys_set: true }));
    render(<CheckStep platform="mac" onContinue={vi.fn()} />);
    expect(await screen.findByRole("button", { name: "Continue to Install" })).toBeEnabled();
  });

  it("shows a retryable error when the check itself fails", async () => {
    mocked.preflight.mockRejectedValueOnce("docker hung");
    render(<CheckStep platform="mac" onContinue={vi.fn()} />);
    expect(await screen.findByText("The check didn’t finish. Click Re-check to try again.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Re-check" })).toBeEnabled();
  });

  it("opens Docker Desktop through the bridge and then waits for it", async () => {
    const user = userEvent.setup();
    mocked.preflight.mockResolvedValue(readyReport({ docker_running: false, ready: false }));
    render(<CheckStep platform="mac" onContinue={vi.fn()} />);
    await user.click(await screen.findByRole("button", { name: "Open Docker Desktop" }));
    expect(mocked.openDockerDesktop).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("button", { name: "Waiting for Docker…" })).toBeDisabled();
  });

  it("tells people to open Docker themselves when the app couldn't", async () => {
    const user = userEvent.setup();
    mocked.preflight.mockResolvedValue(readyReport({ docker_running: false, ready: false }));
    mocked.openDockerDesktop.mockResolvedValue(false);
    render(<CheckStep platform="windows" onContinue={vi.fn()} />);
    await user.click(await screen.findByRole("button", { name: "Open Docker Desktop" }));
    expect(await screen.findByText(/Open it from the Start menu, then click Re-check/)).toBeInTheDocument();
  });

  it("uses Mac wording on macOS and adds the WSL 2 note on Windows", async () => {
    const { unmount } = render(<CheckStep platform="mac" onContinue={vi.fn()} />);
    expect(screen.getByRole("link", { name: "Docker Desktop for Mac" })).toHaveAttribute(
      "href",
      "https://www.docker.com/products/docker-desktop/",
    );
    expect(screen.queryByText(/WSL 2/)).not.toBeInTheDocument();
    await screen.findByText("Everything looks good.");
    unmount();

    render(<CheckStep platform="windows" onContinue={vi.fn()} />);
    expect(screen.getByRole("link", { name: "Docker Desktop for Windows" })).toBeInTheDocument();
    expect(screen.getByText(/Docker Desktop needs WSL 2/)).toBeInTheDocument();
    expect(screen.getByText("Checking your PC…")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Everything looks good.")).toBeInTheDocument());
  });

  it("renders Rust's fix text and only https links", async () => {
    mocked.preflight.mockResolvedValueOnce(
      readyReport({
        docker_installed: false,
        docker_running: false,
        compose_v2: false,
        ready: false,
        fixes: [
          { id: "docker_installed", severity: "error", text: "Install it from docker.com.", url: "https://www.docker.com/" },
          { id: "ports", severity: "warning", text: "Something odd.", url: "javascript:alert(1)" },
        ],
      }),
    );
    render(<CheckStep platform="mac" onContinue={vi.fn()} />);
    expect(await screen.findByText(/Install it from docker.com./)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download Docker Desktop" })).toHaveAttribute("href", "https://www.docker.com/");
    expect(screen.queryByText("Learn more")).not.toBeInTheDocument();
  });

  it("accepts the installer's { link: { href, label } } fix shape too", async () => {
    mocked.preflight.mockResolvedValueOnce(
      readyReport({
        compose_v2: false,
        ready: false,
        fixes: [
          {
            id: "compose_v2",
            severity: "error",
            text: "Compose is missing.",
            link: { href: "https://docs.docker.com/compose/", label: "Compose docs" },
          },
        ],
      }),
    );
    render(<CheckStep platform="mac" onContinue={vi.fn()} />);
    expect(await screen.findByRole("link", { name: "Compose docs" })).toHaveAttribute(
      "href",
      "https://docs.docker.com/compose/",
    );
  });
});
