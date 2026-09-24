/**
 * Contract test for src/bridge.ts: each wrapper calls the exact Rust command / event name with
 * the exact argument shape.
 *
 * Why it exists: A typo in a command name or argument key compiles fine and only fails inside
 * the packaged app. Pinning the names here makes a mismatch with src-tauri/src/commands.rs a
 * red test instead of a dead button.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
const listen = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
  isTauri: () => true,
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => listen(...args),
}));

import * as bridge from "./bridge";

beforeEach(() => {
  invoke.mockReset();
  listen.mockReset();
});

describe("bridge commands", () => {
  it.each([
    ["preflight", () => bridge.preflight()],
    ["open_docker_desktop", () => bridge.openDockerDesktop()],
    ["start_install", () => bridge.startInstall()],
    ["install_status", () => bridge.installStatus()],
    ["open_crawler", () => bridge.openCrawler()],
    ["stack_start", () => bridge.stackStart()],
    ["stack_stop", () => bridge.stackStop()],
    ["app_info", () => bridge.appInfo()],
    ["check_updates", () => bridge.checkUpdates()],
  ])("%s takes no arguments", async (command, run) => {
    invoke.mockResolvedValue({ ok: true });
    await run();
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith(command, undefined);
  });

  it("save_keys sends the fields as flat snake_case arguments", async () => {
    invoke.mockResolvedValue({ ok: true });
    await bridge.saveKeys({ mode: "custom", secret_key: "s".repeat(32), encryption_key: "e", overwrite: true });
    expect(invoke).toHaveBeenCalledWith("save_keys", {
      mode: "custom",
      secret_key: "s".repeat(32),
      encryption_key: "e",
      overwrite: true,
    });
  });

  it("save_keys in generate mode sends no key fields at all", async () => {
    invoke.mockResolvedValue({ ok: true });
    await bridge.saveKeys({ mode: "generate", overwrite: false });
    expect(invoke).toHaveBeenCalledWith("save_keys", { mode: "generate", overwrite: false });
  });

  it("start_install reads { ok } (and tolerates { started })", async () => {
    invoke.mockResolvedValueOnce({ ok: true });
    await expect(bridge.startInstall()).resolves.toEqual({ ok: true });
    invoke.mockResolvedValueOnce({ started: false, reason: "busy" });
    await expect(bridge.startInstall()).resolves.toEqual({ ok: false });
    invoke.mockResolvedValueOnce(null);
    await expect(bridge.startInstall()).resolves.toEqual({ ok: false });
  });

  it("open_docker_desktop reports failure from {ok:false} or false, success otherwise", async () => {
    invoke.mockResolvedValueOnce({ ok: false });
    await expect(bridge.openDockerDesktop()).resolves.toBe(false);
    invoke.mockResolvedValueOnce(false);
    await expect(bridge.openDockerDesktop()).resolves.toBe(false);
    invoke.mockResolvedValueOnce(null);
    await expect(bridge.openDockerDesktop()).resolves.toBe(true);
    invoke.mockResolvedValueOnce({ ok: true });
    await expect(bridge.openDockerDesktop()).resolves.toBe(true);
  });

  it("is not in preview mode inside Tauri", () => {
    expect(bridge.isPreview()).toBe(false);
  });
});

describe("bridge events", () => {
  it("stack://log hands each line to the handler", async () => {
    const unlisten = vi.fn();
    listen.mockResolvedValue(unlisten);
    const handler = vi.fn();
    const stop = await bridge.onStackLog(handler);
    expect(listen).toHaveBeenCalledWith("stack://log", expect.any(Function));
    const deliver = listen.mock.calls[0][1] as (e: { payload: unknown }) => void;
    deliver({ payload: "Container crawler-ai-backend-1  Started" });
    deliver({ payload: { line: "from an object payload" } });
    deliver({ payload: 42 });
    expect(handler).toHaveBeenNthCalledWith(1, "Container crawler-ai-backend-1  Started");
    expect(handler).toHaveBeenNthCalledWith(2, "from an object payload");
    expect(handler).toHaveBeenNthCalledWith(3, "42");
    stop();
    expect(unlisten).toHaveBeenCalled();
  });

  it("stack://phase hands the payload object to the handler", async () => {
    listen.mockResolvedValue(vi.fn());
    const handler = vi.fn();
    await bridge.onStackPhase(handler);
    expect(listen).toHaveBeenCalledWith("stack://phase", expect.any(Function));
    const deliver = listen.mock.calls[0][1] as (e: { payload: unknown }) => void;
    deliver({ payload: { phase: "building", elapsed_s: 12 } });
    deliver({ payload: null });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith({ phase: "building", elapsed_s: 12 });
  });
});
