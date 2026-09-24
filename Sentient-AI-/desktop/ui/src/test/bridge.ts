/**
 * Test double for src/bridge.ts: sensible default answers for every command, and helpers to
 * push `stack://log` / `stack://phase` events into mounted components.
 *
 * Why it exists: Component tests must never need Rust, Docker or Tauri. Each test file calls
 * `vi.mock("<path>/bridge")` (automock), then `installBridge()` in `beforeEach` to give every
 * mocked command a realistic default; a test overrides only what it is about.
 */

import { act } from "@testing-library/react";
import { vi } from "vitest";
import * as bridge from "../bridge";
import type { AppInfo, PhaseEvent, PreflightReport } from "../bridge";

export const mocked = vi.mocked(bridge);

export function readyReport(overrides: Partial<PreflightReport> = {}): PreflightReport {
  return {
    docker_installed: true,
    docker_running: true,
    compose_v2: true,
    compose_version: "2.39.2",
    ports: [
      { port: 3000, service: "web app", free: true, holder: null },
      { port: 8000, service: "backend", free: true, holder: null },
      { port: 5432, service: "database", free: true, holder: null },
      { port: 6379, service: "Redis", free: true, holder: null },
    ],
    disk_free_gb: 120,
    env_keys_set: false,
    existing_stack: false,
    stack_conflict: false,
    ready: true,
    fixes: [],
    ...overrides,
  };
}

export interface BridgeHarness {
  emitLog: (line: string) => void;
  emitPhase: (event: PhaseEvent) => void;
  /** The tray's "Show logs". */
  emitShowLogs: () => void;
  /** Number of live subscriptions (to prove components unsubscribe). */
  listeners: () => number;
}

export function installBridge(options: { appInfo?: Partial<AppInfo> } = {}): BridgeHarness {
  vi.resetAllMocks();
  const logHandlers = new Set<(line: string) => void>();
  const phaseHandlers = new Set<(event: PhaseEvent) => void>();
  const showLogsHandlers = new Set<(payload: unknown) => void>();

  mocked.isPreview.mockReturnValue(false);
  mocked.appInfo.mockResolvedValue({ version: "0.1.0", platform: "mac", installed: false, ...options.appInfo });
  mocked.preflight.mockResolvedValue(readyReport());
  mocked.openDockerDesktop.mockResolvedValue(true);
  mocked.saveKeys.mockResolvedValue({ ok: true });
  mocked.startInstall.mockResolvedValue({ ok: true });
  mocked.installStatus.mockResolvedValue({ phase: "idle", elapsed_s: 0 });
  mocked.openCrawler.mockResolvedValue(undefined);
  mocked.stackStart.mockResolvedValue(undefined);
  mocked.stackStop.mockResolvedValue(undefined);
  mocked.checkUpdates.mockResolvedValue({ latest: "0.1.0", url: "https://github.com/", newer: false });
  mocked.onStackLog.mockImplementation(async (handler) => {
    logHandlers.add(handler);
    return () => {
      logHandlers.delete(handler);
    };
  });
  mocked.onStackPhase.mockImplementation(async (handler) => {
    phaseHandlers.add(handler);
    return () => {
      phaseHandlers.delete(handler);
    };
  });
  mocked.onShowLogs.mockImplementation(async (handler) => {
    showLogsHandlers.add(handler);
    return () => {
      showLogsHandlers.delete(handler);
    };
  });

  return {
    emitLog: (line) => act(() => logHandlers.forEach((handler) => handler(line))),
    emitPhase: (event) => act(() => phaseHandlers.forEach((handler) => handler(event))),
    emitShowLogs: () => act(() => showLogsHandlers.forEach((handler) => handler(null))),
    listeners: () => logHandlers.size + phaseHandlers.size,
  };
}
