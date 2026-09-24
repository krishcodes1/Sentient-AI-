/**
 * The only place the setup window talks to the Rust side of the desktop app: typed wrappers
 * around Tauri's `invoke` (commands) and `listen` (events).
 *
 * Why it exists: The setup/status window is the one webview allowed to call app commands, so
 * every command name and payload shape lives in this file and mirrors
 * src-tauri/src/commands.rs exactly. Components import these functions, never
 * `@tauri-apps/api` directly, and the tests swap this whole module out with `vi.mock`, so no
 * test needs a Rust process. In `npm run dev` outside Tauri (a plain browser tab) the calls go
 * to src/devFake.ts instead, so the screens can be previewed without the app; that branch is
 * compiled out of production builds.
 */

import { invoke, isTauri, type InvokeArgs } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ── Payloads (keep in sync with src-tauri/src/commands.rs) ──────────────────

export type Platform = "mac" | "windows";
export type Severity = "error" | "warning" | "info";

/** One suggested fix from the preflight, grouped in the UI by `id`. */
export interface Fix {
  id: string;
  severity: Severity;
  text: string;
  /** Optional https link (a download page, a help article). */
  url?: string | null;
  /** Same, in the browser installer's shape; either form is accepted. */
  link?: { href: string; label?: string | null } | null;
}

export interface PortCheck {
  port: number;
  service: string;
  free: boolean;
  /** Who listens on the port when it isn't free (process name), if the OS told us. */
  holder?: string | null;
  /** Optional: held by this Crawler AI's own running stack, which is fine. */
  ours?: boolean;
}

export interface PreflightReport {
  docker_installed: boolean;
  docker_running: boolean;
  compose_v2: boolean;
  compose_version?: string | null;
  ports: PortCheck[];
  /** Free disk space in GB; negative when it couldn't be measured. */
  disk_free_gb: number;
  env_keys_set: boolean;
  existing_stack: boolean;
  /** Truthy when a different Crawler AI stack already uses the `crawler-ai` Compose project. */
  stack_conflict: boolean | Record<string, unknown> | null;
  /** Docker is running and Compose v2 is present: the install can start. */
  ready: boolean;
  fixes: Fix[];
}

export type KeyMode = "generate" | "custom";

export interface SaveKeysRequest {
  mode: KeyMode;
  secret_key?: string;
  encryption_key?: string;
  overwrite?: boolean;
}

export interface SaveKeysResult {
  ok: boolean;
  /** "exists" asks the UI to confirm an overwrite; anything else is a failure. */
  reason?: string | null;
  /** Optional, with reason "invalid": per-field messages keyed secret_key / encryption_key / mode. */
  errors?: Record<string, string> | null;
}

/** Payload of `install_status()` and of the `stack://phase` event. */
export interface PhaseEvent {
  phase: string;
  elapsed_s: number;
  error?: string | null;
}

export interface AppInfo {
  version: string;
  platform: Platform;
  installed: boolean;
}

export interface UpdateInfo {
  latest?: string | null;
  url: string;
  newer: boolean;
}

export interface OkResult {
  ok: boolean;
}

// ── Transport ────────────────────────────────────────────────────────────────

const LOG_EVENT = "stack://log";
const PHASE_EVENT = "stack://phase";
const SHOW_LOGS_EVENT = "tray://show-logs";

/**
 * `vite` dev server opened in an ordinary browser: no Tauri runtime to talk to, so use the
 * in-memory fake. `import.meta.env.DEV` is the literal `false` in a production build, so the
 * bundler drops this branch and the fake module entirely.
 */
const FAKE = import.meta.env.DEV && import.meta.env.MODE !== "test" && !isTauri();

async function call<T>(command: string, args?: InvokeArgs): Promise<T> {
  if (FAKE) {
    const fake = await import("./devFake");
    return fake.fakeInvoke<T>(command, args);
  }
  return invoke<T>(command, args);
}

async function subscribe<T>(event: string, handler: (payload: T) => void): Promise<UnlistenFn> {
  if (FAKE) {
    const fake = await import("./devFake");
    return fake.fakeListen<T>(event, handler);
  }
  return listen<T>(event, (e) => handler(e.payload));
}

/** True when the screens are running against the browser preview fake, not the real app. */
export function isPreview(): boolean {
  return FAKE;
}

// ── Commands ─────────────────────────────────────────────────────────────────

/** Docker / Compose / ports / disk / keys checks for step 1. Read-only. */
export function preflight(): Promise<PreflightReport> {
  return call<PreflightReport>("preflight");
}

/** Ask the OS to launch Docker Desktop. Resolves false when it couldn't be opened. */
export async function openDockerDesktop(): Promise<boolean> {
  const result = await call<unknown>("open_docker_desktop");
  if (result === false) return false;
  if (result && typeof result === "object" && (result as Partial<OkResult>).ok === false) return false;
  return true;
}

/**
 * Generate or store SECRET_KEY / ENCRYPTION_KEY. The keys travel once, to Rust, and are never
 * read back. The fields are the command's own arguments, snake_case
 * (`#[tauri::command(rename_all = "snake_case")] fn save_keys(mode, secret_key, encryption_key,
 * overwrite)`); optional fields that aren't set are not sent.
 */
export function saveKeys(request: SaveKeysRequest): Promise<SaveKeysResult> {
  const args: Record<string, unknown> = { mode: request.mode };
  if (request.secret_key !== undefined) args.secret_key = request.secret_key;
  if (request.encryption_key !== undefined) args.encryption_key = request.encryption_key;
  if (request.overwrite !== undefined) args.overwrite = request.overwrite;
  return call<SaveKeysResult>("save_keys", args);
}

/** Start (or resume) extracting the bundled source and `docker compose up`. */
export async function startInstall(): Promise<OkResult> {
  // `{ ok }` per the contract; `{ started }` is accepted too.
  const result = await call<{ ok?: boolean; started?: boolean } | null>("start_install");
  return { ok: Boolean(result?.ok ?? result?.started) };
}

/** Current install phase; lets a reopened window pick up a running install. */
export function installStatus(): Promise<PhaseEvent> {
  return call<PhaseEvent>("install_status");
}

/** Open (or focus) the Crawler AI window, which loads the web app with no IPC access. */
export async function openCrawler(): Promise<void> {
  await call<unknown>("open_crawler");
}

export async function stackStart(): Promise<void> {
  await call<unknown>("stack_start");
}

export async function stackStop(): Promise<void> {
  await call<unknown>("stack_stop");
}

export function appInfo(): Promise<AppInfo> {
  return call<AppInfo>("app_info");
}

/** Compare the running version with the latest GitHub Release. */
export function checkUpdates(): Promise<UpdateInfo> {
  return call<UpdateInfo>("check_updates");
}

// ── Events ───────────────────────────────────────────────────────────────────

/** One line of Docker / install output per event: a string (`{ line }` is accepted too). */
export function onStackLog(handler: (line: string) => void): Promise<UnlistenFn> {
  return subscribe<unknown>(LOG_EVENT, (payload) => {
    if (typeof payload === "string") {
      handler(payload);
    } else if (payload && typeof payload === "object" && typeof (payload as { line?: unknown }).line === "string") {
      handler((payload as { line: string }).line);
    } else {
      handler(String(payload ?? ""));
    }
  });
}

/** Install / stack phase changes. */
export function onStackPhase(handler: (event: PhaseEvent) => void): Promise<UnlistenFn> {
  return subscribe<PhaseEvent>(PHASE_EVENT, (payload) => {
    if (payload && typeof payload === "object") handler(payload);
  });
}

/** The tray / menu-bar "Show logs" item: open the logs panel. No payload. */
export function onShowLogs(handler: (payload: unknown) => void): Promise<UnlistenFn> {
  return subscribe<unknown>(SHOW_LOGS_EVENT, handler);
}

export type { UnlistenFn };
