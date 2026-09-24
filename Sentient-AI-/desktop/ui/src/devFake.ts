/**
 * In-memory stand-in for the Rust commands and events, used only by `npm run dev` when the page
 * is opened in an ordinary browser instead of the Tauri window.
 *
 * Why it exists: Designers and reviewers can click through every screen (checks failing,
 * Docker starting, a streaming install, a failed install and Retry, the status screen) without
 * building the Rust app or touching Docker. Nothing here runs a process or reads a file. The
 * bridge only imports this module when `import.meta.env.DEV` is true, so it is not in release
 * builds. Scenario switches (query string): ?installed=1 ?keys=set ?docker=off|missing
 * ?ports=busy ?fail=1 ?platform=windows
 */

import type { InvokeArgs } from "@tauri-apps/api/core";
import type { AppInfo, PhaseEvent, PreflightReport, SaveKeysRequest, SaveKeysResult, UpdateInfo } from "./bridge";

type Handler = (payload: unknown) => void;

const params = new URLSearchParams(typeof location === "undefined" ? "" : location.search);

const state = {
  installed: params.get("installed") === "1",
  keysSet: params.get("keys") === "set" || params.get("installed") === "1",
  docker: (params.get("docker") ?? "on") as "on" | "off" | "missing" | "starting",
  portsBusy: params.get("ports") === "busy",
  failNext: params.get("fail") === "1",
  platform: params.get("platform") === "windows" ? ("windows" as const) : ("mac" as const),
  phase: { phase: params.get("installed") === "1" ? "healthy" : "idle", elapsed_s: 0 } as PhaseEvent,
  startedAt: 0,
  timers: [] as ReturnType<typeof setTimeout>[],
};

const listeners = new Map<string, Set<Handler>>();

function emit(event: string, payload: unknown) {
  listeners.get(event)?.forEach((handler) => handler(payload));
}

function setPhase(phase: string, error?: string) {
  const elapsed = state.startedAt ? Math.round((Date.now() - state.startedAt) / 1000) : 0;
  state.phase = { phase, elapsed_s: elapsed, ...(error ? { error } : {}) };
  emit("stack://phase", state.phase);
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function report(): PreflightReport {
  const installed = state.docker !== "missing";
  const running = state.docker === "on";
  const ports = [
    { port: 3000, service: "web app", free: !state.portsBusy, holder: state.portsBusy ? "node" : null },
    { port: 8000, service: "backend", free: true, holder: null },
    { port: 5432, service: "database", free: true, holder: null },
    { port: 6379, service: "Redis", free: true, holder: null },
  ];
  return {
    docker_installed: installed,
    docker_running: running,
    compose_v2: installed,
    compose_version: installed ? "2.39.2" : null,
    ports,
    disk_free_gb: 182.4,
    env_keys_set: state.keysSet,
    existing_stack: state.installed,
    stack_conflict: false,
    ready: installed && running,
    fixes: [],
  };
}

const SCRIPT: [string, string[]][] = [
  ["preparing", ["Copying Crawler AI 0.1.0 to the app folder…", "Writing docker-compose settings…"]],
  [
    "pulling",
    ["postgres Pulling", "redis Pulling", "postgres Pull complete", "redis Pull complete"],
  ],
  [
    "building",
    [
      "#1 [backend internal] load build definition from Dockerfile",
      "#2 [backend 1/6] FROM docker.io/library/python:3.12-slim",
      "#5 [backend 3/6] RUN pip install --no-cache-dir -r requirements.txt",
      "#8 [frontend 1/5] FROM docker.io/library/node:22-alpine",
      "#11 [frontend 4/5] RUN npm ci",
      "#12 [frontend 5/5] RUN npm run build",
      "#14 exporting to image",
    ],
  ],
  ["starting_containers", ["Container crawler-ai-postgres-1  Started", "Container crawler-ai-backend-1  Started"]],
  ["waiting_backend", ["Waiting for http://localhost:8000/health …"]],
  ["waiting_frontend", ["Waiting for http://localhost:3000 …"]],
];

function runInstall() {
  state.timers.forEach(clearTimeout);
  state.timers = [];
  state.startedAt = Date.now();
  const fail = state.failNext;
  state.failNext = false;
  let at = 0;
  const later = (ms: number, fn: () => void) => {
    at += ms;
    state.timers.push(setTimeout(fn, at));
  };
  later(50, () => setPhase("preparing"));
  for (const [phase, lines] of SCRIPT) {
    later(600, () => setPhase(phase));
    for (const line of lines) later(350, () => emit("stack://log", line));
    if (fail && phase === "building") {
      later(500, () => emit("stack://log", "ERROR: failed to solve: process \"npm ci\" did not complete successfully: exit code 1"));
      later(200, () =>
        setPhase("failed", "Docker Compose stopped while building the web app (exit code 1)."),
      );
      return;
    }
  }
  later(800, () => {
    state.installed = true;
    setPhase("healthy");
  });
}

export async function fakeListen<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
  const set = listeners.get(event) ?? new Set<Handler>();
  listeners.set(event, set);
  const wrapped: Handler = (payload) => handler(payload as T);
  set.add(wrapped);
  return () => {
    set.delete(wrapped);
  };
}

export async function fakeInvoke<T>(command: string, args?: InvokeArgs): Promise<T> {
  await sleep(command === "preflight" ? 900 : 300);
  const answer = (value: unknown) => value as T;
  switch (command) {
    case "app_info":
      return answer({ version: "0.1.0-preview", platform: state.platform, installed: state.installed } satisfies AppInfo);
    case "preflight":
      return answer(report());
    case "open_docker_desktop":
      if (state.docker === "off") {
        state.docker = "starting";
        setTimeout(() => {
          state.docker = "on";
        }, 7000);
      }
      return answer({ ok: state.docker !== "missing" });
    case "save_keys": {
      const request = (args ?? {}) as unknown as Partial<SaveKeysRequest>;
      if (state.keysSet && !request.overwrite) return answer({ ok: false, reason: "exists" } satisfies SaveKeysResult);
      state.keysSet = true;
      return answer({ ok: true } satisfies SaveKeysResult);
    }
    case "start_install":
      runInstall();
      return answer({ ok: true });
    case "install_status":
      return answer(state.phase);
    case "open_crawler":
      return answer(null);
    case "stack_start":
      emit("stack://log", "Container crawler-ai-backend-1  Started");
      setPhase("starting");
      setTimeout(() => setPhase("healthy"), 1500);
      return answer(null);
    case "stack_stop":
      emit("stack://log", "Container crawler-ai-backend-1  Stopped");
      setPhase("stopped");
      return answer(null);
    case "check_updates":
      return answer({ latest: "0.2.0", url: "https://github.com/", newer: true } satisfies UpdateInfo);
    default:
      throw new Error(`Unknown command in preview: ${command}`);
  }
}
