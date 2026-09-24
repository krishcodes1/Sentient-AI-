/**
 * Turns a preflight report into the rows of step 1 ("Check this computer"): what passed, what
 * needs fixing, and the fix text for each, plus the note under the list.
 *
 * Why it exists: The rules (which state each row is in, what counts as a warning, what to say
 * when Rust sent no fix text) are the heart of step 1 and are easier to get right, and to test,
 * as a pure function than inside the component. Wording follows installer/page.html.
 */

import type { Fix, PreflightReport } from "./bridge";
import { formatGb } from "./format";
import { DOCKER_DESKTOP_URL, type PlatformWords } from "./platform";

export type CheckState = "ok" | "bad" | "warn" | "info" | "skip" | "pending";

export interface CheckRow {
  id: string;
  state: CheckState;
  title: string;
  detail: string;
  fixes: Fix[];
  /** Show the "Open Docker Desktop" button on this row. */
  openDocker?: boolean;
}

/** Below this much free space the first build (≈3.6 GB of downloads) is at risk. */
export const MIN_FREE_GB = 10;

const KNOWN_FIXES = new Set([
  "docker_installed",
  "docker_running",
  "compose_v2",
  "ports",
  "disk",
  "env",
  "existing_stack",
  "stack_conflict",
]);

function groupFixes(fixes: Fix[] | null | undefined): Record<string, Fix[]> {
  const out: Record<string, Fix[]> = {};
  for (const fix of fixes ?? []) {
    if (!fix || typeof fix.text !== "string") continue;
    (out[fix.id] ??= []).push(fix);
  }
  return out;
}

function withDefault(given: Fix[] | undefined, fallback: Fix): Fix[] {
  return given && given.length ? given : [fallback];
}

/** "3000, 8000, 5432 and 6379" */
function listPorts(ports: number[]): string {
  if (ports.length <= 1) return ports.join("");
  return `${ports.slice(0, -1).join(", ")} and ${ports[ports.length - 1]}`;
}

export function buildRows(report: PreflightReport, words: PlatformWords): CheckRow[] {
  const fixes = groupFixes(report.fixes);
  const rows: CheckRow[] = [];
  const installed = !!report.docker_installed;
  const running = installed && !!report.docker_running;

  rows.push({
    id: "docker_installed",
    state: installed ? "ok" : "bad",
    title: "Docker Desktop installed",
    detail: installed ? "Installed." : "",
    fixes: installed
      ? fixes.docker_installed ?? []
      : withDefault(fixes.docker_installed, {
          id: "docker_installed",
          severity: "error",
          text: `Install ${words.docker} (free for personal use), open it once, then click Re-check.`,
          url: DOCKER_DESKTOP_URL,
        }),
  });

  rows.push({
    id: "docker_running",
    state: !installed ? "skip" : running ? "ok" : "bad",
    title: "Docker is running",
    detail: !installed
      ? "Checked once Docker Desktop is installed."
      : running
        ? "The Docker engine is answering."
        : "",
    fixes:
      installed && !running
        ? withDefault(fixes.docker_running, {
            id: "docker_running",
            severity: "error",
            text: "Open Docker Desktop and wait until it says it’s running, then click Re-check.",
          })
        : fixes.docker_running ?? [],
    openDocker: installed && !running,
  });

  const compose = !!report.compose_v2;
  rows.push({
    id: "compose_v2",
    state: !installed ? "skip" : compose ? "ok" : "bad",
    title: "Docker Compose (v2 or newer)",
    detail: !installed
      ? "Comes with Docker Desktop."
      : compose
        ? `Version ${report.compose_version || "2"}.`
        : "",
    fixes:
      installed && !compose
        ? withDefault(fixes.compose_v2, {
            id: "compose_v2",
            severity: "error",
            text: "Docker Compose (v2 or newer) is missing. Update Docker Desktop to the latest version (it checks for updates in its Settings), then click Re-check.",
            url: DOCKER_DESKTOP_URL,
          })
        : fixes.compose_v2 ?? [],
  });

  const ports = Array.isArray(report.ports) ? report.ports : [];
  const busy = ports.filter((p) => !p.free && !p.ours);
  const ours = ports.filter((p) => !p.free && p.ours);
  let portState: CheckState = "ok";
  let portDetail = ours.length ? "In use by your running Crawler AI, which is fine." : "All free.";
  let portFixes = fixes.ports ?? [];
  if (!ports.length) {
    portState = "info";
    portDetail = "Couldn’t check the ports.";
  } else if (busy.length && report.existing_stack) {
    // Most likely the Crawler AI that's already set up here; installing again reuses it.
    portState = "info";
    portDetail = "In use, most likely by the Crawler AI that’s already set up here. That’s fine.";
  } else if (busy.length) {
    portState = "warn";
    portDetail = "";
    if (!portFixes.length) {
      portFixes = busy.map((p) => ({
        id: "ports",
        severity: "warning",
        text: `Port ${p.port} (${p.service}) is in use by ${p.holder || "another app"}. Quit it before installing, or Crawler AI’s ${p.service} can’t start.`,
      }));
    }
  }
  rows.push({
    id: "ports",
    state: portState,
    title: ports.length ? `Ports ${listPorts(ports.map((p) => p.port))}` : "Ports",
    detail: portDetail,
    fixes: portFixes,
  });

  const gb = typeof report.disk_free_gb === "number" && Number.isFinite(report.disk_free_gb) ? report.disk_free_gb : -1;
  rows.push({
    id: "disk",
    state: gb < 0 ? "info" : gb >= MIN_FREE_GB ? "ok" : "warn",
    title: "Disk space",
    detail: gb < 0 ? "Couldn’t measure free space." : `${formatGb(gb)} GB free.`,
    fixes:
      gb >= 0 && gb < MIN_FREE_GB
        ? withDefault(fixes.disk, {
            id: "disk",
            severity: "warning",
            text: `The first install downloads about 3.6 GB and needs roughly ${MIN_FREE_GB} GB of room; free some space first.`,
          })
        : fixes.disk ?? [],
  });

  rows.push({
    id: "env",
    state: report.env_keys_set ? "ok" : "info",
    title: "Security keys",
    detail: report.env_keys_set ? "Already set — you can skip to Install." : "",
    fixes: report.env_keys_set
      ? []
      : withDefault(fixes.env, {
          id: "env",
          severity: "info",
          text: "Not created yet. The next step does it for you.",
        }),
  });

  if (report.existing_stack) {
    rows.push({
      id: "existing_stack",
      state: "info",
      title: "Existing install",
      detail: "",
      fixes: withDefault(fixes.existing_stack, {
        id: "existing_stack",
        severity: "info",
        text: "Crawler AI is already set up on this computer. Install & start updates it; your data is kept.",
      }),
    });
  }

  if (report.stack_conflict) {
    rows.push({
      id: "stack_conflict",
      state: "warn",
      title: "Another copy of Crawler AI",
      detail: "",
      fixes: withDefault(fixes.stack_conflict, {
        id: "stack_conflict",
        severity: "warning",
        text: "Another copy of Crawler AI is set up in Docker. Installing here would replace its containers. Stop it in Docker Desktop first.",
      }),
    });
  }

  // Fix ids this UI doesn't know yet still get shown, so new Rust checks aren't silent.
  for (const [id, list] of Object.entries(fixes)) {
    if (KNOWN_FIXES.has(id)) continue;
    const worst = list.some((f) => f.severity === "error")
      ? "bad"
      : list.some((f) => f.severity === "warning")
        ? "warn"
        : "info";
    rows.push({
      id,
      state: worst,
      title: worst === "bad" ? "Needs attention" : worst === "warn" ? "Warning" : "Note",
      detail: "",
      fixes: list,
    });
  }

  return rows;
}

export interface CheckNote {
  tone: "ok" | "bad" | "info";
  text: string;
}

/** The sentence under the list, telling people whether they can go on. */
export function checkNote(report: PreflightReport, rows: CheckRow[]): CheckNote {
  if (!report.ready) return { tone: "bad", text: "Fix the red items above, then click Re-check." };
  // Warnings outrank "keys already set": the keys row says that itself.
  if (rows.some((row) => row.state === "warn")) {
    return {
      tone: "info",
      text: "Docker is ready. The warnings above won’t stop you, but the install can fail until they’re sorted.",
    };
  }
  return { tone: "ok", text: "Everything looks good." };
}
