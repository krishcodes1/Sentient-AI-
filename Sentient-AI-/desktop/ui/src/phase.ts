/**
 * What an install / stack phase string means to the UI: still working, running, stopped or
 * failed, and the sentence shown next to the spinner.
 *
 * Why it exists: Rust reports phases as short snake_case strings (`install_status()` and the
 * `stack://phase` event). The UI must not break when a new phase name appears, so everything it
 * doesn't know is "working" with a neutral label, and only a few names end the progress view.
 */

import type { PhaseEvent } from "./bridge";

export type PhaseKind = "idle" | "working" | "healthy" | "stopped" | "failed";

const IDLE = new Set(["", "idle", "not_started", "none"]);
const HEALTHY = new Set(["healthy", "running", "ready", "done", "complete", "completed"]);
const STOPPED = new Set(["stopped", "exited"]);
const FAILED = new Set(["failed", "error"]);

const LABELS: Record<string, string> = {
  preparing: "Preparing Crawler AI’s files…",
  extracting: "Preparing Crawler AI’s files…",
  copying: "Preparing Crawler AI’s files…",
  pulling: "Downloading images…",
  downloading: "Downloading images…",
  building: "Building images…",
  starting: "Starting…",
  starting_containers: "Starting…",
  waiting_backend: "Waiting for the backend…",
  waiting_frontend: "Waiting for the web app…",
  waiting: "Waiting for Crawler AI to answer…",
  stopping: "Stopping…",
};

function normalise(phase: string | null | undefined): string {
  return String(phase ?? "").trim().toLowerCase();
}

export function classifyPhase(event: PhaseEvent | null | undefined): PhaseKind {
  if (!event) return "idle";
  const phase = normalise(event.phase);
  if (FAILED.has(phase) || (typeof event.error === "string" && event.error.trim())) return "failed";
  if (HEALTHY.has(phase)) return "healthy";
  if (STOPPED.has(phase)) return "stopped";
  if (IDLE.has(phase)) return "idle";
  return "working";
}

/** Sentence for the progress line of step 3. */
export function phaseLabel(event: PhaseEvent | null | undefined): string {
  switch (classifyPhase(event)) {
    case "healthy":
      return "Crawler AI is running ✓";
    case "failed":
      return "The install stopped";
    case "stopped":
      return "Crawler AI is stopped";
    case "idle":
      return "Getting ready…";
    default:
      return LABELS[normalise(event?.phase)] ?? "Working…";
  }
}
