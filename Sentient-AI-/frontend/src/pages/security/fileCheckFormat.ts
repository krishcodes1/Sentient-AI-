/**
 * fileCheckFormat: the words and badge tones Security ▸ File checks uses for one checked file:
 * the verdict label and its tone, where the file came from, "41 of 72", how long ago, the reason a
 * file was not checked, and the one status line each row shows.
 *
 * Why it exists: a VirusTotal answer is easy to overstate. "No detections" is not a guarantee, and
 * a lookup that did not run is not a pass. Keeping every sentence and tone in one pure module lets
 * one test prove that no verdict is ever drawn in a success colour and no text ever says "safe",
 * and keeps the tab component free of wording rules. Reason codes are turned into the backend's
 * sentences (S10 4.6), so a code is never shown to a person.
 */

import type { FileCheck, FileCheckSource, FileCheckState, FileVerdictName } from "@/types";

/** How often the tab reads the list again while a row is still waiting (S10 6.3: 10 s). */
export const FILE_CHECK_POLL_MS = 10_000;

/** Badge tones. There is deliberately no success tone: nothing here is ever shown as safe. */
export type FileCheckTone = "danger" | "warning" | "neutral";

export const FILE_VERDICTS: readonly FileVerdictName[] = ["malicious", "suspicious", "no_detections", "unknown"];

const VERDICT_LABELS: Record<FileVerdictName, string> = {
  malicious: "Flagged as malicious",
  suspicious: "Some detections",
  no_detections: "No detections",
  unknown: "Unknown to VirusTotal",
};

/** The badge text for one verdict ("Flagged as malicious", "Some detections", …). */
export function verdictLabel(verdict: FileVerdictName): string {
  return VERDICT_LABELS[verdict] ?? "Not checked";
}

/** Red for malicious, amber for some detections, neutral grey for everything else. */
export function verdictTone(verdict: FileVerdictName | null): FileCheckTone {
  if (verdict === "malicious") return "danger";
  if (verdict === "suspicious") return "warning";
  return "neutral";
}

const SOURCE_LABELS: Record<FileCheckSource, string> = {
  page: "This page",
  web: "Web chat",
  telegram: "Telegram",
  slack: "Slack",
  gmail: "Email (Gmail)",
  outlook: "Email (Outlook)",
  hash: "Fingerprint",
  scam: "Scam check",
};

/** Where the file came from, in words ("Telegram", "Email (Gmail)", …). */
export function sourceLabel(source: FileCheckSource | string): string {
  return SOURCE_LABELS[source as FileCheckSource] ?? "Crawler";
}

/** "41 of 72": how many security vendors flag the file, of how many answered. Null without a
 *  vendor count (an unknown file, or one not checked). */
export function countsLabel(flaggedBy: number | null, engines: number | null): string | null {
  if (engines === null || engines === undefined || !Number.isFinite(engines)) return null;
  return `${Math.max(0, flaggedBy ?? 0)} of ${engines}`;
}

// The backend's sentences for each reason code (S10 4.6, services/file_reputation/verdicts.py).
// The limit sentences leave the number out: the owner can change the limits, and the row does
// not carry the limit that applied.
const REASON_SENTENCES: Record<string, string> = {
  no_key: "no VirusTotal key is set (the owner can add one in Security → Service keys)",
  switched_off: "checking files with VirusTotal is turned off in Settings → Permissions",
  minute_limit: "VirusTotal's per-minute lookup limit was reached; Crawler will check it shortly",
  virustotal_limit: "VirusTotal asked Crawler to slow down; Crawler will check it shortly",
  daily_limit: "today's VirusTotal lookups are used up",
  automatic_limit: "today's automatic checks are used up (you can still check a file yourself)",
  user_limit: "your lookups for today are used up",
  key_rejected: "VirusTotal rejected the key (the owner can replace it in Security → Service keys)",
  service_error: "VirusTotal could not be reached",
  too_large: "it is larger than 25 MB, too large to fingerprint",
  empty: "the file is empty",
  analysis_timeout: "VirusTotal had not finished scanning after 15 minutes",
  not_built: "file checks are not set up in this version of Crawler yet",
};
const UNKNOWN_REASON = "VirusTotal could not be asked";
const CODE_SHAPE = /^[a-z][a-z0-9_]*$/;
const NOT_CHECKED_PREFIX = /^not checked( yet)?:\s*/i;

/** The sentence behind a not-checked or waiting row's `reason`: a known code becomes the
 *  backend's sentence, an unknown code a generic one (never the code itself), and a sentence the
 *  server already wrote is kept (without a leading "Not checked:" or a closing full stop). */
export function reasonText(reason: string | null | undefined): string | null {
  const text = (reason ?? "").trim();
  if (!text) return null;
  if (Object.prototype.hasOwnProperty.call(REASON_SENTENCES, text)) return REASON_SENTENCES[text];
  if (CODE_SHAPE.test(text)) return UNKNOWN_REASON;
  return text.replace(NOT_CHECKED_PREFIX, "").replace(/\.$/, "");
}

/** True while a row is still moving (a queued lookup, a card waiting, a scan running), so the
 *  tab keeps reading the list. */
export function isWaiting(state: FileCheckState): boolean {
  return state === "queued" || state === "upload_pending" || state === "analysing";
}

export interface RowStatus {
  /** The verdict badge, only for a checked row. */
  badge: { label: string; tone: FileCheckTone } | null;
  /** The words after the badge, or the whole line for a row that is not checked. */
  text: string;
}

/** What one row says about its file (S10 6.3 "row states"). */
export function rowStatus(check: FileCheck): RowStatus {
  switch (check.state) {
    case "queued": {
      const why = reasonText(check.reason);
      return { badge: null, text: why ? `Checking… (${why})` : "Checking…" };
    }
    case "upload_pending":
      return { badge: null, text: "Waiting for your approval" };
    case "analysing":
      return { badge: null, text: "Scanning on VirusTotal…" };
    case "not_checked": {
      // Without a reason, the server's summary is used only when it is itself a "Not checked: …"
      // sentence; a verdict sentence (which can end "…not a guarantee it is safe") never is.
      const fromSummary = NOT_CHECKED_PREFIX.test(check.summary ?? "") ? reasonText(check.summary) : null;
      const why = reasonText(check.reason) ?? fromSummary ?? UNKNOWN_REASON;
      return { badge: null, text: `Not checked: ${why}` };
    }
    case "checked":
    default:
      return checkedStatus(check);
  }
}

function checkedStatus(check: FileCheck): RowStatus {
  const verdict = check.verdict;
  if (!verdict || !(verdict in VERDICT_LABELS)) {
    // A checked row without a verdict should not happen; say nothing stronger than "not checked".
    return { badge: null, text: `Not checked: ${reasonText(check.reason) ?? UNKNOWN_REASON}` };
  }
  const badge = { label: verdictLabel(verdict), tone: verdictTone(verdict) };
  const counts = countsLabel(verdict === "no_detections" ? 0 : check.flagged_by, check.engines);
  const label = check.threat_label?.trim() || null;
  if (verdict === "unknown") {
    return { badge, text: "" };
  }
  if (verdict === "no_detections") {
    // VirusTotal's "nothing found" is not a clean bill of health; the line says so every time.
    return { badge, text: counts ? `${counts} (not a guarantee)` : "(not a guarantee)" };
  }
  return { badge, text: [counts, label].filter(Boolean).join(" · ") };
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** "just now", "2 min ago", "3 h ago", "yesterday", "4 days ago", else the date. */
export function timeAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const diff = Math.max(0, now - then);
  if (diff < MINUTE) return "just now";
  if (diff < HOUR) return `${Math.floor(diff / MINUTE)} min ago`;
  if (diff < DAY) return `${Math.floor(diff / HOUR)} h ago`;
  if (diff < 2 * DAY) return "yesterday";
  if (diff < 7 * DAY) return `${Math.floor(diff / DAY)} days ago`;
  return new Date(then).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

// Characters that reorder or hide text: bidi embeddings, overrides and isolates, and marks.
// "invoice‮txt.exe" would otherwise read as "invoiceexe.txt".
const HIDDEN_DIRECTION_CHARS = /[؜‎‏‪-‮⁦-⁩]/g;

/** A file name as the tab shows it: direction-changing characters are made visible as "�", so a
 *  name cannot pretend to end in another extension; an empty name reads "Unnamed file". */
export function displayName(name: string | null | undefined): string {
  const text = (name ?? "").replace(HIDDEN_DIRECTION_CHARS, "�").trim();
  return text || "Unnamed file";
}

/** Bytes as whole megabytes, rounded down ("20 MB"), for the size limits the tab names. */
export function megabytes(bytes: number): string {
  return `${Math.floor(bytes / (1024 * 1024))} MB`;
}
