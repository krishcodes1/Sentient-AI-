/**
 * Tests for fileCheckFormat (Security ▸ File checks wording): every verdict has a label and a tone
 * that is never a success tone, sources and counts read as the spec shows them, reason codes become
 * sentences (never the code), each row state has its line, and no line ever says "safe".
 *
 * Why it exists: VirusTotal finding nothing is not a guarantee, and a lookup that did not run is not
 * a pass. These rules are the whole point of the tab's wording, so they are pinned here once.
 */

import { describe, expect, it } from "vitest";
import {
  FILE_CHECK_POLL_MS,
  FILE_VERDICTS,
  countsLabel,
  displayName,
  isWaiting,
  megabytes,
  reasonText,
  rowStatus,
  sourceLabel,
  timeAgo,
  verdictLabel,
  verdictTone,
} from "@/pages/security/fileCheckFormat";
import type { FileCheck, FileCheckSource, FileCheckState } from "@/types";

function check(overrides: Partial<FileCheck>): FileCheck {
  return {
    id: "c1",
    sha256: "a".repeat(64),
    name: "report.docm",
    source: "web",
    size_bytes: 1024,
    state: "checked",
    verdict: "no_detections",
    flagged_by: 0,
    engines: 68,
    threat_label: null,
    summary: "",
    reason: null,
    can_upload: false,
    upload_needs_file: false,
    action_id: null,
    checked_at: "2026-10-14T10:00:00Z",
    updated_at: "2026-10-14T10:00:00Z",
    ...overrides,
  };
}

const ALL_STATES: FileCheckState[] = ["queued", "checked", "not_checked", "upload_pending", "analysing"];

describe("verdicts", () => {
  it("every verdict has a label and no verdict uses a success tone", () => {
    expect(FILE_VERDICTS).toEqual(["malicious", "suspicious", "no_detections", "unknown"]);
    for (const verdict of FILE_VERDICTS) {
      expect(verdictLabel(verdict)).toMatch(/\S/);
      expect(["danger", "warning", "neutral"]).toContain(verdictTone(verdict));
      expect(verdictLabel(verdict)).not.toMatch(/safe|clean/i);
    }
    expect(verdictTone(null)).toBe("neutral");
  });

  it("labels and tones follow the spec: red malicious, amber some detections, grey otherwise", () => {
    expect(FILE_VERDICTS.map((v) => [verdictLabel(v), verdictTone(v)])).toEqual([
      ["Flagged as malicious", "danger"],
      ["Some detections", "warning"],
      ["No detections", "neutral"],
      ["Unknown to VirusTotal", "neutral"],
    ]);
  });
});

describe("sourceLabel and countsLabel", () => {
  it("names every source in words", () => {
    const sources: FileCheckSource[] = ["page", "web", "telegram", "slack", "gmail", "outlook", "hash", "scam"];
    expect(sources.map(sourceLabel)).toEqual([
      "This page",
      "Web chat",
      "Telegram",
      "Slack",
      "Email (Gmail)",
      "Email (Outlook)",
      "Fingerprint",
      "Scam check",
    ]);
    expect(sourceLabel("something_new")).toBe("Crawler");
  });

  it("reads counts as 41 of 72, and has none without a vendor count", () => {
    expect(countsLabel(41, 72)).toBe("41 of 72");
    expect(countsLabel(null, 68)).toBe("0 of 68");
    expect(countsLabel(3, null)).toBeNull();
  });
});

describe("reasonText", () => {
  it("turns each reason code into the backend's sentence and never shows a code", () => {
    expect(reasonText("daily_limit")).toBe("today's VirusTotal lookups are used up");
    expect(reasonText("too_large")).toBe("it is larger than 25 MB, too large to fingerprint");
    expect(reasonText("no_key")).toBe("no VirusTotal key is set (the owner can add one in Security → Service keys)");
    expect(reasonText("some_future_code")).toBe("VirusTotal could not be asked");
    expect(reasonText("constructor")).toBe("VirusTotal could not be asked");
  });

  it("keeps a sentence the server already wrote, without a repeated Not checked prefix", () => {
    expect(reasonText("Not checked: today's 500 VirusTotal lookups are used up.")).toBe(
      "today's 500 VirusTotal lookups are used up",
    );
    expect(reasonText("VirusTotal's per-minute limit")).toBe("VirusTotal's per-minute limit");
    expect(reasonText(null)).toBeNull();
    expect(reasonText("   ")).toBeNull();
  });
});

describe("rowStatus", () => {
  it("gives each row state its line", () => {
    expect(rowStatus(check({ state: "queued", verdict: null, reason: "minute_limit" })).text).toBe(
      "Checking… (VirusTotal's per-minute lookup limit was reached; Crawler will check it shortly)",
    );
    expect(rowStatus(check({ state: "queued", verdict: null })).text).toBe("Checking…");
    expect(rowStatus(check({ state: "not_checked", verdict: null, reason: "too_large" })).text).toBe(
      "Not checked: it is larger than 25 MB, too large to fingerprint",
    );
    expect(rowStatus(check({ state: "upload_pending", verdict: "unknown" })).text).toBe("Waiting for your approval");
    expect(rowStatus(check({ state: "analysing", verdict: "unknown" })).text).toBe("Scanning on VirusTotal…");
  });

  it("a not-checked row without a reason falls back to the server's summary, then a generic sentence", () => {
    expect(
      rowStatus(check({ state: "not_checked", verdict: null, summary: "Not checked: the file is empty." })).text,
    ).toBe("Not checked: the file is empty");
    expect(rowStatus(check({ state: "not_checked", verdict: null, summary: "" })).text).toBe(
      "Not checked: VirusTotal could not be asked",
    );
  });

  it("a checked row shows the verdict badge, the counts and the threat label", () => {
    expect(
      rowStatus(check({ verdict: "malicious", flagged_by: 41, engines: 72, threat_label: "trojan.emotet" })),
    ).toEqual({ badge: { label: "Flagged as malicious", tone: "danger" }, text: "41 of 72 · trojan.emotet" });
    expect(rowStatus(check({ verdict: "suspicious", flagged_by: 2, engines: 70 }))).toEqual({
      badge: { label: "Some detections", tone: "warning" },
      text: "2 of 70",
    });
    expect(rowStatus(check({ verdict: "no_detections", flagged_by: null, engines: 68 }))).toEqual({
      badge: { label: "No detections", tone: "neutral" },
      text: "0 of 68 (not a guarantee)",
    });
    expect(rowStatus(check({ verdict: "unknown", flagged_by: null, engines: null }))).toEqual({
      badge: { label: "Unknown to VirusTotal", tone: "neutral" },
      text: "",
    });
  });

  it("a checked row without a verdict claims nothing", () => {
    expect(rowStatus(check({ verdict: null }))).toEqual({
      badge: null,
      text: "Not checked: VirusTotal could not be asked",
    });
  });

  it("no row line in any state or verdict says safe", () => {
    for (const state of ALL_STATES) {
      for (const verdict of [...FILE_VERDICTS, null]) {
        const status = rowStatus(
          check({
            state,
            verdict,
            // A server summary that says "safe" must never be copied onto a checked row.
            summary: "VirusTotal: none of 68 security vendors flag this file. That is not a guarantee it is safe.",
          }),
        );
        expect(`${status.badge?.label ?? ""} ${status.text}`).not.toMatch(/\bsafe\b/i);
      }
    }
  });

  it("only queued, waiting and scanning rows keep the tab polling, every 10 seconds", () => {
    expect(ALL_STATES.filter(isWaiting)).toEqual(["queued", "upload_pending", "analysing"]);
    expect(FILE_CHECK_POLL_MS).toBe(10_000);
  });
});

describe("timeAgo, displayName and megabytes", () => {
  const now = Date.parse("2026-10-14T12:00:00Z");

  it("says how long ago a file was seen", () => {
    expect(timeAgo("2026-10-14T11:59:30Z", now)).toBe("just now");
    expect(timeAgo("2026-10-14T11:58:00Z", now)).toBe("2 min ago");
    expect(timeAgo("2026-10-14T09:00:00Z", now)).toBe("3 h ago");
    expect(timeAgo("2026-10-13T08:00:00Z", now)).toBe("yesterday");
    expect(timeAgo("2026-10-10T12:00:00Z", now)).toBe("4 days ago");
    expect(timeAgo("2026-09-01T12:00:00Z", now)).toMatch(/2026/);
    expect(timeAgo("not a date", now)).toBe("");
    expect(timeAgo(null, now)).toBe("");
  });

  it("makes direction tricks in a name visible and names an empty one", () => {
    expect(displayName("invoice‮txt.exe")).toBe("invoice�txt.exe");
    expect(displayName("  ")).toBe("Unnamed file");
    expect(displayName("setup.exe")).toBe("setup.exe");
  });

  it("rounds sizes down to whole megabytes", () => {
    expect(megabytes(20 * 1024 * 1024)).toBe("20 MB");
    expect(megabytes(20 * 1024 * 1024 + 5)).toBe("20 MB");
  });
});
