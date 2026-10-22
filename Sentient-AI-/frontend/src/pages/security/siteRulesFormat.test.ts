/**
 * Tests for siteRulesFormat (the Site rules tab's wording): they prove every kind and every place a
 * hit can happen has its plain-English label, that a rule reads "example.com and subdomains" only
 * when it covers them, that counts read "1 time" / "3 times", and that "how long ago" moves from
 * seconds to minutes, hours and days at the right edges.
 *
 * Why it exists: the owner decides what to block from these words. A raw "always_ask", a rule that
 * looked narrower than it is, or a hit that seemed older than it was would each mislead that choice.
 */

import { describe, expect, it } from "vitest";
import {
  SITE_RULE_KINDS,
  kindLabel,
  relativeTime,
  ruleTarget,
  timesText,
  whereLabel,
} from "@/pages/security/siteRulesFormat";

const NOW = Date.parse("2026-10-14T12:00:00Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();

describe("siteRulesFormat", () => {
  it("labels each kind in plain English, strictest first", () => {
    expect(SITE_RULE_KINDS.map(kindLabel)).toEqual(["Blocked", "Always ask", "Trusted"]);
  });

  it("labels each place a site can be stopped or flagged", () => {
    expect(whereLabel("navigation")).toBe("navigation");
    expect(whereLabel("read")).toBe("read");
    expect(whereLabel("call")).toBe("action");
    expect(whereLabel("web")).toBe("web fetch");
  });

  it("says a rule covers subdomains only when it does", () => {
    expect(ruleTarget({ host: "example.com", include_subdomains: true })).toBe("example.com and subdomains");
    expect(ruleTarget({ host: "docs.example.com", include_subdomains: false })).toBe("docs.example.com");
  });

  it("counts hits as one time or many times", () => {
    expect(timesText(1)).toBe("1 time");
    expect(timesText(3)).toBe("3 times");
  });

  it("says how long ago in seconds, minutes, hours and days", () => {
    expect(relativeTime(ago(2_000), NOW)).toBe("just now");
    expect(relativeTime(ago(40_000), NOW)).toBe("40 sec ago");
    expect(relativeTime(ago(2 * 60_000), NOW)).toBe("2 min ago");
    expect(relativeTime(ago(59 * 60_000), NOW)).toBe("59 min ago");
    expect(relativeTime(ago(60 * 60_000), NOW)).toBe("1 hour ago");
    expect(relativeTime(ago(3 * 3_600_000), NOW)).toBe("3 hours ago");
    expect(relativeTime(ago(24 * 3_600_000), NOW)).toBe("1 day ago");
    expect(relativeTime(ago(2 * 86_400_000 + 5_000), NOW)).toBe("2 days ago");
  });

  it("reads a time slightly in the future as just now and returns an unreadable time unchanged", () => {
    expect(relativeTime(new Date(NOW + 30_000).toISOString(), NOW)).toBe("just now");
    expect(relativeTime("not a time", NOW)).toBe("not a time");
  });
});
