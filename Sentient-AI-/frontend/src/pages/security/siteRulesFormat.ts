/**
 * siteRulesFormat: the words the Security page's "Site rules" tab uses for a rule's kind, where a
 * site was stopped or flagged, what a rule covers, and how long ago something happened.
 *
 * Why it exists: the tab, its rows and its tests must say "Always ask" (never "always_ask") and
 * "example.com and subdomains" the same way everywhere; keeping the wording in a component-free
 * module also keeps Fast Refresh working for the tab (react-refresh/only-export-components).
 */

import type { SiteHit, SiteRule, SiteRuleKind } from "@/types";

/** Every kind, in the order the selects list them (strictest first). */
export const SITE_RULE_KINDS: readonly SiteRuleKind[] = ["blocked", "always_ask", "trusted"];

const KIND_LABELS: Record<SiteRuleKind, string> = {
  blocked: "Blocked",
  always_ask: "Always ask",
  trusted: "Trusted",
};

const WHERE_LABELS: Record<SiteHit["where"], string> = {
  navigation: "navigation",
  read: "read",
  call: "action",
  web: "web fetch",
};

/** "Blocked", "Always ask" or "Trusted". */
export function kindLabel(kind: SiteRuleKind): string {
  return KIND_LABELS[kind];
}

/** Where a hit happened, as the recent list says it: "navigation", "read", "action", "web fetch". */
export function whereLabel(where: SiteHit["where"]): string {
  return WHERE_LABELS[where];
}

/** What a rule covers, from the host the server shows: "example.com and subdomains" or the host. */
export function ruleTarget(rule: Pick<SiteRule, "host" | "include_subdomains">): string {
  return rule.include_subdomains ? `${rule.host} and subdomains` : rule.host;
}

/** "1 time" or "3 times". */
export function timesText(count: number): string {
  return count === 1 ? "1 time" : `${count} times`;
}

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? "" : "s"} ago`;
}

/**
 * How long before `now` an ISO time was: "just now", "40 sec ago", "2 min ago", "3 hours ago",
 * "2 days ago". A time in the future (a clock a little ahead) reads "just now"; an unreadable one is
 * returned as it came, so the row still shows something true.
 */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return iso;
  const seconds = Math.max(0, Math.floor((now - at) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds} sec ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return plural(hours, "hour");
  return plural(Math.floor(hours / 24), "day");
}
