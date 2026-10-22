/**
 * mcpReviews: pure helpers for Security ▸ "MCP reviews" and the Connectors chip — the order tools
 * are listed in, what each tool's status says, the CHANGED/NEW chip, how a diff line is coloured
 * and signed, how a run of hidden characters is labelled, and how many tools wait in all.
 *
 * Why it exists: the review shows text an MCP server wrote, and that text is exactly what an
 * attacker controls (a "rug pull" rewrites a trusted tool's description). Keeping the wording and
 * the rules for showing it in one component-free module lets them be tested on their own, keeps
 * Fast Refresh working for the tab, and makes sure the tab and the chip count waiting tools alike.
 */

import type {
  McpPinStatus,
  McpReviewKind,
  McpReviewLine,
  McpReviewList,
  McpTextPart,
  McpToolPinView,
} from "@/types";

/** How long a decoded hidden message may get on screen before it is cut. */
export const HIDDEN_DECODED_CAP = 200;

const STATUS_ORDER: Record<McpPinStatus, number> = { needs_review: 0, kept_off: 1, approved: 2 };

function timeOf(iso: string | null): number {
  if (!iso) return Number.NEGATIVE_INFINITY;
  const when = Date.parse(iso);
  return Number.isNaN(when) ? Number.NEGATIVE_INFINITY : when;
}

function byName(a: McpToolPinView, b: McpToolPinView): number {
  return a.tool_name < b.tool_name ? -1 : a.tool_name > b.tool_name ? 1 : 0;
}

/**
 * Tools in the order the owner should look at them: waiting ones first (the newest change on
 * top), then kept-off ones, then approved ones by name, and tools the server no longer offers
 * last. The same order the server sorts in, so a list that arrives unsorted still reads alike.
 */
export function sortTools(tools: McpToolPinView[]): McpToolPinView[] {
  return [...tools].sort((a, b) => {
    if (a.removed !== b.removed) return a.removed ? 1 : -1;
    const group = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
    if (group !== 0) return group;
    if (a.status === "needs_review") {
      const newer = timeOf(b.changed_at) - timeOf(a.changed_at);
      if (newer !== 0 && !Number.isNaN(newer)) return newer;
    }
    return byName(a, b);
  });
}

/**
 * A day in the viewer's locale ("12 Oct" or "Oct 12"). A value that is not a date comes back as
 * it was, rather than as "Invalid Date".
 */
export function formatDay(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

/** A day and time in the viewer's locale ("14 Oct, 10:02"), for when a change was seen. */
export function formatWhen(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * What the "Show all tools" list says about one tool. "Removed by the server" wins over the
 * status (a removed tool is not offered whatever it was); an approved tool says how it came to be
 * trusted, because "trusted when first seen" was never looked at by a person.
 */
export function statusLabel(pin: McpToolPinView): string {
  if (pin.removed) return "Removed by the server";
  if (pin.status === "needs_review") return "Waiting for review";
  if (pin.status === "kept_off") return "Kept off";
  if (pin.trusted_how === "first_use") return "Trusted when first seen";
  if (pin.trusted_how === "owner_test") return "Trusted when you tested the server";
  return pin.approved_at ? `Approved by you, ${formatDay(pin.approved_at)}` : "Approved by you";
}

/** The chip on a waiting tool's card. */
export function kindLabel(kind: McpReviewKind): "CHANGED" | "NEW" {
  return kind === "new" ? "NEW" : "CHANGED";
}

export interface LineTone {
  background: string;
  color: string;
  sign: "+" | "-" | " " | "";
}

/**
 * How one review line looks. The sign is shown as text, so an added or removed line can be told
 * apart without seeing its colour. A hunk line arrives whole (a "@@ -1,5 +1,6 @@" header, or a
 * sentence saying which part of a change cannot be shown), so it gets no sign of its own.
 */
export function lineTone(op: McpReviewLine["op"]): LineTone {
  if (op === "added") {
    return { background: "var(--fill-success)", color: "var(--accent-success)", sign: "+" };
  }
  if (op === "removed") {
    return { background: "var(--fill-danger)", color: "var(--accent-danger)", sign: "-" };
  }
  if (op === "hunk") return { background: "transparent", color: "var(--text-muted)", sign: "" };
  return { background: "transparent", color: "var(--text-muted)", sign: " " };
}

/**
 * The text of a hidden-characters chip: the server's own description of the run ("U+200B",
 * "41 hidden characters"), plus, for a run of tag characters, the message they spell in quotes,
 * cut at HIDDEN_DECODED_CAP characters. The decoded text is exactly what an attacker hid for the
 * AI to read, so the owner sees it, but a very long one cannot push the rest of the review away.
 */
export function hiddenLabel(part: McpTextPart): string {
  const decoded = part.decoded;
  if (!decoded) return part.text;
  const shown =
    decoded.length > HIDDEN_DECODED_CAP ? `${decoded.slice(0, HIDDEN_DECODED_CAP)}…` : decoded;
  return `${part.text}: "${shown}"`;
}

// Characters that draw nothing or reorder what is around them, as code-point ranges: the soft
// hyphen, the Mongolian vowel separator, zero-width spaces and joiners with the LRM/RLM marks,
// bidi embeddings and overrides, invisible operators, bidi isolates and the deprecated format
// characters, the byte-order mark, and the tag block. The server already turns runs of these into
// hidden parts; this is the second line, so a run it missed is still shown as a code instead of
// being invisible on the page. Numbers rather than escapes, so the source itself holds none.
const INVISIBLE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00ad, 0x00ad],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
  [0xe0000, 0xe007f],
];

function isInvisible(code: number): boolean {
  return INVISIBLE_RANGES.some(([low, high]) => code >= low && code <= high);
}

/** `text` with every invisible character replaced by a visible "[U+200B]"-style code. */
export function showInvisible(text: string): string {
  let out = "";
  // for...of walks code points, so a tag character (outside the BMP) is one character here.
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    out += isInvisible(code) ? `[U+${code.toString(16).toUpperCase().padStart(4, "0")}]` : ch;
  }
  return out;
}

/** Every waiting tool across the caller's servers. */
export function totalNeedsReview(list: McpReviewList): number {
  return list.servers.reduce((sum, server) => sum + server.needs_review_count, 0);
}

/** "1 tool", "4 tools". */
export function toolCount(n: number): string {
  return `${n} ${n === 1 ? "tool" : "tools"}`;
}
