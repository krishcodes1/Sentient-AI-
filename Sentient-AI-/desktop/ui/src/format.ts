/**
 * Small pure helpers shared by the screens: elapsed-time text, error text, safe links, log-line
 * cleanup.
 *
 * Why it exists: These are the bits of logic worth unit-testing on their own, and several
 * components need the same answers (an elapsed clock that reads "4:07", a Rust error turned
 * into a sentence, a link that is only ever https).
 */

/** 0 → "0:00", 247 → "4:07", 3725 → "1:02:05". */
export function formatElapsed(seconds: number | null | undefined): string {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  const mm = h ? String(m).padStart(2, "0") : String(m);
  return `${h ? `${h}:` : ""}${mm}:${String(r).padStart(2, "0")}`;
}

/** Text of a rejected `invoke` (Rust errors arrive as strings) or any thrown value. */
export function errorText(error: unknown): string {
  if (typeof error === "string" && error.trim()) return error.trim();
  if (error instanceof Error && error.message) return error.message;
  if (error && typeof error === "object" && "message" in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) return message.trim();
  }
  return "Unknown error.";
}

/** The URL if it's https (the only links the app shows), otherwise null. */
export function httpsUrl(url: string | null | undefined): string | null {
  if (typeof url !== "string") return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

/** "12.34" → "12.3", "57.8" → "58": enough precision to judge disk space. */
export function formatGb(gb: number): string {
  return gb >= 10 ? String(Math.round(gb)) : String(Math.round(gb * 10) / 10);
}

// eslint-disable-next-line no-control-regex -- matching terminal escape sequences is the point
const ANSI = /\u001b\[[0-9;?]*[ -/]*[@-~]|\u001b\][^\u0007]*\u0007/g;
const MAX_LINE_CHARS = 2000;

/**
 * Turn one raw `stack://log` payload into display lines: strip colour codes, keep only the final
 * state of carriage-return progress redraws, split embedded newlines, cap very long lines.
 */
export function cleanLogLines(raw: string): string[] {
  return raw
    .replace(/\r\n/g, "\n")
    .replace(/\n$/, "")
    .split("\n")
    .map((line) => {
      const redraws = line.split("\r");
      const last = [...redraws].reverse().find((seg) => seg.trim()) ?? "";
      return last.replace(ANSI, "").slice(0, MAX_LINE_CHARS);
    });
}
