/**
 * The id this browser sends as `X-Crawler-Device` on every request to /api: a random id made on
 * first use and kept in localStorage under `crawler.device`, or in memory for the page's life when
 * storage is blocked.
 *
 * Why it exists: An app allowed for a week from the web ("Allow Calendar for 7 days" on an approval
 * card) applies only to requests from the browser that allowed it, and the server tells browsers
 * apart by this id, keeping only its hash (spec 2026-09-25-weekly-app-approvals §3.4). It is not a
 * credential: it narrows where an approval applies and never grants access on its own.
 */

export const DEVICE_STORAGE_KEY = "crawler.device";
export const DEVICE_HEADER = "X-Crawler-Device";

// What the server accepts as a device id. A stored value outside it (edited by hand, or written by
// something else) would be ignored there, so it is replaced here instead.
const DEVICE_ID = /^[A-Za-z0-9_-]{16,100}$/;

// The id last handed out. Keeps the page on one id while storage is blocked or full, and puts the
// same id back if the stored one is cleared while the page is open.
let current: string | null = null;

function newId(): string {
  // randomUUID exists only in a secure context (https, or localhost); Crawler opened by its LAN
  // address over plain http still has getRandomValues.
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * This browser's device id. Read from storage on every call rather than cached, so two tabs that
 * both made one on a first visit settle on whichever was stored last.
 */
export function deviceId(): string {
  try {
    const stored = localStorage.getItem(DEVICE_STORAGE_KEY);
    if (stored !== null && DEVICE_ID.test(stored)) {
      current = stored;
      return stored;
    }
    if (current === null) current = newId();
    localStorage.setItem(DEVICE_STORAGE_KEY, current);
    return current;
  } catch {
    // A private window with site data blocked throws on every access, and a full storage throws on
    // write: the id then lasts as long as the page, so its requests still match one another.
    if (current === null) current = newId();
    return current;
  }
}

/** The header that names this browser, to spread into a request's headers. */
export function deviceHeader(): Record<string, string> {
  return { [DEVICE_HEADER]: deviceId() };
}
