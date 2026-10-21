/**
 * fileHash: the SHA-256 fingerprint of a file picked on Security ▸ File checks, worked out in this
 * browser with Web Crypto, and whether this browser can do that at all.
 *
 * Why it exists: "Check a file…" promises that the file stays on this device. Only its fingerprint
 * goes to Crawler's backend, which looks it up in VirusTotal with the owner's key. Hashing here
 * keeps that promise: the bytes are read into this tab's memory and nothing else. Web Crypto exists
 * only in a secure context (HTTPS or localhost), so the page asks canHash() first and explains why
 * the picker is off, rather than failing after a file is picked. No new package (decision 4).
 */

/** The largest file this page will read into memory to fingerprint (200 MB). */
export const HASH_MAX_BYTES = 200 * 1024 * 1024;

/** True when this page can fingerprint a file: a secure context with `crypto.subtle.digest`. */
export function canHash(): boolean {
  if (typeof window === "undefined") return false;
  // Only an explicit false rules the page out. A browser too old to report isSecureContext
  // exposes crypto.subtle only where it may be used, so the digest check below decides.
  if (window.isSecureContext === false) return false;
  const subtle = globalThis.crypto?.subtle;
  return typeof subtle?.digest === "function";
}

/** The file's SHA-256 as 64 lowercase hex characters (the form the backend and VirusTotal use). */
export async function sha256Hex(file: Blob): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
