/**
 * pwnedPasswords: the in-browser half of Security ▸ Breach monitor ▸ "Check a password". It works
 * out a password's SHA-1 fingerprint here, sends only the first 5 hex characters of it to the
 * backend's Pwned Passwords proxy, and matches the rest of the fingerprint against the answer here.
 *
 * Why it exists: the password must never leave the browser, and the page may only talk to its own
 * backend (CSP connect-src 'self'), so the k-anonymity split happens in this module and the proxy
 * sees a prefix shared by hundreds of passwords. A Docker install opened over plain http on a LAN
 * address has no crypto.subtle (it needs a secure context), so a small FIPS 180-4 SHA-1 lives here
 * too instead of a new package (decisions item 4). No React; nothing here logs or stores anything.
 */

import { getPwnedRange } from "@/services/api";
import type { PwnedRange } from "@/types";

export type PasswordCheck = { found: true; count: number } | { found: false };

const HEX_PREFIX = /^[0-9A-F]{5}$/;

function hex32(word: number): string {
  return (word >>> 0).toString(16).padStart(8, "0");
}

function rotl(word: number, bits: number): number {
  return (word << bits) | (word >>> (32 - bits));
}

/** Pure SHA-1 (FIPS 180-4) over bytes; uppercase hex. Exported for the vector tests. */
export function sha1Fallback(bytes: Uint8Array): string {
  // Padding: one 0x80 byte, zeros, then the length in bits as a 64-bit big-endian number, so the
  // whole message fills a multiple of 64-byte blocks.
  const blocks = Math.ceil((bytes.length + 9) / 64);
  const padded = new Uint8Array(blocks * 64);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  // bytes.length * 8 can pass 2^32, so the high word is the byte count divided by 2^29.
  view.setUint32(padded.length - 8, Math.floor(bytes.length / 0x20000000));
  view.setUint32(padded.length - 4, (bytes.length * 8) >>> 0);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let t = 0; t < 16; t++) w[t] = view.getUint32(offset + t * 4);
    for (let t = 16; t < 80; t++) w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for (let t = 0; t < 80; t++) {
      let f: number;
      let k: number;
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      // Every term is below 2^32, so the plain sum stays exact before it is cut back to 32 bits.
      const next = (rotl(a, 5) + f + e + k + w[t]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30) >>> 0;
      b = a;
      a = next;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }
  return [h0, h1, h2, h3, h4].map(hex32).join("").toUpperCase();
}

/** SHA-1 of the password's UTF-8 bytes, uppercase hex. crypto.subtle when the page has it (a
 *  secure context: https or localhost); otherwise the pure fallback, because a Docker install
 *  opened over plain http on a LAN address has no crypto.subtle. No new package (decisions item 4). */
export async function sha1Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const subtle = globalThis.crypto?.subtle;
  if (subtle && typeof subtle.digest === "function") {
    try {
      const digest = new Uint8Array(await subtle.digest("SHA-1", bytes));
      return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
    } catch {
      // A browser that has crypto.subtle but refuses SHA-1 still gets an answer.
    }
  }
  return sha1Fallback(bytes);
}

/** Hash locally, send only hash.slice(0, 5) through fetchRange, match hash.slice(5) here;
 *  entries with count <= 0 (padding) never match. Never trims or alters the password. A failed
 *  fetch rejects; it never resolves to "not found". */
export async function checkPassword(
  password: string,
  fetchRange: (prefix: string) => Promise<PwnedRange> = getPwnedRange,
): Promise<PasswordCheck> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const range = await fetchRange(prefix);
  // An answer for some other prefix (or no list at all) says nothing about this password, so it is
  // a failed check, never "not found".
  if (
    !range ||
    typeof range.prefix !== "string" ||
    range.prefix.toUpperCase() !== prefix ||
    !HEX_PREFIX.test(prefix) ||
    !Array.isArray(range.suffixes)
  ) {
    throw new Error("The Pwned Passwords answer could not be read.");
  }
  for (const entry of range.suffixes) {
    if (!Array.isArray(entry)) continue;
    const [candidate, count] = entry;
    if (typeof candidate !== "string" || typeof count !== "number" || !(count > 0)) continue;
    if (candidate.toUpperCase() === suffix) return { found: true, count };
  }
  return { found: false };
}
