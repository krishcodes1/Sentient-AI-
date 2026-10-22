/**
 * Tests for pwnedPasswords (the in-browser half of the Pwned Passwords check): they prove the pure
 * SHA-1 matches the FIPS 180 vectors and the browser's own crypto.subtle, that only the first five
 * hex characters of the fingerprint are ever handed to the range request, that a match needs the
 * rest of the fingerprint and a count above zero, that a failed or mismatched range answer rejects
 * instead of reading as "not found", and that the password is hashed exactly as typed.
 *
 * Why it exists: the promise on the Security page is that the password never leaves the browser.
 * A helper that sent the whole hash, trimmed the password, matched a padding entry, or turned an
 * outage into "not found" would break that promise or tell someone a leaked password is unknown.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { PwnedRange } from "@/types";

vi.mock("@/services/api", () => ({
  getPwnedRange: vi.fn(),
}));

import { checkPassword, sha1Fallback, sha1Hex } from "@/pages/security/pwnedPasswords";
import { getPwnedRange } from "@/services/api";

const SOURCE = "Pwned Passwords by Have I Been Pwned (haveibeenpwned.com)";
// SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8 (worked out with Node's crypto).
const PASSWORD_PREFIX = "5BAA6";
const PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function rangeFetcher(suffixes: [string, number][]) {
  return vi.fn(async (prefix: string): Promise<PwnedRange> => ({ prefix, suffixes, source: SOURCE }));
}

describe("pwnedPasswords", () => {
  afterEach(() => {
    vi.mocked(getPwnedRange).mockReset();
  });

  it('sha1Fallback matches the FIPS 180 vectors for "", "abc" and the 448-bit message, and a UTF-8 password with accents and an emoji', () => {
    expect(sha1Fallback(utf8(""))).toBe("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
    expect(sha1Fallback(utf8("abc"))).toBe("A9993E364706816ABA3E25717850C26C9CD0D89D");
    expect(sha1Fallback(utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))).toBe(
      "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
    );
    expect(sha1Fallback(utf8("Pässwörd çafé 🔐"))).toBe("58B1DDF5E8A474603843EFF5F03C3DB9E876F678");
  });

  it("sha1Fallback is right on both sides of each padding boundary and for a million bytes", () => {
    // 55 bytes is the longest message that pads into one block; 56 and 64 need a second one.
    expect(sha1Fallback(utf8("x".repeat(55)))).toBe("CEF734BA81A024479E09EB5A75B6DDAE62E6ABF1");
    expect(sha1Fallback(utf8("x".repeat(56)))).toBe("901305367C259952F4E7AF8323F480D59F81335B");
    expect(sha1Fallback(utf8("x".repeat(64)))).toBe("BB2FA3EE7AFB9F54C6DFB5D021F14B1FFE40C163");
    expect(sha1Fallback(utf8("a".repeat(1_000_000)))).toBe("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");
  });

  it("sha1Hex gives the same answer through crypto.subtle and through the fallback when crypto.subtle is missing", async () => {
    const words = ["", "password", "Pässwörd çafé 🔐", "correct horse battery staple"];
    const digest = vi.spyOn(globalThis.crypto.subtle, "digest");
    const throughSubtle = [];
    for (const word of words) throughSubtle.push(await sha1Hex(word));
    expect(digest).toHaveBeenCalledTimes(words.length);

    // A page served over plain http on a LAN address has no crypto.subtle at all.
    vi.stubGlobal("crypto", {});
    const throughFallback = [];
    for (const word of words) throughFallback.push(await sha1Hex(word));

    expect(throughFallback).toEqual(throughSubtle);
    expect(throughSubtle).toEqual([
      "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
      `${PASSWORD_PREFIX}${PASSWORD_SUFFIX}`,
      "58B1DDF5E8A474603843EFF5F03C3DB9E876F678",
      "ABF7AAD6438836DBE526AA231ABDE2D0EEF74D42",
    ]);
  });

  it("sha1Hex falls back to the pure SHA-1 when crypto.subtle refuses the digest", async () => {
    vi.spyOn(globalThis.crypto.subtle, "digest").mockRejectedValue(new Error("SHA-1 is not allowed here"));

    expect(await sha1Hex("password")).toBe(`${PASSWORD_PREFIX}${PASSWORD_SUFFIX}`);
  });

  it("checkPassword sends only the first five uppercase hex characters of the hash, never the password or the rest of the hash", async () => {
    const fetchRange = rangeFetcher([]);

    await checkPassword("password", fetchRange);

    expect(fetchRange.mock.calls).toEqual([[PASSWORD_PREFIX]]);
    const sent = JSON.stringify(fetchRange.mock.calls);
    expect(sent).not.toContain("password");
    expect(sent).not.toContain(PASSWORD_SUFFIX);
    expect(sent).not.toContain(PASSWORD_SUFFIX.slice(0, 6));
  });

  it("checkPassword asks the backend's range route by default", async () => {
    vi.mocked(getPwnedRange).mockResolvedValue({
      prefix: PASSWORD_PREFIX,
      suffixes: [[PASSWORD_SUFFIX, 52256]],
      source: SOURCE,
    });

    expect(await checkPassword("password")).toEqual({ found: true, count: 52256 });
    expect(vi.mocked(getPwnedRange).mock.calls).toEqual([[PASSWORD_PREFIX]]);
  });

  it("checkPassword reports the breach count when the suffix is in the range and ignores padding entries with a count of zero", async () => {
    const found = await checkPassword(
      "password",
      rangeFetcher([
        ["0018A45C4D1DEF81644B54AB7F969B88D65", 1],
        [PASSWORD_SUFFIX.toLowerCase(), 52256],
      ]),
    );
    expect(found).toEqual({ found: true, count: 52256 });

    // Padding entries (count 0) are decoys that hide how many real entries a range holds.
    const padded = await checkPassword("password", rangeFetcher([[PASSWORD_SUFFIX, 0]]));
    expect(padded).toEqual({ found: false });
  });

  it("checkPassword reports not found when no suffix matches", async () => {
    const result = await checkPassword(
      "password",
      rangeFetcher([
        ["0018A45C4D1DEF81644B54AB7F969B88D65", 3],
        // One character off at the end: a different password.
        [`${PASSWORD_SUFFIX.slice(0, -1)}9`, 12],
      ]),
    );

    expect(result).toEqual({ found: false });
  });

  it("checkPassword rejects when the range request fails instead of reporting not found", async () => {
    const failing = vi.fn(async () => {
      throw new Error("Not checked: the Pwned Passwords service could not be reached.");
    });

    await expect(checkPassword("password", failing)).rejects.toThrow("could not be reached");
  });

  it("checkPassword rejects an answer for another prefix or without a list instead of reporting not found", async () => {
    const otherPrefix = vi.fn(async (): Promise<PwnedRange> => ({ prefix: "00000", suffixes: [], source: SOURCE }));
    await expect(checkPassword("password", otherPrefix)).rejects.toThrow("could not be read");

    const noList = vi.fn(
      async (prefix: string) => ({ prefix, suffixes: null, source: SOURCE }) as unknown as PwnedRange,
    );
    await expect(checkPassword("password", noList)).rejects.toThrow("could not be read");
  });

  it("checkPassword hashes the password exactly as typed, spaces included", async () => {
    const fetchRange = rangeFetcher([["9097D192D7EE8B3B5AA5292", 1]]);

    const result = await checkPassword(" password ", fetchRange);

    // SHA-1(" password ") = E6EE5DBAB4167ECE69097D192D7EE8B3B5AA5292, not the hash of "password".
    expect(fetchRange.mock.calls).toEqual([["E6EE5"]]);
    expect(result).toEqual({ found: false });
    const exact = rangeFetcher([["DBAB4167ECE69097D192D7EE8B3B5AA5292", 7]]);
    expect(await checkPassword(" password ", exact)).toEqual({ found: true, count: 7 });
  });
});
