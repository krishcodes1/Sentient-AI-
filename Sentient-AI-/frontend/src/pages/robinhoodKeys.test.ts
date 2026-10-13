/**
 * Tests for the Robinhood key pair maker: the private key it hands the form is the base64 seed the
 * backend signs with, the public key belongs to that seed, and a browser without Ed25519 gets a
 * plain message instead of a half-made key.
 *
 * Why it exists: Guards against a key pair whose halves do not match (Robinhood would refuse every
 * signature with an opaque 401 after the user had already registered the public key) and against
 * the private key leaving in PKCS #8 form, which the backend rejects.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { KEY_PAIR_UNSUPPORTED, generateRobinhoodKeyPair, seedFromPkcs8 } from "@/pages/robinhoodKeys";

// RFC 8410's PKCS #8 header for an Ed25519 private key, written out
// independently of the module's copy.
const HEADER = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

// Robinhood's published signing example (docs.robinhood.com/crypto/trading/).
// Documentation values, not live credentials.
const DOC_PRIVATE_KEY = "xQnTJVeQLmw1/Mg2YimEViSpw/SdJcgNXZ5kQkAXNPU=";
const DOC_PUBLIC_KEY = "jPItx4TLjcnSUnmnXQQyAKL4eJj3+oWNNMmmm2vATqk=";

function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function pkcs8(seed: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(HEADER.length + seed.length);
  out.set(HEADER);
  out.set(seed, HEADER.length);
  return out;
}

/** Sign with the seed and check the signature against the public key. */
async function halvesMatch(privateKey: string, publicKey: string): Promise<boolean> {
  const message = new TextEncoder().encode("rh-api-key1698708981/api/v1/crypto/trading/accounts/GET");
  const signer = await crypto.subtle.importKey("pkcs8", pkcs8(fromBase64(privateKey)), "Ed25519", false, ["sign"]);
  const verifier = await crypto.subtle.importKey("raw", fromBase64(publicKey), "Ed25519", false, ["verify"]);
  const signature = await crypto.subtle.sign("Ed25519", signer, message);
  return crypto.subtle.verify("Ed25519", verifier, signature, message);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("generateRobinhoodKeyPair", () => {
  it("returns a base64 seed and the public key that belongs to it", async () => {
    const pair = await generateRobinhoodKeyPair();

    expect(fromBase64(pair.privateKey)).toHaveLength(32);
    expect(fromBase64(pair.publicKey)).toHaveLength(32);
    expect(await halvesMatch(pair.privateKey, pair.publicKey)).toBe(true);
  });

  it("makes a fresh pair each time", async () => {
    const [a, b] = await Promise.all([generateRobinhoodKeyPair(), generateRobinhoodKeyPair()]);
    expect(a.privateKey).not.toBe(b.privateKey);
    expect(await halvesMatch(a.privateKey, b.publicKey)).toBe(false);
  });

  it("says so plainly when the browser has no Ed25519", async () => {
    vi.spyOn(crypto.subtle, "generateKey").mockRejectedValue(new DOMException("nope", "NotSupportedError"));
    await expect(generateRobinhoodKeyPair()).rejects.toThrow(KEY_PAIR_UNSUPPORTED);
  });
});

describe("seedFromPkcs8", () => {
  it("unwraps the documented key to the seed Robinhood's script prints", async () => {
    // The documented seed, wrapped and unwrapped, still signs for the documented public key.
    const seed = seedFromPkcs8(pkcs8(fromBase64(DOC_PRIVATE_KEY)));
    expect(seed).toEqual(fromBase64(DOC_PRIVATE_KEY));
    expect(await halvesMatch(DOC_PRIVATE_KEY, DOC_PUBLIC_KEY)).toBe(true);
  });

  it("refuses anything that is not an Ed25519 PKCS #8 key", () => {
    const seed = fromBase64(DOC_PRIVATE_KEY);
    expect(seedFromPkcs8(seed)).toBeNull();
    expect(seedFromPkcs8(pkcs8(seed).slice(0, 40))).toBeNull();
    const otherCurve = pkcs8(seed);
    otherCurve[11] = 0x6f; // X448's OID ends in 0x6f
    expect(seedFromPkcs8(otherCurve)).toBeNull();
  });
});
