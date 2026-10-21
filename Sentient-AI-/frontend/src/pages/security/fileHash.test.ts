/**
 * Tests for fileHash (Security ▸ File checks fingerprinting): sha256Hex gives the published SHA-256
 * vectors as lowercase hex, and canHash is true only in a secure context with Web Crypto.
 *
 * Why it exists: the tab promises that only a file's fingerprint leaves the device, and the backend
 * refuses anything but 64 lowercase hex characters. A wrong digest would look up the wrong file in
 * VirusTotal; a canHash that said yes over plain HTTP would offer a picker that cannot work.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { HASH_MAX_BYTES, canHash, sha256Hex } from "@/pages/security/fileHash";

function setSecureContext(value: boolean | undefined) {
  Object.defineProperty(window, "isSecureContext", { value, configurable: true });
}

afterEach(() => {
  // jsdom has no isSecureContext of its own; put it back the way it was.
  delete (window as { isSecureContext?: boolean }).isSecureContext;
});

describe("sha256Hex", () => {
  it("sha256Hex of abc is the published vector", async () => {
    expect(await sha256Hex(new Blob(["abc"]))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("matches the published vectors for an empty file and a two-block message", async () => {
    expect(await sha256Hex(new Blob([]))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(await sha256Hex(new Blob(["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"]))).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("hashes a picked binary file byte for byte as 64 lowercase hex characters", async () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, n) => n);
    const digest = await sha256Hex(new File([bytes], "all-bytes.bin", { type: "application/octet-stream" }));
    // Worked out independently with Node's crypto.createHash("sha256").
    expect(digest).toBe("40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("asks Web Crypto for SHA-256 over the file's own bytes", async () => {
    const digest = vi.spyOn(globalThis.crypto.subtle, "digest");
    await sha256Hex(new Blob(["abc"]));
    expect(digest).toHaveBeenCalledTimes(1);
    expect(digest.mock.calls[0][0]).toBe("SHA-256");
    expect(new Uint8Array(digest.mock.calls[0][1] as ArrayBuffer)).toEqual(new Uint8Array([97, 98, 99]));
  });
});

describe("canHash", () => {
  it("canHash is false outside a secure context", () => {
    setSecureContext(false);
    expect(canHash()).toBe(false);
  });

  it("is true in a secure context with Web Crypto", () => {
    setSecureContext(true);
    expect(canHash()).toBe(true);
  });

  it("is false when the browser has no crypto.subtle, even in a secure context", () => {
    setSecureContext(true);
    vi.stubGlobal("crypto", {});
    expect(canHash()).toBe(false);
  });

  it("leaves the decision to Web Crypto when the browser does not report isSecureContext", () => {
    setSecureContext(undefined);
    expect(canHash()).toBe(true);
    vi.stubGlobal("crypto", {});
    expect(canHash()).toBe(false);
  });
});

describe("HASH_MAX_BYTES", () => {
  it("is 200 MB", () => {
    expect(HASH_MAX_BYTES).toBe(200 * 1024 * 1024);
  });
});
