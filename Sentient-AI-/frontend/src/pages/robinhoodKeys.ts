/**
 * Makes the Ed25519 key pair that signs requests to the Robinhood Crypto
 * API, in the browser, so connecting Robinhood needs no script.
 *
 * The private key fills the connector form's private key field exactly as a
 * pasted one would and is sent only when the connector is saved. The public
 * key is what the user registers at robinhood.com/account/crypto, which
 * answers with the API key.
 */

export interface RobinhoodKeyPair {
  /** Base64 of the 32-byte seed: what the backend stores as `api_secret`. */
  privateKey: string;
  /** Base64 of the 32-byte public key: what Robinhood asks for. */
  publicKey: string;
}

export const KEY_PAIR_UNSUPPORTED =
  "This browser cannot make Ed25519 keys. Use the key script in Robinhood's docs instead.";

// PKCS #8 wraps an Ed25519 private key as this fixed header followed by the
// 32-byte seed (RFC 8410). Browsers export private keys only in this form.
const PKCS8_ED25519_HEADER = [
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const KEY_BYTES = 32;

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** The seed inside a PKCS #8 Ed25519 key, or null for any other shape. */
export function seedFromPkcs8(pkcs8: Uint8Array): Uint8Array | null {
  if (pkcs8.length !== PKCS8_ED25519_HEADER.length + KEY_BYTES) return null;
  if (!PKCS8_ED25519_HEADER.every((byte, i) => pkcs8[i] === byte)) return null;
  return pkcs8.slice(PKCS8_ED25519_HEADER.length);
}

/** Generate a key pair. Throws an Error carrying `KEY_PAIR_UNSUPPORTED`
 * when the browser lacks Ed25519 (or Web Crypto, off a secure origin). */
export async function generateRobinhoodKeyPair(): Promise<RobinhoodKeyPair> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error(KEY_PAIR_UNSUPPORTED);
  let pair: CryptoKeyPair;
  try {
    pair = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  } catch {
    throw new Error(KEY_PAIR_UNSUPPORTED);
  }
  const seed = seedFromPkcs8(new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  if (!seed || publicKey.length !== KEY_BYTES) throw new Error(KEY_PAIR_UNSUPPORTED);
  return { privateKey: toBase64(seed), publicKey: toBase64(publicKey) };
}
