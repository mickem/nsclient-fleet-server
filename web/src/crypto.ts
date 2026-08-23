// Client-side bundle encryption (enc-v1 / NSEB1).
//
// Mirrors `crates/core/src/encbundle.rs` exactly — keep the two in sync:
//
//   "NSEB1" (5) || key fingerprint (8 = first bytes of SHA-256 over the raw key)
//              || nonce (12) || AES-256-GCM ciphertext + 16-byte tag
//
// AAD = name || 0x00 || version, binding the bundle's identity into the authentication.
// The key is generated here, shown to the operator once, and NEVER sent to the server —
// only its fingerprint is registered, so the server can say "wrong key" but never decrypt.

const MAGIC = Uint8Array.from("NSEB1", (c) => c.charCodeAt(0));
const FINGERPRINT_LEN = 8;
const NONCE_LEN = 12;

export function generateKeyB64(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toB64(bytes);
}

export async function keyFingerprintHex(keyB64: string): Promise<string> {
  const raw = fromB64(keyB64.trim());
  if (raw.length !== 32) throw new Error(`key must be 32 bytes base64 (got ${raw.length})`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  return toHex(digest.slice(0, FINGERPRINT_LEN));
}

/** Encrypt a bundle zip for upload as `format=enc-v1`. */
export async function encryptBundle(
  keyB64: string,
  name: string,
  version: string,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const raw = fromB64(keyB64.trim());
  if (raw.length !== 32) throw new Error(`key must be 32 bytes base64 (got ${raw.length})`);
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = new Uint8Array(NONCE_LEN);
  crypto.getRandomValues(nonce);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aadFor(name, version) },
      key,
      plaintext,
    ),
  );
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  const out = new Uint8Array(MAGIC.length + FINGERPRINT_LEN + NONCE_LEN + ct.length);
  out.set(MAGIC, 0);
  out.set(digest.slice(0, FINGERPRINT_LEN), MAGIC.length);
  out.set(nonce, MAGIC.length + FINGERPRINT_LEN);
  out.set(ct, MAGIC.length + FINGERPRINT_LEN + NONCE_LEN);
  return out;
}

function aadFor(name: string, version: string): Uint8Array<ArrayBuffer> {
  const enc = new TextEncoder();
  const n = enc.encode(name);
  const v = enc.encode(version);
  const aad = new Uint8Array(n.length + 1 + v.length);
  aad.set(n, 0);
  aad[n.length] = 0;
  aad.set(v, n.length + 1);
  return aad;
}

// The unlocked key lives for the browser session only: never localStorage (survives too
// long), never the server (defeats the whole design).
const SESSION_KEY = "nsfleet.bundleKey";

export function rememberKey(keyB64: string) {
  sessionStorage.setItem(SESSION_KEY, keyB64);
}

export function recalledKey(): string | null {
  return sessionStorage.getItem(SESSION_KEY);
}

export function forgetKey() {
  sessionStorage.removeItem(SESSION_KEY);
}

function toB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromB64(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
