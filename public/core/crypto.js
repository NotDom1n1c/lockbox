// Web Crypto helpers. The same file runs in Node 22+ and in the browser.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export const utf8 = (s) => te.encode(s);
export const fromUtf8 = (b) => td.decode(b);

export function toB64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function randomToken(prefix = "lbx_") {
  return prefix + toB64(randomBytes(24)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const newKey = () => toB64(randomBytes(32));

export async function importKey(raw) {
  const bytes = typeof raw === "string" ? fromB64(raw) : raw;
  if (bytes.length !== 32) throw new Error("keys are 32 bytes (AES-256)");
  return subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

// AES-256-GCM with associated data: the ciphertext only opens in the context it was made for
export async function seal(key, bytes, aad) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, key, bytes);
  return { iv: toB64(iv), ct: toB64(ct) };
}

export async function open(key, { iv, ct }, aad) {
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv), additionalData: utf8(aad) }, key, fromB64(ct));
  return new Uint8Array(pt);
}

export async function sha256Hex(input) {
  const bytes = typeof input === "string" ? utf8(input) : input;
  const h = await subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// constant-time compare for hex strings of equal length
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
