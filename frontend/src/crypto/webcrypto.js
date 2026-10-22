/**
 * webcrypto.js
 *
 * Thin wrappers around the browser's native WebCrypto API. This file
 * handles everything that ISN'T ML-KEM/ML-DSA: PBKDF2 (password-based
 * key derivation, for both the account-login verifier and the local
 * key-wrapping key), HKDF-SHA256 (session key derivation from the KEM
 * shared secret), and AES-256-GCM (message + key-at-rest encryption).
 *
 * WebCrypto is used deliberately over a JS implementation here: it's
 * native, constant-time, and battle-tested for exactly these primitives.
 * PQC primitives (ML-KEM/ML-DSA) aren't in WebCrypto yet, hence
 * @noble/post-quantum for those specifically.
 */

// ---------- encoding helpers ----------

export function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function utf8(str) {
  return new TextEncoder().encode(str);
}

export function fromUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function randomBytes(len) {
  return crypto.getRandomValues(new Uint8Array(len));
}

// ---------- PBKDF2 ----------

const PBKDF2_ITERATIONS = 200_000;

async function pbkdf2Bits(password, saltBytes, lengthBits) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    utf8(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    lengthBits
  );
  return new Uint8Array(bits);
}

/** Returns a hex digest suitable for sending to the server as the
 * account-login verifier. This is NOT the key-wrapping key — see
 * deriveWrappingKey below. Different salts, different purposes. */
export async function pbkdf2Verifier(password, saltBytes) {
  const bits = await pbkdf2Bits(password, saltBytes, 256);
  return bytesToHex(bits);
}

/** Returns a non-extractable AES-256-GCM CryptoKey for wrapping private
 * keys / session keys at rest in IndexedDB. This key and its salt never
 * leave the browser. */
export async function deriveWrappingKey(password, saltBytes) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    utf8(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ---------- AES-256-GCM ----------

export async function aeadEncrypt(key, plaintextBytes, aadBytes = new Uint8Array()) {
  const nonce = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aadBytes },
    key,
    plaintextBytes
  );
  return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

export async function aeadDecrypt(key, nonceBytes, ciphertextBytes, aadBytes = new Uint8Array()) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonceBytes, additionalData: aadBytes },
    key,
    ciphertextBytes
  );
  return new Uint8Array(plaintext);
}

// ---------- HKDF-SHA256 (session key derivation) ----------

/** Derives a non-extractable AES-256-GCM CryptoKey from an ML-KEM shared
 * secret. `info` binds the derived key to a specific session so the same
 * shared secret can never be reused as a key for a different context. */
export async function deriveSessionKey(sharedSecretBytes, infoString) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    sharedSecretBytes,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: utf8(infoString) },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Session keys need to be persisted (wrapped) in IndexedDB so history
 * stays decryptable across reloads, but WebCrypto's non-extractable keys
 * can't be exported. So for storage we derive an *extractable* raw key
 * via HKDF (same inputs, same output), wrap those raw bytes with the
 * account's wrapping key, and re-import as non-extractable on load. */
export async function deriveSessionKeyRawBytes(sharedSecretBytes, infoString) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    sharedSecretBytes,
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: utf8(infoString) },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

export async function importAesGcmKey(rawBytes) {
  return crypto.subtle.importKey("raw", rawBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}
