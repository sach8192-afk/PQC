/**
 * identity.js
 *
 * REQ-KEY-1: generate ML-KEM-768 keypair locally.
 * REQ-KEY-2: generate ML-DSA-65 keypair locally.
 * REQ-KEY-3: only public keys are ever sent to the server.
 * REQ-KEY-4: on any keygen failure, abort and let the caller offer retry.
 *
 * Private keys are wrapped (AES-256-GCM, key derived via PBKDF2 from the
 * user's password) and stored in IndexedDB. They are decrypted into
 * memory only after a successful login and held only for the tab's
 * lifetime (see session.js / App state — never re-persisted unwrapped).
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import {
  randomBytes,
  bytesToHex,
  hexToBytes,
  pbkdf2Verifier,
  deriveWrappingKey,
  aeadEncrypt,
  aeadDecrypt,
} from "./webcrypto.js";
import { saveIdentity, loadIdentity } from "./store.js";

/**
 * Generates both keypairs, wraps the secret keys with a password-derived
 * key, and persists the wrapped blobs + public keys in IndexedDB. Returns
 * the data the caller should send to the server (public keys + the
 * account login verifier) — nothing secret is in the return value's
 * "forServer" field.
 *
 * Throws on any failure — callers should catch and offer retry (REQ-KEY-4)
 * without partial state: nothing is written to IndexedDB or returned
 * unless every step below succeeds.
 */
export async function createIdentity(username, password, { persist = true } = {}) {
  let kemKeys, sigKeys;
  try {
    kemKeys = ml_kem768.keygen();
    sigKeys = ml_dsa65.keygen();
  } catch (err) {
    throw new Error("Key generation failed: " + err.message);
  }

  // Two independent salts/purposes, deliberately never mixed:
  //   - keyWrapSalt -> wraps the private keys at rest, stays local
  //   - loginSalt   -> server-side account verifier, sent to the server
  const keyWrapSalt = randomBytes(16);
  const loginSalt = randomBytes(16);

  const wrappingKey = await deriveWrappingKey(password, keyWrapSalt);
  const wrappedKem = await aeadEncrypt(wrappingKey, kemKeys.secretKey);
  const wrappedSig = await aeadEncrypt(wrappingKey, sigKeys.secretKey);

  const loginVerifier = await pbkdf2Verifier(password, loginSalt);

  const record = {
    username,
    kem_public_key: bytesToHex(kemKeys.publicKey),
    sig_public_key: bytesToHex(sigKeys.publicKey),
    key_wrap_salt: bytesToHex(keyWrapSalt),
    wrapped_kem_secret: { nonce: bytesToHex(wrappedKem.nonce), ciphertext: bytesToHex(wrappedKem.ciphertext) },
    wrapped_sig_secret: { nonce: bytesToHex(wrappedSig.nonce), ciphertext: bytesToHex(wrappedSig.ciphertext) },
    login_salt: bytesToHex(loginSalt),
  };

  if (persist) await saveIdentity(record);

  return {
    localRecord: record,
    forServer: {
      username,
      kem_public_key: record.kem_public_key,
      sig_public_key: record.sig_public_key,
      password_salt: record.login_salt,
      password_verifier: loginVerifier,
    },
  };
}

/**
 * Loads the wrapped identity for `username` from IndexedDB and unwraps
 * the private keys using the supplied password. Returns null if no local
 * identity exists for this username (e.g. wrong browser/device — identity
 * is local-only per SRS §2.5 multi-device-out-of-scope).
 * Throws if the password is wrong (unwrap/decrypt failure).
 */
export async function unlockIdentity(username, password) {
  const record = await loadIdentity(username);
  if (!record) return null;

  const keyWrapSalt = hexToBytes(record.key_wrap_salt);
  const wrappingKey = await deriveWrappingKey(password, keyWrapSalt);

  const kemSecret = await aeadDecrypt(
    wrappingKey,
    hexToBytes(record.wrapped_kem_secret.nonce),
    hexToBytes(record.wrapped_kem_secret.ciphertext)
  );
  const sigSecret = await aeadDecrypt(
    wrappingKey,
    hexToBytes(record.wrapped_sig_secret.nonce),
    hexToBytes(record.wrapped_sig_secret.ciphertext)
  );

  const loginVerifier = await pbkdf2Verifier(password, hexToBytes(record.login_salt));

  return {
    username,
    kemPublicKey: hexToBytes(record.kem_public_key),
    sigPublicKey: hexToBytes(record.sig_public_key),
    kemSecretKey: kemSecret,
    sigSecretKey: sigSecret,
    loginVerifier,
    wrappingKey, // CryptoKey — needed by session.js to wrap/unwrap session keys; never exportable
  };
}

export async function hasLocalIdentity(username) {
  const record = await loadIdentity(username);
  return !!record;
}
