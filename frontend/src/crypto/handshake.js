/**
 * handshake.js
 *
 * REQ-HS-1: ML-KEM-768 encapsulation/decapsulation to derive a shared secret.
 * REQ-HS-2: sign all handshake messages with the sender's ML-DSA-65 secret key.
 * REQ-HS-3: verify every received handshake message before accepting it;
 *           abort on verification failure.
 * REQ-HS-5 (server side, enforced there): server relays without inspecting.
 *
 * Nothing in this file ever runs on the server. It's imported only by
 * the React app.
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { bytesToHex, hexToBytes } from "./webcrypto.js";

/**
 * Alice's side: initiate a handshake with Bob.
 * Returns the shared secret (raw bytes, to be fed into HKDF by
 * session.js) plus the wire envelope to send over the WebSocket.
 */
export function initiateHandshake({ myUsername, mySigSecretKey, peerUsername, peerKemPublicKeyHex }) {
  const peerKemPublicKey = hexToBytes(peerKemPublicKeyHex);

  let cipherText, sharedSecret;
  try {
    ({ cipherText, sharedSecret } = ml_kem768.encapsulate(peerKemPublicKey));
  } catch (err) {
    throw new Error("ML-KEM encapsulation failed: " + err.message);
  }

  let signature;
  try {
    signature = ml_dsa65.sign(cipherText, mySigSecretKey);
  } catch (err) {
    throw new Error("ML-DSA signing failed: " + err.message);
  }

  const sessionId = [myUsername, peerUsername].sort().join("|");

  return {
    sharedSecret,
    sessionId,
    envelope: {
      type: "handshake_init",
      to: peerUsername,
      session_id: sessionId,
      kem_ciphertext: bytesToHex(cipherText),
      signature: bytesToHex(signature),
    },
  };
}

/**
 * Bob's side: verify + decapsulate an incoming handshake_init envelope.
 * Throws (does NOT return a partial/unverified secret) on any failure —
 * callers must catch and surface "Secure connection could not be
 * established" per SRS §3.1, never proceed with an unauthenticated
 * shared secret.
 */
export function respondToHandshake({ envelope, peerSigPublicKeyHex, myKemSecretKey }) {
  const cipherText = hexToBytes(envelope.kem_ciphertext);
  const signature = hexToBytes(envelope.signature);
  const peerSigPublicKey = hexToBytes(peerSigPublicKeyHex);

  let verified;
  try {
    verified = ml_dsa65.verify(signature, cipherText, peerSigPublicKey);
  } catch (err) {
    verified = false;
  }
  if (!verified) {
    throw new Error("HANDSHAKE_VERIFY_FAILED");
  }

  let sharedSecret;
  try {
    sharedSecret = ml_kem768.decapsulate(cipherText, myKemSecretKey);
  } catch (err) {
    throw new Error("ML-KEM decapsulation failed: " + err.message);
  }

  return { sharedSecret, sessionId: envelope.session_id };
}
