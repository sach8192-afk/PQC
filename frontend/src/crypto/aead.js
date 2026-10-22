/**
 * aead.js
 *
 * REQ-MSG-2: encrypt every outgoing message with AEAD under the session key.
 * REQ-MSG-3: attach a monotonic sequence number.
 * REQ-RCV-2: decrypt using the session key, plaintext shown client-side only.
 * REQ-RCV-3: reject + flag (don't display) on AEAD tag failure.
 * REQ-RCV-4: detect + flag out-of-order/repeated sequence numbers.
 *
 * Per design review: ML-DSA is reserved for the handshake only (REQ-HS-2),
 * not per-message signing — signing every message would blow the ~5ms
 * per-message budget in §5.1 (ml_dsa65.sign() alone runs ~9ms). Instead,
 * sender/recipient/sequence_number are bound into the AEAD's associated
 * data (AAD), so tampering with any of that metadata breaks the auth tag
 * without a separate signature.
 */
import { utf8, fromUtf8, aeadEncrypt, aeadDecrypt, bytesToHex, hexToBytes } from "./webcrypto.js";
import { getSequenceState, setSequenceState, localSessionStorageId } from "./store.js";

function buildAad(sessionId, sender, recipient, sequenceNumber, keyId = null) {
  const base = `${sessionId}|${sender}|${recipient}|${sequenceNumber}`;
  // Legacy messages did not carry a key version. Keep their original AAD
  // format so they can still be opened with an archived legacy key.
  return utf8(keyId ? `${base}|${keyId}` : base);
}

/** Encrypts a plaintext message. Caller supplies the next sequence
 * number (tracked per-session, see nextOutgoingSequence below). */
export async function encryptMessage({ sessionKey, sessionId, sender, recipient, sequenceNumber, plaintext, keyId = null }) {
  const aad = buildAad(sessionId, sender, recipient, sequenceNumber, keyId);
  const { nonce, ciphertext } = await aeadEncrypt(sessionKey, utf8(plaintext), aad);
  return {
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
    sequence_number: sequenceNumber,
    key_id: keyId,
  };
}

/**
 * Decrypts + validates an incoming message. Returns
 * { plaintext, replayWarning } on success, or throws
 * AEAD_VERIFY_FAILED if the tag check fails (caller must not display
 * the message body in that case — REQ-RCV-3).
 */
export async function decryptMessage({ sessionKey, sessionId, sender, recipient, sequenceNumber, nonceHex, ciphertextHex, keyId = null, trackSequence = true, ownerUsername = null }) {
  const aad = buildAad(sessionId, sender, recipient, sequenceNumber, keyId);
  let plaintextBytes;
  try {
    plaintextBytes = await aeadDecrypt(sessionKey, hexToBytes(nonceHex), hexToBytes(ciphertextHex), aad);
  } catch (err) {
    throw new Error("AEAD_VERIFY_FAILED");
  }

  // Inbox previews authenticate/decrypt the latest ciphertext without
  // mutating replay state; only actual receive/history processing advances it.
  const replayWarning = trackSequence
    ? await checkAndAdvanceIncomingSequence(sessionId, sender, sequenceNumber, ownerUsername ?? recipient)
    : false;

  return { plaintext: fromUtf8(plaintextBytes), replayWarning };
}

/** Per-session, per-direction sequence number bookkeeping. Two counters
 * live under one IndexedDB record: `out` (my next outgoing number) and
 * `inSeen` (highest sequence number seen from the peer). */
export async function nextOutgoingSequence(sessionId, ownerUsername = null) {
  const storageId = localSessionStorageId(sessionId, ownerUsername);
  const state = (await getSequenceState(storageId)) || { out: 0, inSeen: -1 };
  const next = state.out + 1;
  await setSequenceState(storageId, { ...state, out: next });
  return next;
}

async function checkAndAdvanceIncomingSequence(sessionId, sender, sequenceNumber, ownerUsername = null) {
  const storageId = localSessionStorageId(sessionId, ownerUsername);
  const state = (await getSequenceState(storageId)) || { out: 0, inSeen: -1 };
  const seenKey = `inSeen_${sender}`;
  const lastSeen = state[seenKey] ?? -1;

  let replayWarning = false;
  if (sequenceNumber <= lastSeen) {
    // Repeated or out-of-order — flag per REQ-RCV-4, still show the
    // message (already AEAD-verified genuine) with a warning badge
    // rather than silently dropping it, which is friendlier for a PoC.
    replayWarning = true;
  }

  await setSequenceState(storageId, { ...state, [seenKey]: Math.max(lastSeen, sequenceNumber) });
  return replayWarning;
}
