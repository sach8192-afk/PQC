/**
 * History decryption recovery for locally retained PQC session-key versions.
 *
 * Some earlier backend builds did not include `key_id` in the history API,
 * even though that ID had been bound into AES-GCM AAD at send time. This
 * helper tries the declared key version first, then locally retained versions
 * with their version ID and the legacy no-version AAD. It never bypasses AES-GCM
 * authentication; a candidate is accepted only if the authentication tag passes.
 */
import { decryptMessage } from "./aead.js";
import { loadSessionKeyFor, loadSessionKeyCandidatesFor } from "./session.js";

export async function decryptStoredMessage({
  message,
  sessionId,
  wrappingKey,
  activeSessionKey = null,
  activeKeyId = null,
  ownerUsername = null,
}) {
  const declaredKeyId = message?.key_id || null;
  const candidates = [];
  let lastError = null;

  const addCandidate = (key, keyId) => {
    if (!key) return;
    candidates.push({ key, keyId: keyId || null });
  };

  // Fast path for a correctly versioned history record.
  if (declaredKeyId) {
    try {
      const exactKey = activeKeyId === declaredKeyId && activeSessionKey
        ? activeSessionKey
        : await loadSessionKeyFor(sessionId, wrappingKey, declaredKeyId, ownerUsername);
      if (exactKey) {
        try {
          const result = await decryptMessage({
            sessionKey: exactKey,
            sessionId,
            sender: message.sender,
            recipient: message.recipient,
            sequenceNumber: message.sequence_number,
            nonceHex: message.nonce,
            ciphertextHex: message.ciphertext,
            keyId: declaredKeyId,
            trackSequence: false,
          });
          return { ...result, keyIdUsed: declaredKeyId };
        } catch (err) {
          lastError = err;
          addCandidate(exactKey, declaredKeyId);
        }
      }
    } catch (err) {
      lastError = err;
    }
  }

  addCandidate(activeSessionKey, activeKeyId);
  const storedCandidates = await loadSessionKeyCandidatesFor(sessionId, wrappingKey, ownerUsername).catch((err) => {
    lastError = err;
    return [];
  });
  for (const candidate of storedCandidates) addCandidate(candidate.key, candidate.keyId);

  // With a declared key ID, that ID is the first AAD choice. If the server
  // omitted it, try each locally retained version ID before legacy AAD.
  for (const candidate of candidates) {
    const aadKeyIds = declaredKeyId
      ? [declaredKeyId, candidate.keyId, null]
      : [candidate.keyId, null];
    const tried = new Set();
    for (const keyId of aadKeyIds) {
      const marker = keyId === null ? "__NO_KEY_ID__" : keyId;
      if (tried.has(marker)) continue;
      tried.add(marker);
      try {
        const result = await decryptMessage({
          sessionKey: candidate.key,
          sessionId,
          sender: message.sender,
          recipient: message.recipient,
          sequenceNumber: message.sequence_number,
          nonceHex: message.nonce,
          ciphertextHex: message.ciphertext,
          keyId,
          trackSequence: false,
        });
        return { ...result, keyIdUsed: keyId };
      } catch (err) {
        lastError = err;
      }
    }
  }

  throw new Error(
    lastError?.message === "AEAD_VERIFY_FAILED"
      ? "No locally retained session-key version could authenticate this message"
      : (lastError?.message || "No locally retained session key is available")
  );
}
