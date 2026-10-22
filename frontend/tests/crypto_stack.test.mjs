import "fake-indexeddb/auto";
import { createIdentity, unlockIdentity } from "../src/crypto/identity.js";
import { initiateHandshake, respondToHandshake } from "../src/crypto/handshake.js";
import { establishSessionKey, loadSessionKeyFor, loadSessionStatusFor, loadPendingHandshakeFor, markSessionEstablished } from "../src/crypto/session.js";
import { encryptMessage, decryptMessage, nextOutgoingSequence } from "../src/crypto/aead.js";
import { deriveWrappingKey, hexToBytes } from "../src/crypto/webcrypto.js";
import { decryptStoredMessage } from "../src/crypto/history.js";
import { loadIdentity } from "../src/crypto/store.js";

function assert(cond, msg) {
  if (!cond) throw new Error("ASSERTION FAILED: " + msg);
  console.log("  ok:", msg);
}

async function main() {
  console.log("--- 1. Identity creation (Alice, Bob) ---");
  const alice = await createIdentity("alice", "alice-password-123");
  const bob = await createIdentity("bob", "bob-password-456");
  const stagedRegistration = await createIdentity("register-pending-test", "pending-password-123", { persist: false });
  assert(!(await loadIdentity("register-pending-test")) && !!stagedRegistration.localRecord,
    "staged registration does not overwrite/persist a local identity before server registration succeeds");
  assert(alice.forServer.username === "alice", "alice forServer payload has username");
  assert(!("kem_secret_key" in alice.forServer) && !JSON.stringify(alice.forServer).includes("secret"), "alice forServer payload has NO secret material");
  console.log("  alice kem_public_key len (hex chars):", alice.forServer.kem_public_key.length, "-> bytes:", alice.forServer.kem_public_key.length / 2);
  assert(alice.forServer.kem_public_key.length / 2 === 1184, "ML-KEM-768 public key is 1184 bytes");
  assert(alice.forServer.sig_public_key.length / 2 === 1952, "ML-DSA-65 public key is 1952 bytes");

  console.log("--- 2. Duplicate registration attempt fails to unlock with wrong password ---");
  try {
    await unlockIdentity("alice", "wrong-password");
    throw new Error("should have thrown");
  } catch (err) {
    assert(err.message !== "should have thrown", "wrong password rejected: " + err.message);
  }

  console.log("--- 3. Correct login unlocks identity ---");
  const aliceUnlocked = await unlockIdentity("alice", "alice-password-123");
  const bobUnlocked = await unlockIdentity("bob", "bob-password-456");
  assert(aliceUnlocked.kemSecretKey.length === 2400, "alice KEM secret key unwrapped correctly (2400 bytes)");
  assert(bobUnlocked.sigSecretKey.length === 4032, "bob DSA secret key unwrapped correctly (4032 bytes)");

  console.log("--- 4. Handshake: alice initiates with bob's public key ---");
  const initResult = initiateHandshake({
    myUsername: "alice",
    mySigSecretKey: aliceUnlocked.sigSecretKey,
    peerUsername: "bob",
    peerKemPublicKeyHex: bob.forServer.kem_public_key,
  });
  assert(initResult.envelope.type === "handshake_init", "envelope type correct");
  assert(!JSON.stringify(initResult.envelope).match(/secret/i), "envelope contains no secret material");
  initResult.envelope.handshake_id = "test-handshake-a";
  console.log("  kem_ciphertext bytes:", initResult.envelope.kem_ciphertext.length / 2);
  assert(initResult.envelope.kem_ciphertext.length / 2 === 1088, "ciphertext is 1088 bytes (ML-KEM-768)");

  console.log("--- 5. Bob responds: verify + decapsulate ---");
  const respResult = respondToHandshake({
    envelope: initResult.envelope,
    peerSigPublicKeyHex: alice.forServer.sig_public_key,
    myKemSecretKey: bobUnlocked.kemSecretKey,
  });
  assert(
    Buffer.from(initResult.sharedSecret).equals(Buffer.from(respResult.sharedSecret)),
    "alice's and bob's shared secrets match"
  );

  console.log("--- 6. Tampered handshake signature is rejected ---");
  const tamperedEnvelope = { ...initResult.envelope, kem_ciphertext: initResult.envelope.kem_ciphertext.replace(/^../, "ff") };
  try {
    respondToHandshake({
      envelope: tamperedEnvelope,
      peerSigPublicKeyHex: alice.forServer.sig_public_key,
      myKemSecretKey: bobUnlocked.kemSecretKey,
    });
    throw new Error("should have thrown");
  } catch (err) {
    assert(err.message === "HANDSHAKE_VERIFY_FAILED", "tampered handshake correctly rejected: " + err.message);
  }

  console.log("--- 7. Session key derivation (both sides independently) ---");
  const aliceWrapKey = await deriveWrappingKey("alice-password-123", hexToBytes((await loadIdentity("alice")).key_wrap_salt));
  const bobWrapKey = await deriveWrappingKey("bob-password-456", hexToBytes((await loadIdentity("bob")).key_wrap_salt));

  const aliceSessionKey = await establishSessionKey({
    sharedSecret: initResult.sharedSecret,
    sessionId: initResult.sessionId,
    wrappingKey: aliceWrapKey,
    handshakeId: "test-handshake-a",
  });
  const bobSessionKey = await establishSessionKey({
    sharedSecret: respResult.sharedSecret,
    sessionId: respResult.sessionId,
    wrappingKey: bobWrapKey,
    handshakeId: "test-handshake-a",
  });
  assert(!!aliceSessionKey && !!bobSessionKey, "both session keys derived without error");

  console.log("--- 7a. Account-isolated session storage in one browser profile ---");
  const sharedBrowserSessionId = "alice|bob-shared-browser-test";
  const aliceScopedKey = await establishSessionKey({
    sharedSecret: initResult.sharedSecret,
    sessionId: sharedBrowserSessionId,
    wrappingKey: aliceWrapKey,
    handshakeId: "same-handshake-id",
    ownerUsername: "alice",
  });
  const bobScopedKey = await establishSessionKey({
    sharedSecret: respResult.sharedSecret,
    sessionId: sharedBrowserSessionId,
    wrappingKey: bobWrapKey,
    handshakeId: "same-handshake-id",
    ownerUsername: "bob",
  });
  const aliceScopedReloaded = await loadSessionKeyFor(sharedBrowserSessionId, aliceWrapKey, "same-handshake-id", "alice");
  const bobScopedReloaded = await loadSessionKeyFor(sharedBrowserSessionId, bobWrapKey, "same-handshake-id", "bob");
  const scopedCipher = await encryptMessage({
    sessionKey: aliceScopedKey,
    sessionId: sharedBrowserSessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: 1,
    plaintext: "Account-isolated session storage works",
    keyId: "same-handshake-id",
  });
  const aliceSelfHistory = await decryptMessage({
    sessionKey: aliceScopedReloaded,
    sessionId: sharedBrowserSessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: scopedCipher.sequence_number,
    nonceHex: scopedCipher.nonce,
    ciphertextHex: scopedCipher.ciphertext,
    keyId: "same-handshake-id",
    trackSequence: false,
  });
  const bobHistory = await decryptMessage({
    sessionKey: bobScopedReloaded,
    sessionId: sharedBrowserSessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: scopedCipher.sequence_number,
    nonceHex: scopedCipher.nonce,
    ciphertextHex: scopedCipher.ciphertext,
    keyId: "same-handshake-id",
    trackSequence: false,
  });
  assert(
    aliceSelfHistory.plaintext === "Account-isolated session storage works" && bobHistory.plaintext === "Account-isolated session storage works",
    "two local accounts can independently wrap/restore the same session key without overwriting each other's IndexedDB records"
  );

  console.log("--- 7b. Pending handshake persistence for offline messaging ---");
  const offlineSessionId = "alice|bob-offline-test";
  const pendingHandshake = { ...initResult.envelope, handshake_id: "pending-offline-test" };
  await establishSessionKey({
    sharedSecret: initResult.sharedSecret,
    sessionId: offlineSessionId,
    wrappingKey: aliceWrapKey,
    status: "pending",
    pendingHandshake,
  });
  assert(await loadSessionStatusFor(offlineSessionId) === "pending", "offline session status stays pending before peer confirmation");
  assert((await loadPendingHandshakeFor(offlineSessionId))?.handshake_id === "pending-offline-test", "same handshake envelope persists for safe resend after reload");
  await markSessionEstablished(offlineSessionId);
  assert(await loadSessionStatusFor(offlineSessionId) === "established", "peer acknowledgement persists confirmed session status");
  assert(await loadPendingHandshakeFor(offlineSessionId) === null, "confirmed session discards its pending resend envelope");

  console.log("--- 8. Message encrypt (alice) -> decrypt (bob) ---");
  const seq1 = await nextOutgoingSequence(initResult.sessionId);
  const encrypted = await encryptMessage({
    sessionKey: aliceSessionKey,
    sessionId: initResult.sessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: seq1,
    plaintext: "Hello Bob, this channel is post-quantum secure.",
    keyId: "test-handshake-a",
  });
  const decrypted = await decryptMessage({
    sessionKey: bobSessionKey,
    sessionId: initResult.sessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: encrypted.sequence_number,
    nonceHex: encrypted.nonce,
    ciphertextHex: encrypted.ciphertext,
    keyId: "test-handshake-a",
  });
  assert(decrypted.plaintext === "Hello Bob, this channel is post-quantum secure.", "plaintext round-trips correctly: \"" + decrypted.plaintext + "\"");
  assert(decrypted.replayWarning === false, "first message: no replay warning");

  console.log("--- 9. Tampered ciphertext is rejected (AEAD tag check) ---");
  try {
    await decryptMessage({
      sessionKey: bobSessionKey,
      sessionId: initResult.sessionId,
      sender: "alice",
      recipient: "bob",
      sequenceNumber: encrypted.sequence_number,
      nonceHex: encrypted.nonce,
      ciphertextHex: encrypted.ciphertext.replace(/^../, "ff"),
      keyId: "test-handshake-a",
    });
    throw new Error("should have thrown");
  } catch (err) {
    assert(err.message === "AEAD_VERIFY_FAILED", "tampered ciphertext correctly rejected: " + err.message);
  }

  console.log("--- 10. Wrong AAD (metadata tamper) is rejected ---");
  try {
    await decryptMessage({
      sessionKey: bobSessionKey,
      sessionId: initResult.sessionId,
      sender: "alice",
      recipient: "MALLORY",  // tampered recipient -> AAD mismatch
      sequenceNumber: encrypted.sequence_number,
      nonceHex: encrypted.nonce,
      ciphertextHex: encrypted.ciphertext,
      keyId: "test-handshake-a",
    });
    throw new Error("should have thrown");
  } catch (err) {
    assert(err.message === "AEAD_VERIFY_FAILED", "AAD tamper (recipient field) correctly rejected: " + err.message);
  }

  console.log("--- 11. Replay detection: resend same sequence number ---");
  const replayDecrypt = await decryptMessage({
    sessionKey: bobSessionKey,
    sessionId: initResult.sessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: encrypted.sequence_number,  // same seq again
    nonceHex: encrypted.nonce,
    ciphertextHex: encrypted.ciphertext,
    keyId: "test-handshake-a",
  });
  assert(replayDecrypt.replayWarning === true, "repeated sequence number flagged as replay");

  console.log("--- 12. Session key persists across a fresh unwrap (reload simulation) ---");
  const bobSessionKeyReloaded = await loadSessionKeyFor(respResult.sessionId, bobWrapKey);
  const decrypted2 = await decryptMessage({
    sessionKey: bobSessionKeyReloaded,
    sessionId: initResult.sessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: encrypted.sequence_number + 100, // avoid replay flag from step 11, just checking key works
    nonceHex: encrypted.nonce,
    ciphertextHex: encrypted.ciphertext,
  }).catch(e => e.message);
  // AAD includes sequence number so this will actually fail AEAD (expected) -
  // real check is that the key itself imports/decrypts correctly:
  const correctSeqDecrypt = await decryptMessage({
    sessionKey: bobSessionKeyReloaded,
    sessionId: initResult.sessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: encrypted.sequence_number,
    nonceHex: encrypted.nonce,
    ciphertextHex: encrypted.ciphertext,
    keyId: "test-handshake-a",
  });
  assert(correctSeqDecrypt.plaintext === "Hello Bob, this channel is post-quantum secure.", "reloaded/re-unwrapped session key still decrypts correctly");

  console.log("--- 13. Session-key versioning preserves old ciphertext after re-handshake ---");
  const versionedSessionId = "alice|bob-version-test";
  const version1Key = await establishSessionKey({
    sharedSecret: initResult.sharedSecret,
    sessionId: versionedSessionId,
    wrappingKey: aliceWrapKey,
    handshakeId: "version-one",
  });
  const oldCipher = await encryptMessage({
    sessionKey: version1Key,
    sessionId: versionedSessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: 1,
    plaintext: "Message from the first key",
    keyId: "version-one",
  });
  // A different shared secret simulates an independent/re-established KEM handshake.
  const differentSecret = new Uint8Array(initResult.sharedSecret).map((b, i) => b ^ ((i % 251) + 1));
  const version2Key = await establishSessionKey({
    sharedSecret: differentSecret,
    sessionId: versionedSessionId,
    wrappingKey: aliceWrapKey,
    handshakeId: "version-two",
  });
  const restoredVersion1 = await loadSessionKeyFor(versionedSessionId, aliceWrapKey, "version-one");
  const oldDecoded = await decryptMessage({
    sessionKey: restoredVersion1,
    sessionId: versionedSessionId,
    sender: "alice",
    recipient: "bob",
    sequenceNumber: oldCipher.sequence_number,
    nonceHex: oldCipher.nonce,
    ciphertextHex: oldCipher.ciphertext,
    keyId: "version-one",
    trackSequence: false,
  });
  assert(oldDecoded.plaintext === "Message from the first key", "older ciphertext remains decryptable using its handshake key version");

  console.log("--- 13b. History remains decryptable when an API response omits key_id ---");
  const aliceAfterRelogin = await unlockIdentity("alice", "alice-password-123");
  const restoredWithMissingMetadata = await decryptStoredMessage({
    message: {
      // Simulate an older / mismatched history endpoint omitting key_id.
      sender: "alice",
      recipient: "bob",
      sequence_number: oldCipher.sequence_number,
      nonce: oldCipher.nonce,
      ciphertext: oldCipher.ciphertext,
    },
    sessionId: versionedSessionId,
    wrappingKey: aliceAfterRelogin.wrappingKey,
    activeSessionKey: version2Key,
    activeKeyId: "version-two",
  });
  assert(
    restoredWithMissingMetadata.plaintext === "Message from the first key" && restoredWithMissingMetadata.keyIdUsed === "version-one",
    "re-login unwrap + retained key versions recover history even if key_id metadata is missing"
  );
  try {
    await decryptMessage({
      sessionKey: version2Key,
      sessionId: versionedSessionId,
      sender: "alice",
      recipient: "bob",
      sequenceNumber: oldCipher.sequence_number,
      nonceHex: oldCipher.nonce,
      ciphertextHex: oldCipher.ciphertext,
      keyId: "version-two",
      trackSequence: false,
    });
    throw new Error("should have thrown");
  } catch (err) {
    assert(err.message === "AEAD_VERIFY_FAILED", "key-version mismatch fails AEAD authentication");
  }

  console.log("\nALL CRYPTO STACK TESTS PASSED");
}

main().catch((err) => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
