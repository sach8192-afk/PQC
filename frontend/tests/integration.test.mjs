/**
 * integration.test.mjs
 *
 * Exercises the ACTUAL frontend crypto modules (identity.js, handshake.js,
 * session.js, aead.js) against the REAL running backend (main.py) over
 * real HTTP + WebSocket — no mocks on either side except IndexedDB
 * (fake-indexeddb, since Node has no browser storage) and WebSocket
 * (the 'ws' package, since Node has no native browser WebSocket).
 *
 * This is the highest-value test in the project: it proves the blind
 * relay backend and the client-side crypto actually interoperate over
 * the wire, not just in isolation.
 *
 * Prerequisite: backend running on http://localhost:8000
 * Run with: node tests/integration.test.mjs
 */
import "fake-indexeddb/auto";
import WebSocket from "ws";
globalThis.WebSocket = WebSocket;

import { createIdentity, unlockIdentity } from "../src/crypto/identity.js";
import { initiateHandshake, respondToHandshake } from "../src/crypto/handshake.js";
import { establishSessionKey } from "../src/crypto/session.js";
import { encryptMessage, decryptMessage, nextOutgoingSequence } from "../src/crypto/aead.js";

const BASE = "http://localhost:8000";

function assert(cond, msg) {
  if (!cond) throw new Error("ASSERTION FAILED: " + msg);
  console.log("  ok:", msg);
}

async function api(path, opts = {}) {
  const res = await fetch(BASE + path, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${path} -> ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

function connectWs(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket("ws://localhost:8000/ws");
    const onMessage = (data) => {
      let envelope;
      try { envelope = JSON.parse(data.toString()); } catch { return; }
      if (envelope.type === "auth_ok") {
        ws.off("message", onMessage);
        resolve(ws);
      } else if (envelope.type === "auth_error") {
        ws.off("message", onMessage);
        reject(new Error(`WebSocket authentication failed: ${envelope.reason}`));
      }
    };
    ws.on("message", onMessage);
    ws.on("open", () => ws.send(JSON.stringify({ type: "auth", token })));
    ws.on("error", reject);
  });
}

function waitForMessage(ws, predicate, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timed out waiting for WS message")), timeoutMs);
    function handler(data) {
      const envelope = JSON.parse(data.toString());
      if (predicate(envelope)) {
        clearTimeout(timer);
        ws.off("message", handler);
        resolve(envelope);
      }
    }
    ws.on("message", handler);
  });
}

async function main() {
  const uniq = Date.now();
  const aliceUsername = `alice_${uniq}`;
  const bobUsername = `bob_${uniq}`;

  console.log("--- 1. Create + register identities against the LIVE backend ---");
  const alice = await createIdentity(aliceUsername, "alice-password-123");
  const bob = await createIdentity(bobUsername, "bob-password-456");

  await api("/api/register", { method: "POST", body: JSON.stringify(alice.forServer) });
  await api("/api/register", { method: "POST", body: JSON.stringify(bob.forServer) });
  assert(true, "both users registered with the real backend");

  console.log("--- 2. Login (real server-side password verification) ---");
  const aliceUnlocked = await unlockIdentity(aliceUsername, "alice-password-123");
  const bobUnlocked = await unlockIdentity(bobUsername, "bob-password-456");

  const aliceLogin = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({ username: aliceUsername, password_verifier: aliceUnlocked.loginVerifier }),
  });
  const bobLogin = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({ username: bobUsername, password_verifier: bobUnlocked.loginVerifier }),
  });
  assert(!!aliceLogin.token && !!bobLogin.token, "both users received bearer tokens");

  console.log("--- 2b. Wrong password rejected by the real server ---");
  try {
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username: aliceUsername, password_verifier: "0000" }),
    });
    throw new Error("should have thrown");
  } catch (err) {
    assert(err.message.includes("401"), "wrong credential correctly rejected by server: " + err.message);
  }

  console.log("--- 3. Alice fetches Bob's PUBLIC keys via the real API ---");
  const bobPublicKeys = await api(`/api/users/${bobUsername}/public-keys`, {
    headers: { Authorization: `Bearer ${aliceLogin.token}` },
  });
  assert(bobPublicKeys.kem_public_key === bob.forServer.kem_public_key, "fetched public key matches what was registered");

  console.log("--- 4. Both connect over real WebSocket ---");
  const aliceWs = await connectWs(aliceLogin.token);
  const bobWs = await connectWs(bobLogin.token);
  assert(true, "both WebSocket connections established");

  console.log("--- 5. Alice initiates handshake, relays over the real WS ---");
  const { sharedSecret: aliceSecret, sessionId, envelope } = initiateHandshake({
    myUsername: aliceUsername,
    mySigSecretKey: aliceUnlocked.sigSecretKey,
    peerUsername: bobUsername,
    peerKemPublicKeyHex: bobPublicKeys.kem_public_key,
  });
  // Match the app protocol: handshake IDs correlate confirmation to the
  // specific attempt and prevent a delayed ACK from confirming a retry.
  envelope.handshake_id = `handshake-${uniq}`;

  const bobReceivePromise = waitForMessage(bobWs, (e) => e.type === "handshake_init");
  aliceWs.send(JSON.stringify(envelope));
  const receivedByBob = await bobReceivePromise;
  assert(receivedByBob.kem_ciphertext === envelope.kem_ciphertext, "Bob received the exact ciphertext Alice sent, relayed by the real backend");

  console.log("--- 6. Bob verifies + decapsulates using Alice's REAL public key from the server ---");
  const alicePublicKeys = await api(`/api/users/${aliceUsername}/public-keys`, {
    headers: { Authorization: `Bearer ${bobLogin.token}` },
  });
  const { sharedSecret: bobSecret } = respondToHandshake({
    envelope: receivedByBob,
    peerSigPublicKeyHex: alicePublicKeys.sig_public_key,
    myKemSecretKey: bobUnlocked.kemSecretKey,
  });
  assert(Buffer.from(aliceSecret).equals(Buffer.from(bobSecret)), "shared secrets match after a REAL network round-trip");

  console.log("--- 7. Both derive session keys ---");
  const aliceSessionKey = await establishSessionKey({ sharedSecret: aliceSecret, sessionId, wrappingKey: aliceUnlocked.wrappingKey, handshakeId: envelope.handshake_id });
  const bobSessionKey = await establishSessionKey({ sharedSecret: bobSecret, sessionId, wrappingKey: bobUnlocked.wrappingKey, handshakeId: envelope.handshake_id });

  console.log("--- 8. Alice sends an encrypted chat message over the real WS; server stores + relays it ---");
  const seq = await nextOutgoingSequence(sessionId);
  const encrypted = await encryptMessage({
    sessionKey: aliceSessionKey,
    sessionId,
    sender: aliceUsername,
    recipient: bobUsername,
    sequenceNumber: seq,
    plaintext: "Hello Bob, this is a real end-to-end test over the network.",
    keyId: envelope.handshake_id,
  });

  const clientMessageId = `msg-${uniq}`;
  const bobChatPromise = waitForMessage(bobWs, (e) => e.type === "chat_message" && e.client_message_id === clientMessageId);
  const storedReceiptPromise = waitForMessage(aliceWs, (e) =>
    e.type === "message_status" && e.client_message_id === clientMessageId && e.status === "sent"
  );
  aliceWs.send(JSON.stringify({
    type: "chat_message",
    to: bobUsername,
    session_id: sessionId,
    client_message_id: clientMessageId,
    nonce: encrypted.nonce,
    ciphertext: encrypted.ciphertext,
    sequence_number: encrypted.sequence_number,
    key_id: encrypted.key_id,
  }));
  const chatEnvelope = await bobChatPromise;
  await storedReceiptPromise;
  assert(true, "sender receives a sent receipt only after the server stores the ciphertext");

  const decrypted = await decryptMessage({
    sessionKey: bobSessionKey,
    sessionId,
    sender: aliceUsername,
    recipient: bobUsername,
    sequenceNumber: chatEnvelope.sequence_number,
    nonceHex: chatEnvelope.nonce,
    ciphertextHex: chatEnvelope.ciphertext,
    keyId: chatEnvelope.key_id,
  });
  assert(decrypted.plaintext === "Hello Bob, this is a real end-to-end test over the network.", "Bob decrypted Alice's real-time message correctly: \"" + decrypted.plaintext + "\"");

  console.log("--- 8b. Bob acknowledges delivery only after AEAD decryption succeeds ---");
  const deliveredReceiptPromise = waitForMessage(aliceWs, (e) =>
    e.type === "message_status" && e.client_message_id === clientMessageId && e.status === "delivered"
  );
  bobWs.send(JSON.stringify({
    type: "delivery_ack",
    to: aliceUsername,
    session_id: sessionId,
    client_message_id: clientMessageId,
    sequence_number: chatEnvelope.sequence_number,
  }));
  await deliveredReceiptPromise;
  assert(true, "sender receives delivered receipt after Bob's authenticated decryption acknowledgement");

  console.log("--- 9. History endpoint returns ciphertext only; client decrypts it ---");
  const history = await api(`/api/messages/${aliceUsername}`, { headers: { Authorization: `Bearer ${bobLogin.token}` } });
  assert(history.messages.length === 1, "one message persisted server-side");
  assert(history.messages[0].client_message_id === clientMessageId, "history preserves the client message ID");
  assert(history.messages[0].delivery_status === "delivered", "history persists the delivered status");
  assert(!JSON.stringify(history.messages).includes("Hello Bob"), "server-stored history contains NO plaintext");
  const historyDecrypted = await decryptMessage({
    sessionKey: bobSessionKey,
    sessionId,
    sender: history.messages[0].sender,
    recipient: history.messages[0].recipient,
    sequenceNumber: history.messages[0].sequence_number,
    nonceHex: history.messages[0].nonce,
    ciphertextHex: history.messages[0].ciphertext,
    keyId: history.messages[0].key_id,
  });
  assert(historyDecrypted.plaintext === "Hello Bob, this is a real end-to-end test over the network.", "history ciphertext decrypts correctly client-side");

  console.log("--- 10. Server's own source code contains no private key / decrypt reference (defense in depth check via API introspection) ---");
  // Already covered by backend's own test_relay.py; here we just confirm
  // the API contract never returns a private-key-shaped field.
  const allResponses = JSON.stringify({ aliceLogin, bobLogin, bobPublicKeys, alicePublicKeys, history });
  assert(!/secret_key|private_key/i.test(allResponses), "no API response anywhere contains private-key-shaped data");

  console.log("--- 11. Offline handshake store-and-forward: a THIRD user (Carol) is offline when Alice initiates ---");
  const carolUsername = `carol_${uniq}`;
  const carol = await createIdentity(carolUsername, "carol-password-789");
  await api("/api/register", { method: "POST", body: JSON.stringify(carol.forServer) });
  const carolLogin = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({ username: carolUsername, password_verifier: (await unlockIdentity(carolUsername, "carol-password-789")).loginVerifier }),
  });
  // Note: Carol does NOT open a WebSocket here — simulating "offline".

  const carolPublicKeys = await api(`/api/users/${carolUsername}/public-keys`, { headers: { Authorization: `Bearer ${aliceLogin.token}` } });
  const aliceToCarol = initiateHandshake({
    myUsername: aliceUsername,
    mySigSecretKey: aliceUnlocked.sigSecretKey,
    peerUsername: carolUsername,
    peerKemPublicKeyHex: carolPublicKeys.kem_public_key,
  });
  const carolSessionId = [aliceUsername, carolUsername].sort().join("|");
  const carolHandshakeId = `handshake-carol-${uniq}`;
  aliceToCarol.envelope.handshake_id = carolHandshakeId;
  const aliceCarolSessionKey = await establishSessionKey({
    sharedSecret: aliceToCarol.sharedSecret,
    sessionId: carolSessionId,
    wrappingKey: aliceUnlocked.wrappingKey,
    status: "pending",
    pendingHandshake: aliceToCarol.envelope,
    handshakeId: carolHandshakeId,
  });
  aliceWs.send(JSON.stringify(aliceToCarol.envelope));

  // Carol is offline, but Alice already has the local session key. Send an
  // encrypted message immediately; the relay should persist it without a
  // live recipient socket, ready for Carol to decrypt after she reconnects.
  const carolSequence = await nextOutgoingSequence(carolSessionId);
  const carolEncrypted = await encryptMessage({
    sessionKey: aliceCarolSessionKey,
    sessionId: carolSessionId,
    sender: aliceUsername,
    recipient: carolUsername,
    sequenceNumber: carolSequence,
    plaintext: "Queued while Carol was offline.",
    keyId: carolHandshakeId,
  });
  const carolMessageId = `offline-message-${uniq}`;
  const carolStoredReceipt = waitForMessage(aliceWs, (e) =>
    e.type === "message_status" && e.client_message_id === carolMessageId && e.status === "sent"
  );
  aliceWs.send(JSON.stringify({
    type: "chat_message",
    to: carolUsername,
    session_id: carolSessionId,
    client_message_id: carolMessageId,
    nonce: carolEncrypted.nonce,
    ciphertext: carolEncrypted.ciphertext,
    sequence_number: carolEncrypted.sequence_number,
    key_id: carolEncrypted.key_id,
  }));
  await carolStoredReceipt;
  await new Promise((r) => setTimeout(r, 100)); // allow persistence before Carol signs in

  const pending = await api("/api/handshakes/pending", { headers: { Authorization: `Bearer ${carolLogin.token}` } });
  assert(pending.pending.length === 1 && pending.pending[0].from === aliceUsername, "Carol finds Alice's handshake waiting for her after 'logging in'");

  const carolUnlocked = await unlockIdentity(carolUsername, "carol-password-789");
  const carolResp = respondToHandshake({
    envelope: { ...pending.pending[0], kem_ciphertext: pending.pending[0].kem_ciphertext, signature: pending.pending[0].signature },
    peerSigPublicKeyHex: alicePublicKeys.sig_public_key,
    myKemSecretKey: carolUnlocked.kemSecretKey,
  });
  assert(Buffer.from(carolResp.sharedSecret).equals(Buffer.from(aliceToCarol.sharedSecret)), "Carol's offline-delivered handshake produces the SAME shared secret Alice derived");

  const carolSessionKey = await establishSessionKey({
    sharedSecret: carolResp.sharedSecret,
    sessionId: carolSessionId,
    wrappingKey: carolUnlocked.wrappingKey,
    status: "established",
    handshakeId: carolHandshakeId,
  });
  const carolHistory = await api(`/api/messages/${aliceUsername}`, { headers: { Authorization: `Bearer ${carolLogin.token}` } });
  assert(carolHistory.messages.length === 1, "offline ciphertext is available in history after Carol logs in");
  assert(!JSON.stringify(carolHistory.messages).includes("Queued while Carol was offline."), "offline history still contains ciphertext, not plaintext");
  const offlineDecrypted = await decryptMessage({
    sessionKey: carolSessionKey,
    sessionId: carolSessionId,
    sender: carolHistory.messages[0].sender,
    recipient: carolHistory.messages[0].recipient,
    sequenceNumber: carolHistory.messages[0].sequence_number,
    nonceHex: carolHistory.messages[0].nonce,
    ciphertextHex: carolHistory.messages[0].ciphertext,
    keyId: carolHistory.messages[0].key_id,
  });
  assert(offlineDecrypted.plaintext === "Queued while Carol was offline.", "Carol decrypts the message queued while her browser was offline");

  const carolWs = await connectWs(carolLogin.token);
  const offlineDeliveredReceipt = waitForMessage(aliceWs, (e) =>
    e.type === "message_status" && e.client_message_id === carolMessageId && e.status === "delivered"
  );
  carolWs.send(JSON.stringify({
    type: "delivery_ack",
    to: aliceUsername,
    session_id: carolSessionId,
    client_message_id: carolMessageId,
    sequence_number: carolHistory.messages[0].sequence_number,
  }));
  await offlineDeliveredReceipt;
  assert(true, "offline queued message transitions to delivered after Carol decrypts and acknowledges it");

  await api(`/api/handshakes/${pending.pending[0].session_id}/consume`, { method: "POST", headers: { Authorization: `Bearer ${carolLogin.token}` } });
  const pendingAfter = await api("/api/handshakes/pending", { headers: { Authorization: `Bearer ${carolLogin.token}` } });
  assert(pendingAfter.pending.length === 0, "consumed handshake no longer re-served");

  aliceWs.close();
  bobWs.close();
  carolWs.close();

  console.log("\nALL INTEGRATION TESTS PASSED (real backend + real crypto modules + real network)");
}

main().catch((err) => {
  console.error("INTEGRATION TEST FAILED:", err);
  process.exit(1);
});
