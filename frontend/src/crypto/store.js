/**
 * IndexedDB persistence for locally wrapped key material.
 * Private keys and session keys are always wrapped before persistence.
 */
import { openDB } from "idb";

const DB_NAME = "pqchat";
const DB_VERSION = 2;

async function getDb() {
  return openDB(DB_NAME, DB_VERSION, {
    upgrade(db) {
      if (!db.objectStoreNames.contains("identities")) {
        db.createObjectStore("identities", { keyPath: "username" });
      }
      // One active/latest key record per conversation, retained for the
      // existing application API and the current composer key.
      if (!db.objectStoreNames.contains("sessionKeys")) {
        db.createObjectStore("sessionKeys", { keyPath: "session_id" });
      }
      // One wrapped key per handshake/session epoch. This prevents a later
      // handshake from destroying the only local copy of the key needed to
      // decrypt older ciphertext in the same conversation.
      if (!db.objectStoreNames.contains("sessionKeyVersions")) {
        db.createObjectStore("sessionKeyVersions", { keyPath: "key_id" });
      }
      if (!db.objectStoreNames.contains("sequenceState")) {
        db.createObjectStore("sequenceState", { keyPath: "session_id" });
      }
    },
  });
}

export async function saveIdentity(record) {
  const db = await getDb();
  await db.put("identities", record);
}

export async function loadIdentity(username) {
  const db = await getDb();
  return db.get("identities", username);
}

export async function saveSessionKey(record) {
  const db = await getDb();
  await db.put("sessionKeys", record);
}

export async function loadSessionKey(sessionId) {
  const db = await getDb();
  return db.get("sessionKeys", sessionId);
}

// IndexedDB belongs to the browser origin, not to an application account.
// Include the local owner so two usernames tested in one browser profile do
// not overwrite one another's password-wrapped session keys or counters.
export function localSessionStorageId(sessionId, ownerUsername = null) {
  return ownerUsername ? JSON.stringify([ownerUsername, sessionId]) : sessionId;
}

export function sessionKeyVersionId(storageSessionId, handshakeId) {
  return `${storageSessionId}::${handshakeId}`;
}

export async function saveSessionKeyVersion(record) {
  const db = await getDb();
  await db.put("sessionKeyVersions", record);
}

export async function loadSessionKeyVersion(sessionId, handshakeId) {
  const db = await getDb();
  return db.get("sessionKeyVersions", sessionKeyVersionId(sessionId, handshakeId));
}

export async function listSessionKeyVersions(sessionId) {
  const db = await getDb();
  return (await db.getAll("sessionKeyVersions")).filter((record) => record.session_id === sessionId);
}

export async function getSequenceState(sessionId) {
  const db = await getDb();
  return db.get("sequenceState", sessionId);
}

export async function setSequenceState(sessionId, state) {
  const db = await getDb();
  await db.put("sequenceState", { session_id: sessionId, ...state });
}

export async function updateSessionKeyRecord(sessionId, updates) {
  const db = await getDb();
  const current = await db.get("sessionKeys", sessionId);
  if (!current) return null;
  const updated = { ...current, ...updates };
  await db.put("sessionKeys", updated);
  return updated;
}

export async function updateSessionKeyVersion(sessionId, handshakeId, updates) {
  const db = await getDb();
  const keyId = sessionKeyVersionId(sessionId, handshakeId);
  const current = await db.get("sessionKeyVersions", keyId);
  if (!current) return null;
  const updated = { ...current, ...updates };
  await db.put("sessionKeyVersions", updated);
  return updated;
}
