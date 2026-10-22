/**
 * HKDF-derived session keys, wrapped at rest in IndexedDB.
 *
 * IMPORTANT: IndexedDB is scoped to a browser origin, not to a username. Two
 * accounts used from the same browser profile must therefore never share the
 * same storage key for a conversation. Logical `sessionId` remains the
 * canonical Alice|Bob value used by HKDF/AAD and the relay; `storageId` is
 * additionally scoped to the local account for persistence only.
 */
import {
  deriveSessionKeyRawBytes,
  importAesGcmKey,
  aeadEncrypt,
  aeadDecrypt,
  bytesToHex,
  hexToBytes,
} from "./webcrypto.js";
import {
  saveSessionKey,
  loadSessionKey,
  updateSessionKeyRecord,
  saveSessionKeyVersion,
  loadSessionKeyVersion,
  listSessionKeyVersions,
  updateSessionKeyVersion,
  sessionKeyVersionId,
  localSessionStorageId,
} from "./store.js";

function idForRecord(record) {
  return record?.handshake_id || record?.pending_handshake?.handshake_id || "__legacy__";
}

function storageIdFor(sessionId, ownerUsername = null) {
  return localSessionStorageId(sessionId, ownerUsername);
}

async function canUnlock(record, wrappingKey) {
  if (!record?.wrapped_key || !wrappingKey) return false;
  try {
    const rawKey = await aeadDecrypt(
      wrappingKey,
      hexToBytes(record.wrapped_key.nonce),
      hexToBytes(record.wrapped_key.ciphertext)
    );
    await importAesGcmKey(rawKey);
    return true;
  } catch {
    return false;
  }
}

async function archiveVersion(storageId, record, logicalSessionId = null, ownerUsername = null) {
  if (!record?.wrapped_key) return;
  const handshakeId = idForRecord(record);
  const existing = await loadSessionKeyVersion(storageId, handshakeId);
  if (existing) return;
  await saveSessionKeyVersion({
    key_id: sessionKeyVersionId(storageId, handshakeId),
    session_id: storageId,
    conversation_id: logicalSessionId || record.conversation_id || storageId,
    owner_username: ownerUsername || record.owner_username || null,
    handshake_id: handshakeId,
    wrapped_key: record.wrapped_key,
    established_at: record.established_at || null,
    status: record.status || "legacy",
    pending_handshake: record.pending_handshake || null,
    archived_at: new Date().toISOString(),
  });
}

/**
 * Migrate a pre-account-scoping record only when its wrapped key can be
 * unlocked with this account's wrapping key. This avoids accidentally
 * adopting another user's IndexedDB record after a shared-browser test.
 */
async function migrateLegacyRecords(sessionId, storageId, wrappingKey, ownerUsername) {
  if (storageId === sessionId || !wrappingKey) return;

  const scopedActive = await loadSessionKey(storageId);
  if (!scopedActive) {
    const legacyActive = await loadSessionKey(sessionId).catch(() => null);
    if (legacyActive && await canUnlock(legacyActive, wrappingKey)) {
      const migrated = {
        ...legacyActive,
        session_id: storageId,
        conversation_id: sessionId,
        owner_username: ownerUsername,
      };
      // Treat a previously active key as a history candidate first, not as
      // authority to start sending. Older builds shared this IndexedDB slot
      // between accounts and could store a key that no longer matches the
      // relay's winning handshake. A still-pending handshake may be resumed
      // because its exact envelope and key were persisted together.
      await archiveVersion(storageId, migrated, sessionId, ownerUsername);
      if (legacyActive.status === "pending" && legacyActive.pending_handshake?.handshake_id) {
        await saveSessionKey(migrated);
      }
    }
  }

  // Older builds may have multiple unscoped key versions. Migrate only those
  // that authenticate under this user's wrapping key; skip other accounts'
  // records without exposing key material or weakening AEAD checks.
  const oldVersions = await listSessionKeyVersions(sessionId).catch(() => []);
  for (const version of oldVersions) {
    if (!(await canUnlock(version, wrappingKey))) continue;
    const newKeyId = sessionKeyVersionId(storageId, version.handshake_id);
    if (await loadSessionKeyVersion(storageId, version.handshake_id)) continue;
    await saveSessionKeyVersion({
      ...version,
      key_id: newKeyId,
      session_id: storageId,
      conversation_id: sessionId,
      owner_username: ownerUsername,
    });
  }
}

/** Derives, wraps, and persists the key for a specific handshake. */
export async function establishSessionKey({
  sharedSecret,
  sessionId,
  wrappingKey,
  status = "pending",
  pendingHandshake = null,
  handshakeId = pendingHandshake?.handshake_id || null,
  ownerUsername = null,
}) {
  const storageId = storageIdFor(sessionId, ownerUsername);
  await migrateLegacyRecords(sessionId, storageId, wrappingKey, ownerUsername);
  const existing = await loadSessionKey(storageId);
  if (existing?.wrapped_key) {
    const oldId = idForRecord(existing);
    if (oldId !== (handshakeId || "__legacy__")) {
      await archiveVersion(storageId, existing, sessionId, ownerUsername);
    }
  }

  const rawKey = await deriveSessionKeyRawBytes(sharedSecret, sessionId);
  const wrapped = await aeadEncrypt(wrappingKey, rawKey);
  const wrappedKey = {
    nonce: bytesToHex(wrapped.nonce),
    ciphertext: bytesToHex(wrapped.ciphertext),
  };
  const establishedAt = new Date().toISOString();
  const activeRecord = {
    session_id: storageId,
    conversation_id: sessionId,
    owner_username: ownerUsername,
    handshake_id: handshakeId,
    active_key_id: handshakeId,
    wrapped_key: wrappedKey,
    established_at: establishedAt,
    status,
    pending_handshake: status === "pending" ? pendingHandshake : null,
  };
  await saveSessionKey(activeRecord);

  const versionId = handshakeId || "__legacy__";
  await saveSessionKeyVersion({
    key_id: sessionKeyVersionId(storageId, versionId),
    session_id: storageId,
    conversation_id: sessionId,
    owner_username: ownerUsername,
    handshake_id: versionId,
    wrapped_key: wrappedKey,
    established_at: establishedAt,
    status,
    pending_handshake: status === "pending" ? pendingHandshake : null,
  });
  return importAesGcmKey(rawKey);
}

/** Loads a specific handshake key, or the current account's active key. */
export async function loadSessionKeyFor(sessionId, wrappingKey, handshakeId = null, ownerUsername = null) {
  const storageId = storageIdFor(sessionId, ownerUsername);
  await migrateLegacyRecords(sessionId, storageId, wrappingKey, ownerUsername);

  let record;
  if (handshakeId) {
    record = await loadSessionKeyVersion(storageId, handshakeId);
    if (!record) {
      // Migrate an active record created by older v2 builds into a version
      // record, but only within this account's namespace.
      const active = await loadSessionKey(storageId);
      if (active && idForRecord(active) === handshakeId) {
        await archiveVersion(storageId, active, sessionId, ownerUsername);
        record = await loadSessionKeyVersion(storageId, handshakeId);
      }
    }
  } else {
    record = await loadSessionKey(storageId);
    if (record?.wrapped_key) await archiveVersion(storageId, record, sessionId, ownerUsername);
  }
  if (!record?.wrapped_key) return null;
  const rawKey = await aeadDecrypt(
    wrappingKey,
    hexToBytes(record.wrapped_key.nonce),
    hexToBytes(record.wrapped_key.ciphertext)
  );
  return importAesGcmKey(rawKey);
}

/** Returns active key ID (null means a legacy key without a handshake ID). */
export async function loadActiveSessionKeyIdFor(sessionId, ownerUsername = null, wrappingKey = null) {
  const storageId = storageIdFor(sessionId, ownerUsername);
  await migrateLegacyRecords(sessionId, storageId, wrappingKey, ownerUsername);
  const record = await loadSessionKey(storageId);
  return record?.handshake_id || record?.pending_handshake?.handshake_id || null;
}

/** Loads every locally available key for fallback decryption of old history. */
export async function loadSessionKeyCandidatesFor(sessionId, wrappingKey, ownerUsername = null) {
  const storageId = storageIdFor(sessionId, ownerUsername);
  await migrateLegacyRecords(sessionId, storageId, wrappingKey, ownerUsername);
  const candidates = [];
  const seen = new Set();
  const active = await loadSessionKey(storageId);
  if (active?.wrapped_key) {
    const activeId = idForRecord(active);
    try {
      await archiveVersion(storageId, active, sessionId, ownerUsername);
      const key = await loadSessionKeyFor(sessionId, wrappingKey, activeId, ownerUsername);
      if (key) {
        candidates.push({ keyId: activeId === "__legacy__" ? null : activeId, key });
        seen.add(activeId);
      }
    } catch (err) {
      console.warn("Could not unlock active session-key version; trying archived versions:", err?.message || err);
    }
  }
  const versions = await listSessionKeyVersions(storageId);
  for (const version of versions) {
    if (seen.has(version.handshake_id)) continue;
    try {
      const key = await loadSessionKeyFor(sessionId, wrappingKey, version.handshake_id, ownerUsername);
      if (key) {
        candidates.push({ keyId: version.handshake_id === "__legacy__" ? null : version.handshake_id, key });
        seen.add(version.handshake_id);
      }
    } catch (err) {
      console.warn("Could not unlock a stored session-key version:", err?.message || err);
    }
  }
  return candidates;
}

export async function loadSessionStatusFor(sessionId, handshakeId = null, ownerUsername = null, wrappingKey = null) {
  const storageId = storageIdFor(sessionId, ownerUsername);
  await migrateLegacyRecords(sessionId, storageId, wrappingKey, ownerUsername);
  if (handshakeId) {
    const record = await loadSessionKeyVersion(storageId, handshakeId);
    if (record) return record.status || "established";
  }
  const record = await loadSessionKey(storageId);
  return record?.status || "established";
}

export async function loadPendingHandshakeFor(sessionId, ownerUsername = null, wrappingKey = null) {
  const storageId = storageIdFor(sessionId, ownerUsername);
  await migrateLegacyRecords(sessionId, storageId, wrappingKey, ownerUsername);
  const record = await loadSessionKey(storageId);
  return record?.pending_handshake || null;
}

/** Confirm only the key version associated with this handshake. */
export async function markSessionEstablished(sessionId, handshakeId = null, ownerUsername = null) {
  const storageId = storageIdFor(sessionId, ownerUsername);
  const updates = {
    status: "established",
    pending_handshake: null,
    peer_confirmed_at: new Date().toISOString(),
  };
  const effectiveId = handshakeId || await loadActiveSessionKeyIdFor(sessionId, ownerUsername);
  if (effectiveId) {
    await updateSessionKeyVersion(storageId, effectiveId, updates);
    const activeId = await loadActiveSessionKeyIdFor(sessionId, ownerUsername);
    if (activeId === effectiveId) await updateSessionKeyRecord(storageId, updates);
    return;
  }
  await updateSessionKeyRecord(storageId, updates);
}
