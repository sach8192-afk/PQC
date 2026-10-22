"""
main.py

PQChat v2 backend — a blind relay.

This process never generates, holds, or sees a private key, never
performs a KEM encapsulation/decapsulation, never runs an AEAD decrypt,
and never signs or verifies anything. Its job is authentication,
routing, and storing opaque bytes. See tests/test_relay.py, which
enforces this at the code level, not just in prose.

REST:
  POST /api/register              store username + public keys + server credential
  POST /api/login                 verify credential, issue bearer token
  POST /api/logout
  GET  /api/users/search?q=...    search usernames (min 3 chars, max 10 results)
  GET  /api/users/{username}/public-keys
  GET  /api/messages/{peer}    return stored ciphertext history in timestamp order
  GET  /api/conversations      inbox summaries + per-user unread counts
  POST /api/conversations/{peer}/read mark inbound messages as read

WebSocket /ws (first frame authenticates):
  Relays opaque handshake/message envelopes and emits delivery status
  events. It stores ciphertext plus routing metadata only. A `sent`
  status means the backend persisted the message; `delivered` means the
  recipient client acknowledged successful local authentication/decryption.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import asyncio
import os
import re

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import auth
import db
from models import RegisterRequest, LoginRequest, PublicKeysResponse, MessageOut


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.ensure_indexes()
    yield


app = FastAPI(title="PQChat v2 API — blind relay", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# username -> live WebSocket, for real-time relay. Server-local, not
# persisted (a restart just means clients reconnect and re-fetch queued
# envelopes / history from Mongo, same as any relay).
WS_CONNECTIONS: dict[str, WebSocket] = {}
# Serializes handshake reservation per conversation. PQChat v2 is a single
# backend process; this prevents crossed handshake_init messages from
# overwriting each other's session record within that process.
_HANDSHAKE_LOCKS: dict[str, asyncio.Lock] = {}


def _handshake_lock(session_id: str) -> asyncio.Lock:
    lock = _HANDSHAKE_LOCKS.get(session_id)
    if lock is None:
        lock = asyncio.Lock()
        _HANDSHAKE_LOCKS[session_id] = lock
    return lock


def require_auth(authorization: str | None) -> str:
    """Returns the authenticated username. Never touches key material —
    this only proves which account owns the connection."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    username = auth.resolve_token(authorization.removeprefix("Bearer "))
    if not username:
        raise HTTPException(401, "Invalid or expired session — please log in again")
    return username


async def _find_one(collection, query):
    if db.USE_MOCK:
        return collection.find_one(query)
    return await collection.find_one(query)


async def _insert_one(collection, doc):
    if db.USE_MOCK:
        return collection.insert_one(doc)
    return await collection.insert_one(doc)


async def _find_many(collection, query, sort_field=None):
    if db.USE_MOCK:
        cursor = collection.find(query)
        if sort_field:
            cursor = cursor.sort(sort_field, 1)
        return list(cursor)
    cursor = collection.find(query)
    if sort_field:
        cursor = cursor.sort(sort_field, 1)
    return [doc async for doc in cursor]


async def _update_one(collection, query, update, upsert=False):
    if db.USE_MOCK:
        return collection.update_one(query, update, upsert=upsert)
    return await collection.update_one(query, update, upsert=upsert)


async def _update_many(collection, query, update):
    if db.USE_MOCK:
        return collection.update_many(query, update)
    return await collection.update_many(query, update)


@app.get("/health")
async def health():
    """Lightweight platform health check; DB connectivity is checked at startup."""
    return {"status": "ok"}


# --------------------------------------------------------------------------
# Identity & Key Generation — server side is upload-only (REQ-KEY-3)
# --------------------------------------------------------------------------

@app.post("/api/register")
async def register(req: RegisterRequest):
    existing = await _find_one(db.users, {"username": req.username})
    if existing:
        raise HTTPException(400, "That username is taken.")

    credential = auth.make_server_credential(req.password_verifier)

    await _insert_one(db.users, {
        "username": req.username,
        "server_salt": credential["server_salt"],
        "server_hash": credential["server_hash"],
        "password_salt": req.password_salt,  # client's PBKDF2 salt, needed to recompute the verifier
        "kem_public_key": req.kem_public_key,
        "sig_public_key": req.sig_public_key,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"status": "registered", "username": req.username}


@app.post("/api/login")
async def login(req: LoginRequest):
    user = await _find_one(db.users, {"username": req.username})
    if not user or not auth.check_server_credential(
        req.password_verifier, user["server_salt"], user["server_hash"]
    ):
        raise HTTPException(401, "Invalid username or password.")
    token = auth.issue_token(req.username)
    return {"status": "ok", "token": token, "username": req.username}


@app.post("/api/logout")
def logout(authorization: str | None = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        auth.revoke_token(authorization.removeprefix("Bearer "))
    return {"status": "logged out"}


@app.get("/api/users/search")
async def search_users(
    q: str = Query(..., min_length=3, max_length=32),
    authorization: str | None = Header(None),
):
    """Return a small set of username-prefix matches to an authenticated user.

    The API intentionally does not expose a bulk directory endpoint. Search
    limits reduce casual enumeration, but username search is not a privacy
    boundary; deployments needing private membership should use invite-based
    contact discovery and rate limiting.
    """
    me = require_auth(authorization)
    prefix = q.strip()
    if len(prefix) < 3:
        raise HTTPException(422, "Search query must contain at least 3 characters")

    query = {
        "username": {
            "$regex": "^" + re.escape(prefix),
            "$options": "i",
            "$ne": me,
        }
    }
    if db.USE_MOCK:
        cursor = db.users.find(query).sort("username", 1)
        docs = list(cursor)[:10]
    else:
        cursor = db.users.find(query).sort("username", 1).limit(10)
        docs = [doc async for doc in cursor]
    return [doc["username"] for doc in docs]


@app.get("/api/users/{username}/public-keys", response_model=PublicKeysResponse)
async def get_public_keys(username: str, authorization: str | None = Header(None)):
    require_auth(authorization)
    user = await _find_one(db.users, {"username": username})
    if not user:
        raise HTTPException(404, "Unknown user")
    return PublicKeysResponse(
        username=user["username"],
        kem_public_key=user["kem_public_key"],
        sig_public_key=user["sig_public_key"],
    )


# --------------------------------------------------------------------------
# Message History — ciphertext only, client decrypts (REQ-HIST-1/2)
# --------------------------------------------------------------------------

@app.get("/api/handshakes/pending")
async def get_pending_handshakes(authorization: str | None = Header(None)):
    """Handshake envelopes (opaque kem_ciphertext + signature) addressed
    to me that I haven't consumed yet — covers the case where the
    initiator sent handshake_init while I was offline (basic
    store-and-forward per SRS §2.5)."""
    me = require_auth(authorization)
    docs = await _find_many(db.sessions, {"to": me, "status": "pending"})
    return {"pending": [
        {
            "session_id": d["session_id"],
            "from": d["from"],
            "kem_ciphertext": d["kem_ciphertext"],
            "signature": d["signature"],
            "handshake_id": d.get("handshake_id"),
        }
        for d in docs
    ]}


@app.post("/api/handshakes/{session_id}/consume")
async def consume_handshake(session_id: str, authorization: str | None = Header(None)):
    """Marks a pending handshake as delivered once the client has
    verified the handshake and derived its local session key, so it is not re-served on next fetch."""
    me = require_auth(authorization)
    doc = await _find_one(db.sessions, {"session_id": session_id, "to": me})
    if not doc:
        raise HTTPException(404, "No pending handshake for this session")
    # The recipient endpoint is called only after its browser has verified
    # the handshake and derived the matching secret. Persist that confirmation
    # even if the WebSocket ACK itself is still reconnecting.
    update = {
        "$set": {"status": "established", "active_handshake_id": doc.get("handshake_id")},
        "$unset": {"previous_handshake_id": ""},
    }
    if db.USE_MOCK:
        db.sessions.update_one({"session_id": session_id, "to": me}, update)
    else:
        await db.sessions.update_one({"session_id": session_id, "to": me}, update)
    return {"status": "ok"}


@app.get("/api/conversations")
async def get_conversations(authorization: str | None = Header(None)):
    """List only conversations involving the authenticated user.

    The latest message is returned as ciphertext for client-side preview
    decryption. The backend never stores or returns plaintext previews.
    Messages without read_at count as unread only for their recipient.
    """
    me = require_auth(authorization)
    # The PoC has a small message volume. Read the timestamp-ordered
    # message set and filter in Python so inbox discovery behaves consistently
    # with history retrieval even for legacy documents and test/mock backends.
    # Only conversations involving the authenticated user are included below.
    docs = await _find_many(db.messages, {}, sort_field="timestamp")
    grouped = {}
    for doc in docs:
        sender = doc.get("sender")
        recipient = doc.get("recipient")
        if sender != me and recipient != me:
            continue
        if sender == me:
            peer = recipient
        elif recipient == me:
            peer = sender
        else:
            continue
        if not isinstance(peer, str) or not peer or peer == me:
            continue

        item = grouped.setdefault(peer, {
            "peer": peer,
            "unread_count": 0,
            "last_message": None,
            "updated_at": "",
        })
        if recipient == me and not doc.get("read_at"):
            item["unread_count"] += 1
        item["last_message"] = {
            "sender": sender,
            "recipient": recipient,
            "ciphertext": doc.get("ciphertext", ""),
            "nonce": doc.get("nonce", ""),
            "sequence_number": doc.get("sequence_number", 0),
            "timestamp": doc.get("timestamp", ""),
            "client_message_id": doc.get("client_message_id"),
            "key_id": doc.get("key_id"),
            "delivery_status": doc.get("delivery_status", "sent"),
        }
        item["updated_at"] = doc.get("timestamp", "")

    conversations = sorted(
        grouped.values(),
        key=lambda item: item.get("updated_at") or "",
        reverse=True,
    )
    return {"conversations": conversations}


@app.post("/api/conversations/{peer}/read")
async def mark_conversation_read(peer: str, authorization: str | None = Header(None)):
    """Mark inbound messages as read when the recipient opens a conversation."""
    me = require_auth(authorization)
    if peer == me:
        raise HTTPException(400, "Cannot mark a conversation with yourself as read")
    if not await _find_one(db.users, {"username": peer}):
        raise HTTPException(404, "Unknown user")
    session_id = db.session_id_for(me, peer)
    result = await _update_many(
        db.messages,
        {
            "session_id": session_id,
            "sender": peer,
            "recipient": me,
            "read_at": {"$exists": False},
        },
        {"$set": {"read_at": datetime.now(timezone.utc).isoformat()}},
    )
    modified_count = getattr(result, "modified_count", 0)
    return {"status": "ok", "marked_read": modified_count}


@app.get("/api/messages/{peer}")
async def get_history(peer: str, authorization: str | None = Header(None)):
    me = require_auth(authorization)
    session_id = db.session_id_for(me, peer)
    # Sequence numbers are per sender/direction, so sort conversation history
    # by server timestamp to preserve the actual exchange order.
    docs = await _find_many(db.messages, {"session_id": session_id}, sort_field="timestamp")
    return {
        "session_id": session_id,
        "messages": [
            MessageOut(
                sender=d["sender"],
                recipient=d["recipient"],
                ciphertext=d["ciphertext"],
                nonce=d["nonce"],
                sequence_number=d["sequence_number"],
                timestamp=d["timestamp"],
                client_message_id=d.get("client_message_id"),
                key_id=d.get("key_id"),
                delivery_status=d.get("delivery_status", "sent"),
            )
            for d in docs
        ],
    }


# --------------------------------------------------------------------------
# WebSocket relay — handshake + message envelopes, all opaque
# --------------------------------------------------------------------------

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    # Bearer tokens must not appear in the WebSocket URL, which can be copied
    # into proxy/access logs. Authenticate with the first WSS data frame.
    await websocket.accept()
    username = None
    try:
        try:
            auth_envelope = await asyncio.wait_for(websocket.receive_json(), timeout=10)
        except (asyncio.TimeoutError, WebSocketDisconnect):
            await websocket.close(code=4401)
            return
        if not isinstance(auth_envelope, dict) or auth_envelope.get("type") != "auth":
            await websocket.send_json({"type": "auth_error", "reason": "authentication_required"})
            await websocket.close(code=4401)
            return
        username = auth.resolve_token(auth_envelope.get("token"))
        if not username:
            await websocket.send_json({"type": "auth_error", "reason": "invalid_or_expired_token"})
            await websocket.close(code=4401)
            return
        await websocket.send_json({"type": "auth_ok"})
        WS_CONNECTIONS[username] = websocket

        while True:
            envelope = await websocket.receive_json()
            msg_type = envelope.get("type")

            if msg_type == "handshake_init":
                # Relay opaque cryptographic material, but validate routing
                # metadata so it cannot create arbitrary/mismatched sessions.
                to = envelope.get("to")
                session_id = envelope.get("session_id")
                kem_ciphertext = envelope.get("kem_ciphertext")
                signature = envelope.get("signature")
                handshake_id = envelope.get("handshake_id")
                valid_routing = (
                    isinstance(to, str) and bool(to) and to != username
                    and session_id == db.session_id_for(username, to)
                    and isinstance(kem_ciphertext, str) and bool(kem_ciphertext)
                    and isinstance(signature, str) and bool(signature)
                    and isinstance(handshake_id, str) and 1 <= len(handshake_id) <= 128
                )
                if not valid_routing or not await _find_one(db.users, {"username": to}):
                    await websocket.send_json({
                        "type": "handshake_error",
                        "from": to if isinstance(to, str) else None,
                        "session_id": session_id,
                        "handshake_id": handshake_id,
                        "reason": "invalid_handshake_target_or_envelope",
                    })
                    continue

                # Only one handshake may be pending for a conversation at a
                # time. Without arbitration, Alice->Bob and Bob->Alice can
                # race and overwrite the same session record with different
                # shared secrets. The first reserved handshake wins; a second
                # different attempt is rejected, and its client will receive
                # the winning handshake as the recipient.
                conflict = False
                reserved_status = "pending"
                previous_handshake_id = None
                async with _handshake_lock(session_id):
                    existing = await _find_one(db.sessions, {"session_id": session_id})
                    same_handshake = bool(
                        existing
                        and existing.get("handshake_id") == handshake_id
                        and existing.get("from") == username
                        and existing.get("to") == to
                        and existing.get("kem_ciphertext") == kem_ciphertext
                        and existing.get("signature") == signature
                    )
                    reused_id_with_different_payload = bool(
                        existing and existing.get("handshake_id") == handshake_id and not same_handshake
                    )
                    if (
                        reused_id_with_different_payload
                        or (existing and existing.get("status") == "pending" and not same_handshake)
                        or (same_handshake and existing.get("status") == "rejected")
                    ):
                        conflict = True
                    elif same_handshake:
                        # Idempotent resend: preserve the exact attempt and
                        # report the server's current state to its initiator.
                        reserved_status = existing.get("status", "pending")
                        previous_handshake_id = existing.get("previous_handshake_id")
                    else:
                        # While a re-handshake is pending, permit the previous
                        # confirmed key epoch to continue briefly. As soon as
                        # the new attempt is peer-confirmed, only the new ID is
                        # accepted for outgoing messages.
                        if existing and existing.get("status") == "established":
                            previous_handshake_id = existing.get("handshake_id")
                        await _update_one(db.sessions, {"session_id": session_id}, {"$set": {
                            "session_id": session_id,
                            "participants": sorted([username, to]),
                            "from": username,
                            "to": to,
                            "kem_ciphertext": kem_ciphertext,
                            "signature": signature,
                            "handshake_id": handshake_id,
                            "previous_handshake_id": previous_handshake_id,
                            "status": "pending",
                            "established_at": datetime.now(timezone.utc).isoformat(),
                        }}, upsert=True)
                        reserved_status = "pending"
                if conflict:
                    await websocket.send_json({
                        "type": "handshake_error",
                        "from": to,
                        "session_id": session_id,
                        "handshake_id": handshake_id,
                        "reason": "another_handshake_pending",
                    })
                    continue

                # Tell the initiator that this exact key epoch has been
                # reserved by the relay. This enables offline store-and-forward
                # without enabling sends for a locally-generated, rejected
                # competing handshake.
                await websocket.send_json({
                    "type": "handshake_accepted",
                    "from": to,
                    "session_id": session_id,
                    "handshake_id": handshake_id,
                    "status": reserved_status,
                })
                peer_ws = WS_CONNECTIONS.get(to)
                if peer_ws is not None:
                    await peer_ws.send_json({**envelope, "from": username})

            elif msg_type == "handshake_reject":
                # A recipient who cannot verify a queued or live handshake or
                # derive its local session key can reject it. Match the authenticated recipient
                # to the exact pending handshake before notifying the sender.
                to = envelope.get("to")
                session_id = envelope.get("session_id")
                handshake_id = envelope.get("handshake_id")
                if (
                    not isinstance(to, str) or not to or to == username
                    or session_id != db.session_id_for(username, to)
                    or not isinstance(handshake_id, str) or not handshake_id
                ):
                    continue
                handshake_record = await _find_one(db.sessions, {
                    "session_id": session_id,
                    "handshake_id": handshake_id,
                    "from": to,
                    "to": username,
                    "status": "pending",
                })
                if not handshake_record:
                    continue
                if handshake_record.get("previous_handshake_id"):
                    # A rejected re-key attempt must not destroy the previous
                    # established epoch. Restore its ID so its key remains
                    # valid for both clients while the failed attempt is gone.
                    previous_id = handshake_record["previous_handshake_id"]
                    await _update_one(db.sessions, {
                        "session_id": session_id, "handshake_id": handshake_id,
                        "from": to, "to": username,
                    }, {"$set": {
                        "handshake_id": previous_id,
                        "active_handshake_id": previous_id,
                        "status": "established",
                        "rejected_handshake_id": handshake_id,
                    }, "$unset": {"previous_handshake_id": ""}})
                else:
                    await _update_one(db.sessions, {
                        "session_id": session_id, "handshake_id": handshake_id,
                        "from": to, "to": username,
                    }, {"$set": {"status": "rejected", "rejected_at": datetime.now(timezone.utc).isoformat()}})
                sender_ws = WS_CONNECTIONS.get(to)
                if sender_ws is not None:
                    await sender_ws.send_json({
                        "type": "handshake_error",
                        "from": username,
                        "session_id": session_id,
                        "handshake_id": handshake_id,
                        "reason": "peer_rejected_handshake",
                    })

            elif msg_type == "handshake_ack":
                # Relay confirmation only when it matches the outstanding
                # handshake record for this authenticated recipient.
                to = envelope.get("to")  # original initiator
                session_id = envelope.get("session_id")
                handshake_id = envelope.get("handshake_id")
                if (
                    not isinstance(to, str) or to == username
                    or session_id != db.session_id_for(username, to)
                    or not isinstance(handshake_id, str) or not handshake_id
                ):
                    continue
                handshake_record = await _find_one(db.sessions, {
                    "session_id": session_id,
                    "handshake_id": handshake_id,
                    "from": to,
                    "to": username,
                })
                if not handshake_record:
                    continue
                await _update_one(db.sessions, {"session_id": session_id, "handshake_id": handshake_id}, {
                    "$set": {"status": "established", "active_handshake_id": handshake_id},
                    "$unset": {"previous_handshake_id": ""},
                })
                peer_ws = WS_CONNECTIONS.get(to)
                if peer_ws is not None:
                    await peer_ws.send_json({**envelope, "from": username})

            elif msg_type == "chat_message":
                to = envelope.get("to")
                if not isinstance(to, str) or not to or to == username:
                    if envelope.get("client_message_id"):
                        await websocket.send_json({
                            "type": "message_status",
                            "client_message_id": envelope["client_message_id"],
                            "status": "failed",
                            "reason": "invalid_recipient",
                        })
                    continue
                if not await _find_one(db.users, {"username": to}):
                    if envelope.get("client_message_id"):
                        await websocket.send_json({
                            "type": "message_status",
                            "client_message_id": envelope["client_message_id"],
                            "status": "failed",
                            "reason": "unknown_recipient",
                        })
                    continue

                session_id = envelope.get("session_id") or db.session_id_for(username, to)
                # The conversation ID is routing metadata and must match the
                # authenticated sender/recipient pair.
                expected_session_id = db.session_id_for(username, to)
                seq = envelope.get("sequence_number")
                ciphertext = envelope.get("ciphertext")
                nonce = envelope.get("nonce")
                client_message_id = envelope.get("client_message_id")
                key_id = envelope.get("key_id")
                if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
                    if isinstance(client_message_id, str) and client_message_id:
                        await websocket.send_json({
                            "type": "message_status",
                            "client_message_id": client_message_id,
                            "status": "failed",
                            "reason": "session_key_epoch_not_reserved",
                            "peer": to,
                            "key_id": key_id,
                        })
                    continue
                if (
                    session_id != expected_session_id
                    or not isinstance(seq, int) or isinstance(seq, bool) or seq < 1
                    or not isinstance(ciphertext, str) or not ciphertext
                    or not isinstance(nonce, str) or not nonce
                    or (client_message_id is not None and
                        (not isinstance(client_message_id, str) or not client_message_id or len(client_message_id) > 128))
                ):
                    if isinstance(client_message_id, str) and client_message_id:
                        await websocket.send_json({
                            "type": "message_status",
                            "client_message_id": client_message_id,
                            "status": "failed",
                            "reason": "invalid_message_envelope",
                        })
                    continue

                # Never persist or relay ciphertext encrypted under a key
                # epoch that the relay did not reserve for this conversation.
                # This blocks messages from a crossed/rejected handshake from
                # polluting history and appearing as AES-GCM failures later.
                session_record = await _find_one(db.sessions, {"session_id": session_id})
                allowed_key_ids = set()
                if session_record and session_record.get("status") in ("pending", "established"):
                    if session_record.get("handshake_id"):
                        allowed_key_ids.add(session_record["handshake_id"])
                    if session_record.get("status") == "pending" and session_record.get("previous_handshake_id"):
                        allowed_key_ids.add(session_record["previous_handshake_id"])
                if key_id not in allowed_key_ids:
                    if isinstance(client_message_id, str) and client_message_id:
                        await websocket.send_json({
                            "type": "message_status",
                            "client_message_id": client_message_id,
                            "status": "failed",
                            "reason": "session_key_epoch_not_reserved",
                            "peer": to,
                            "key_id": key_id,
                        })
                    continue

                record = {
                    "session_id": session_id,
                    "sender": username,
                    "recipient": to,
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "sequence_number": seq,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "delivery_status": "sent",
                }
                if key_id:
                    record["key_id"] = key_id
                if client_message_id:
                    record["client_message_id"] = client_message_id

                await _insert_one(db.messages, record)
                # A `sent` receipt is emitted only after Mongo accepted the
                # ciphertext. It does not mean the recipient received it.
                if client_message_id:
                    await websocket.send_json({
                        "type": "message_status",
                        "client_message_id": client_message_id,
                        "status": "sent",
                    })
                peer_ws = WS_CONNECTIONS.get(to)
                if peer_ws is not None:
                    await peer_ws.send_json({**envelope, "type": "chat_message",
                                              "from": username, "timestamp": record["timestamp"]})

            elif msg_type == "delivery_ack":
                # The recipient sends this only after decryptMessage() passes
                # AEAD authentication. Match the record to the authenticated
                # recipient and pair/session so an unrelated account cannot
                # mark another user's message as delivered.
                to = envelope.get("to")  # original sender
                client_message_id = envelope.get("client_message_id")
                session_id = envelope.get("session_id")
                seq = envelope.get("sequence_number")
                if (
                    not isinstance(to, str) or not to or to == username
                    or not isinstance(client_message_id, str) or not client_message_id
                    or session_id != db.session_id_for(username, to)
                    or not isinstance(seq, int) or isinstance(seq, bool) or seq < 1
                ):
                    continue

                query = {
                    "client_message_id": client_message_id,
                    "session_id": session_id,
                    "sender": to,
                    "recipient": username,
                    "sequence_number": seq,
                }
                stored = await _find_one(db.messages, query)
                if not stored:
                    continue
                delivered_at = datetime.now(timezone.utc).isoformat()
                await _update_one(db.messages, query, {"$set": {
                    "delivery_status": "delivered",
                    "delivered_at": delivered_at,
                }})
                sender_ws = WS_CONNECTIONS.get(to)
                if sender_ws is not None:
                    await sender_ws.send_json({
                        "type": "message_status",
                        "client_message_id": client_message_id,
                        "status": "delivered",
                        "delivered_at": delivered_at,
                    })
    except WebSocketDisconnect:
        pass
    finally:
        if username and WS_CONNECTIONS.get(username) is websocket:
            WS_CONNECTIONS.pop(username, None)


# In the production container, serve the compiled React app from the same
# origin as REST and WebSocket endpoints. During local Vite development the
# directory is unset, so the Vite dev server continues to provide the UI.
_frontend_dist = os.environ.get("PQCHAT_FRONTEND_DIST")
if _frontend_dist and os.path.isdir(_frontend_dist):
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")
