"""
test_relay.py

Enforces the "blind relay" property at the code level, not just in
prose comments. Two kinds of checks:

  1. Static: none of the backend's own source files reference private-key
     material, decryption, or PQC secret operations by name. If someone
     adds `decapsulate(...)` or a `secret_key` field to this backend in
     the future, this test fails immediately.

  2. Behavioral: register/login/message payloads accepted by the running
     API never contain a private-key-shaped field, and a full
     register -> login -> handshake-relay -> message-relay flow works
     using only opaque/public data.

Run with: PQCHAT_USE_MONGOMOCK=1 python3 -m pytest tests/test_relay.py -v
"""

import os
import re
import sys
from contextlib import contextmanager

os.environ.setdefault("PQCHAT_USE_MONGOMOCK", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

import main
import db

client = TestClient(main.app)


@contextmanager
def authenticated_ws(token):
    """Open /ws and authenticate without putting a bearer token in the URL."""
    with client.websocket_connect("/ws") as websocket:
        websocket.send_json({"type": "auth", "token": token})
        response = websocket.receive_json()
        assert response["type"] == "auth_ok"
        yield websocket


BACKEND_SOURCE_FILES = ["main.py", "db.py", "auth.py", "models.py"]
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Substrings that would indicate the server is touching secret material
# or performing a cryptographic operation only the client should do.
FORBIDDEN_PATTERNS = [
    r"secret_key",
    r"private_key",
    r"kem_sk",
    r"sig_sk",
    r"\bdecapsulate\b",
    r"\bdecaps\(",
    r"\bencaps\(",
    r"\.decrypt\(",
    r"AESGCM",
    r"aead_decrypt",
    r"aead_encrypt",
]


def test_no_forbidden_crypto_terms_in_backend_source():
    for filename in BACKEND_SOURCE_FILES:
        path = os.path.join(BACKEND_DIR, filename)
        with open(path, "r") as f:
            source = f.read()
        for pattern in FORBIDDEN_PATTERNS:
            match = re.search(pattern, source, re.IGNORECASE)
            assert match is None, (
                f"{filename} contains '{match.group(0) if match else pattern}' — "
                f"the backend must never reference private keys or perform "
                f"decrypt/decapsulate operations. That belongs in the client."
            )


@pytest.fixture(autouse=True)
def clean_db():
    db.users.delete_many({})
    db.sessions.delete_many({})
    db.messages.delete_many({})
    yield


def test_register_login_and_message_relay_never_needs_secrets():
    # Registration payload contains only public keys — a real client
    # would compute these via ml_kem768.keygen()/ml_dsa65.keygen() and
    # send only .publicKey. We simulate with fixed-size hex blobs
    # matching real ML-KEM-768/ML-DSA-65 public key lengths.
    alice_kem_pk = ("aa" * 1184)
    alice_sig_pk = ("bb" * 1952)
    bob_kem_pk = ("cc" * 1184)
    bob_sig_pk = ("dd" * 1952)

    r = client.post("/api/register", json={
        "username": "alice",
        "password_verifier": "deadbeef" * 8,
        "password_salt": "0011" * 8,
        "kem_public_key": alice_kem_pk,
        "sig_public_key": alice_sig_pk,
    })
    assert r.status_code == 200

    r = client.post("/api/register", json={
        "username": "bob",
        "password_verifier": "cafebabe" * 8,
        "password_salt": "2233" * 8,
        "kem_public_key": bob_kem_pk,
        "sig_public_key": bob_sig_pk,
    })
    assert r.status_code == 200

    r = client.post("/api/login", json={"username": "alice", "password_verifier": "deadbeef" * 8})
    assert r.status_code == 200
    alice_token = r.json()["token"]

    r = client.get("/api/users/bob/public-keys", headers={"Authorization": f"Bearer {alice_token}"})
    assert r.status_code == 200
    assert r.json()["kem_public_key"] == bob_kem_pk

    # No message history yet
    r = client.get("/api/messages/bob", headers={"Authorization": f"Bearer {alice_token}"})
    assert r.status_code == 200
    assert r.json()["messages"] == []


def test_register_rejects_missing_public_keys():
    r = client.post("/api/register", json={
        "username": "eve",
        "password_verifier": "x" * 64,
        "password_salt": "y" * 32,
        # missing kem_public_key / sig_public_key entirely -> validation error
    })
    assert r.status_code == 422


def test_user_discovery_requires_search_and_does_not_list_directory():
    for username in ("alice", "alicia", "bob"):
        r = client.post("/api/register", json={
            "username": username,
            "password_verifier": (username + "v") * 16,
            "password_salt": (username + "s") * 8,
            "kem_public_key": ("aa" * 1184),
            "sig_public_key": ("bb" * 1952),
        })
        assert r.status_code == 200

    login = client.post("/api/login", json={
        "username": "bob",
        "password_verifier": ("bobv") * 16,
    })
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['token']}"}

    # The old unfiltered directory and unused public salt lookup are removed.
    assert client.get("/api/users", headers=headers).status_code == 404
    assert client.get("/api/users/alice/password-salt").status_code == 404
    assert client.get("/api/users/unknown/password-salt").status_code == 404
    # Prefix search returns other matching accounts but excludes the caller.
    result = client.get("/api/users/search?q=ali", headers=headers)
    assert result.status_code == 200
    assert result.json() == ["alice", "alicia"]
    # Short queries cannot be used for one-character-at-a-time enumeration.
    assert client.get("/api/users/search?q=al", headers=headers).status_code == 422
    # Search is authenticated.
    assert client.get("/api/users/search?q=ali").status_code == 401


def test_message_receipts_distinguish_relay_storage_from_client_delivery():
    """A sent receipt follows persistence; delivered follows recipient ack."""
    for username, verifier in (("alice", "deadbeef" * 8), ("bob", "cafebabe" * 8)):
        response = client.post("/api/register", json={
            "username": username,
            "password_verifier": verifier,
            "password_salt": "0011" * 8,
            "kem_public_key": "aa" * 1184,
            "sig_public_key": "bb" * 1952,
        })
        assert response.status_code == 200

    alice_login = client.post("/api/login", json={
        "username": "alice", "password_verifier": "deadbeef" * 8,
    })
    bob_login = client.post("/api/login", json={
        "username": "bob", "password_verifier": "cafebabe" * 8,
    })
    alice_token = alice_login.json()["token"]
    bob_token = bob_login.json()["token"]
    session_id = "alice|bob"
    message_id = "receipt-test-001"

    with authenticated_ws(alice_token) as alice_ws, \
         authenticated_ws(bob_token) as bob_ws:
        alice_ws.send_json({
            "type": "handshake_init",
            "to": "bob",
            "session_id": session_id,
            "handshake_id": "handshake-version-001",
            "kem_ciphertext": "opaque-kem-ciphertext",
            "signature": "opaque-handshake-signature",
        })
        accepted = alice_ws.receive_json()
        assert accepted["type"] == "handshake_accepted"
        assert accepted["handshake_id"] == "handshake-version-001"
        assert accepted["status"] == "pending"
        relayed_handshake = bob_ws.receive_json()
        assert relayed_handshake["type"] == "handshake_init"

        alice_ws.send_json({
            "type": "chat_message",
            "to": "bob",
            "session_id": session_id,
            "client_message_id": message_id,
            "key_id": "handshake-version-001",
            "ciphertext": "opaque-ciphertext",
            "nonce": "opaque-nonce",
            "sequence_number": 1,
        })

        sent = alice_ws.receive_json()
        assert sent["type"] == "message_status"
        assert sent["status"] == "sent"
        relayed = bob_ws.receive_json()
        assert relayed["type"] == "chat_message"
        assert relayed["client_message_id"] == message_id

        bob_ws.send_json({
            "type": "delivery_ack",
            "to": "alice",
            "session_id": session_id,
            "client_message_id": message_id,
            "sequence_number": 1,
        })
        delivered = alice_ws.receive_json()
        assert delivered["type"] == "message_status"
        assert delivered["status"] == "delivered"

    history = client.get(
        "/api/messages/alice",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert history.status_code == 200
    assert history.json()["messages"][0]["client_message_id"] == message_id
    assert history.json()["messages"][0]["key_id"] == "handshake-version-001"
    assert history.json()["messages"][0]["delivery_status"] == "delivered"

    # Any account with stored messages must see the peer in its inbox summary.
    alice_inbox = client.get("/api/conversations", headers={"Authorization": f"Bearer {alice_token}"})
    bob_inbox = client.get("/api/conversations", headers={"Authorization": f"Bearer {bob_token}"})
    assert alice_inbox.status_code == 200
    assert bob_inbox.status_code == 200
    assert alice_inbox.json()["conversations"][0]["peer"] == "bob"
    assert bob_inbox.json()["conversations"][0]["peer"] == "alice"



def test_crossed_handshakes_do_not_overwrite_the_winning_session():
    for username, verifier in (("alice", "alice-handshake-verifier" * 3), ("bob", "bob-handshake-verifier" * 3)):
        response = client.post("/api/register", json={
            "username": username,
            "password_verifier": verifier,
            "password_salt": "0011223344556677",
            "kem_public_key": "aa" * 1184,
            "sig_public_key": "bb" * 1952,
        })
        assert response.status_code == 200

    alice_verifier = "alice-handshake-verifier" * 3
    bob_verifier = "bob-handshake-verifier" * 3
    alice_token = client.post("/api/login", json={
        "username": "alice", "password_verifier": alice_verifier,
    }).json()["token"]
    bob_token = client.post("/api/login", json={
        "username": "bob", "password_verifier": bob_verifier,
    }).json()["token"]

    session_id = "alice|bob"
    alice_init = {
        "type": "handshake_init", "to": "bob", "session_id": session_id,
        "handshake_id": "alice-init-001", "kem_ciphertext": "opaque-kem-a",
        "signature": "opaque-signature-a",
    }
    bob_competing_init = {
        "type": "handshake_init", "to": "alice", "session_id": session_id,
        "handshake_id": "bob-init-002", "kem_ciphertext": "opaque-kem-b",
        "signature": "opaque-signature-b",
    }

    with authenticated_ws(alice_token) as alice_ws, \
         authenticated_ws(bob_token) as bob_ws:
        alice_ws.send_json(alice_init)
        accepted = alice_ws.receive_json()
        assert accepted["type"] == "handshake_accepted"
        assert accepted["handshake_id"] == "alice-init-001"
        relayed_winner = bob_ws.receive_json()
        assert relayed_winner["type"] == "handshake_init"
        assert relayed_winner["handshake_id"] == "alice-init-001"

        # Bob starts a different handshake before acknowledging Alice's.
        # The relay must reject it rather than replace Alice's KEM ciphertext.
        bob_ws.send_json(bob_competing_init)
        rejected = bob_ws.receive_json()
        assert rejected["type"] == "handshake_error"
        assert rejected["handshake_id"] == "bob-init-002"
        assert rejected["reason"] == "another_handshake_pending"

        bob_ws.send_json({
            "type": "handshake_ack", "to": "alice", "session_id": session_id,
            "handshake_id": "alice-init-001",
        })
        ack = alice_ws.receive_json()
        assert ack["type"] == "handshake_ack"
        assert ack["handshake_id"] == "alice-init-001"

    stored = client.get("/api/handshakes/pending", headers={"Authorization": f"Bearer {bob_token}"})
    assert stored.status_code == 200
    # Alice's winning handshake was established and should no longer be pending.
    assert stored.json()["pending"] == []


def test_conversation_inbox_shows_latest_ciphertext_and_tracks_unread_count():
    for username, verifier, kem_byte, sig_byte in (
        ("alice", "alice-inbox-verifier" * 3, "aa", "bb"),
        ("bob", "bob-inbox-verifier" * 3, "cc", "dd"),
    ):
        response = client.post("/api/register", json={
            "username": username,
            "password_verifier": verifier,
            "password_salt": "0011223344556677",
            "kem_public_key": kem_byte * 1184,
            "sig_public_key": sig_byte * 1952,
        })
        assert response.status_code == 200

    alice_verifier = "alice-inbox-verifier" * 3
    bob_verifier = "bob-inbox-verifier" * 3
    alice_token = client.post("/api/login", json={
        "username": "alice", "password_verifier": alice_verifier,
    }).json()["token"]
    bob_token = client.post("/api/login", json={
        "username": "bob", "password_verifier": bob_verifier,
    }).json()["token"]

    session_id = "alice|bob"
    message_id = "inbox-message-001"
    with authenticated_ws(alice_token) as alice_ws:
        alice_ws.send_json({
            "type": "handshake_init", "to": "bob", "session_id": session_id,
            "handshake_id": "inbox-handshake-001", "kem_ciphertext": "opaque-kem",
            "signature": "opaque-signature",
        })
        accepted = alice_ws.receive_json()
        assert accepted["type"] == "handshake_accepted"
        alice_ws.send_json({
            "type": "chat_message",
            "to": "bob",
            "session_id": session_id,
            "client_message_id": message_id,
            "key_id": "inbox-handshake-001",
            "ciphertext": "opaque-ciphertext-only",
            "nonce": "opaque-nonce",
            "sequence_number": 1,
        })
        assert alice_ws.receive_json()["status"] == "sent"

    bob_headers = {"Authorization": f"Bearer {bob_token}"}
    inbox = client.get("/api/conversations", headers=bob_headers)
    assert inbox.status_code == 200
    assert len(inbox.json()["conversations"]) == 1
    conversation = inbox.json()["conversations"][0]
    assert conversation["peer"] == "alice"
    assert conversation["unread_count"] == 1
    assert conversation["last_message"]["ciphertext"] == "opaque-ciphertext-only"
    assert "plaintext" not in conversation["last_message"]

    marked = client.post("/api/conversations/alice/read", headers=bob_headers)
    assert marked.status_code == 200
    assert marked.json()["marked_read"] == 1

    inbox_after_read = client.get("/api/conversations", headers=bob_headers)
    assert inbox_after_read.json()["conversations"][0]["unread_count"] == 0

    unauthenticated = client.get("/api/conversations")
    assert unauthenticated.status_code == 401


def test_rehandshake_upserts_existing_conversation_and_matches_attempt_id():
    """A second handshake for a conversation must not break its WebSocket."""
    for username, verifier in (("alice", "alice-verifier" * 6), ("bob", "bob-verifier" * 6)):
        response = client.post("/api/register", json={
            "username": username,
            "password_verifier": verifier,
            "password_salt": "0011223344556677",
            "kem_public_key": "aa" * 1184,
            "sig_public_key": "bb" * 1952,
        })
        assert response.status_code == 200

    alice_login = client.post("/api/login", json={
        "username": "alice", "password_verifier": "alice-verifier" * 6,
    })
    bob_login = client.post("/api/login", json={
        "username": "bob", "password_verifier": "bob-verifier" * 6,
    })
    alice_token = alice_login.json()["token"]
    bob_token = bob_login.json()["token"]

    with authenticated_ws(alice_token) as alice_ws, \
         authenticated_ws(bob_token) as bob_ws:
        for attempt_id in ("handshake-attempt-1", "handshake-attempt-2"):
            alice_ws.send_json({
                "type": "handshake_init",
                "to": "bob",
                "session_id": "alice|bob",
                "handshake_id": attempt_id,
                "kem_ciphertext": "opaque-kem-ciphertext-" + attempt_id,
                "signature": "opaque-signature-" + attempt_id,
            })
            accepted = alice_ws.receive_json()
            assert accepted["type"] == "handshake_accepted"
            assert accepted["handshake_id"] == attempt_id
            relayed = bob_ws.receive_json()
            assert relayed["type"] == "handshake_init"
            assert relayed["handshake_id"] == attempt_id

            bob_ws.send_json({
                "type": "handshake_ack",
                "to": "alice",
                "session_id": "alice|bob",
                "handshake_id": attempt_id,
            })
            ack = alice_ws.receive_json()
            assert ack["type"] == "handshake_ack"
            assert ack["handshake_id"] == attempt_id


def test_offline_recipient_can_receive_queued_handshake_and_ciphertext_history():
    """The sender can submit ciphertext before the recipient has a live socket.

    The backend only stores opaque bytes. The recipient's later login retrieves
    the pending KEM envelope and message history, then decrypts on the client.
    """
    for username, verifier, kem_byte, sig_byte in (
        ("alice", "alice-offline-verifier" * 3, "aa", "bb"),
        ("bob", "bob-offline-verifier" * 3, "cc", "dd"),
    ):
        response = client.post("/api/register", json={
            "username": username,
            "password_verifier": verifier,
            "password_salt": "0011223344556677",
            "kem_public_key": kem_byte * 1184,
            "sig_public_key": sig_byte * 1952,
        })
        assert response.status_code == 200

    alice_verifier = "alice-offline-verifier" * 3
    bob_verifier = "bob-offline-verifier" * 3
    alice_token = client.post("/api/login", json={
        "username": "alice", "password_verifier": alice_verifier,
    }).json()["token"]
    bob_token = client.post("/api/login", json={
        "username": "bob", "password_verifier": bob_verifier,
    }).json()["token"]

    session_id = "alice|bob"
    handshake_id = "offline-handshake-1"
    message_id = "offline-message-1"
    ciphertext = "ab" * 64
    nonce = "cd" * 12

    # Bob deliberately has no WebSocket connection in this test.
    with authenticated_ws(alice_token) as alice_ws:
        alice_ws.send_json({
            "type": "handshake_init",
            "to": "bob",
            "session_id": session_id,
            "handshake_id": handshake_id,
            "kem_ciphertext": "ef" * 1088,
            "signature": "12" * 3309,
        })
        accepted = alice_ws.receive_json()
        assert accepted["type"] == "handshake_accepted"
        assert accepted["status"] == "pending"
        alice_ws.send_json({
            "type": "chat_message",
            "to": "bob",
            "session_id": session_id,
            "client_message_id": message_id,
            "key_id": handshake_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "sequence_number": 1,
        })
        sent_receipt = alice_ws.receive_json()
        assert sent_receipt["type"] == "message_status"
        assert sent_receipt["client_message_id"] == message_id
        assert sent_receipt["status"] == "sent"

    pending = client.get(
        "/api/handshakes/pending",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert pending.status_code == 200
    assert len(pending.json()["pending"]) == 1
    assert pending.json()["pending"][0]["handshake_id"] == handshake_id
    assert pending.json()["pending"][0]["from"] == "alice"

    history = client.get(
        "/api/messages/alice",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert history.status_code == 200
    queued = history.json()["messages"]
    assert len(queued) == 1
    assert queued[0]["client_message_id"] == message_id
    assert queued[0]["ciphertext"] == ciphertext
    assert queued[0]["nonce"] == nonce



def test_relay_rejects_messages_encrypted_under_unreserved_handshake_id():
    for username, verifier in (("alice", "alice-epoch-verifier" * 3), ("bob", "bob-epoch-verifier" * 3)):
        response = client.post("/api/register", json={
            "username": username,
            "password_verifier": verifier,
            "password_salt": "0011223344556677",
            "kem_public_key": "aa" * 1184,
            "sig_public_key": "bb" * 1952,
        })
        assert response.status_code == 200

    alice_token = client.post("/api/login", json={
        "username": "alice", "password_verifier": "alice-epoch-verifier" * 3,
    }).json()["token"]
    bob_token = client.post("/api/login", json={
        "username": "bob", "password_verifier": "bob-epoch-verifier" * 3,
    }).json()["token"]

    with authenticated_ws(alice_token) as alice_ws, \
         authenticated_ws(bob_token) as bob_ws:
        alice_ws.send_json({
            "type": "handshake_init", "to": "bob", "session_id": "alice|bob",
            "handshake_id": "accepted-epoch", "kem_ciphertext": "opaque-kem",
            "signature": "opaque-signature",
        })
        accepted = alice_ws.receive_json()
        assert accepted["type"] == "handshake_accepted"
        assert bob_ws.receive_json()["type"] == "handshake_init"

        alice_ws.send_json({
            "type": "chat_message", "to": "bob", "session_id": "alice|bob",
            "client_message_id": "wrong-epoch-message", "key_id": "losing-epoch",
            "ciphertext": "opaque-ciphertext", "nonce": "opaque-nonce", "sequence_number": 1,
        })
        failed = alice_ws.receive_json()
        assert failed["type"] == "message_status"
        assert failed["status"] == "failed"
        assert failed["reason"] == "session_key_epoch_not_reserved"
        bob_inbox = client.get("/api/conversations", headers={"Authorization": f"Bearer {bob_token}"})
        assert bob_inbox.status_code == 200
        assert bob_inbox.json()["conversations"] == []


def test_recipient_can_reject_failed_handshake_and_sender_is_not_left_pending():
    for username, verifier, kem_byte, sig_byte in (
        ("alice", "alice-reject-verifier" * 3, "aa", "bb"),
        ("bob", "bob-reject-verifier" * 3, "cc", "dd"),
    ):
        response = client.post("/api/register", json={
            "username": username,
            "password_verifier": verifier,
            "password_salt": "0011223344556677",
            "kem_public_key": kem_byte * 1184,
            "sig_public_key": sig_byte * 1952,
        })
        assert response.status_code == 200

    alice_token = client.post("/api/login", json={
        "username": "alice", "password_verifier": "alice-reject-verifier" * 3,
    }).json()["token"]
    bob_token = client.post("/api/login", json={
        "username": "bob", "password_verifier": "bob-reject-verifier" * 3,
    }).json()["token"]

    with authenticated_ws(alice_token) as alice_ws, \
         authenticated_ws(bob_token) as bob_ws:
        alice_ws.send_json({
            "type": "handshake_init", "to": "bob", "session_id": "alice|bob",
            "handshake_id": "reject-test-1", "kem_ciphertext": "ef" * 1088,
            "signature": "12" * 3309,
        })
        accepted = alice_ws.receive_json()
        assert accepted["type"] == "handshake_accepted"
        relayed = bob_ws.receive_json()
        assert relayed["type"] == "handshake_init"

        bob_ws.send_json({
            "type": "handshake_reject", "to": "alice",
            "session_id": "alice|bob", "handshake_id": "reject-test-1",
        })
        rejection = alice_ws.receive_json()
        assert rejection["type"] == "handshake_error"
        assert rejection["handshake_id"] == "reject-test-1"
        assert rejection["reason"] == "peer_rejected_handshake"

    pending = client.get("/api/handshakes/pending", headers={"Authorization": f"Bearer {bob_token}"})
    assert pending.status_code == 200
    assert pending.json()["pending"] == []
