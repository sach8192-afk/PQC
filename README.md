# PQChat v2 — Secure Post-Quantum Chat Application

Client-side ML-KEM-768 + ML-DSA-65, blind-relay server, per the SRS
(`Secure Post-Quantum Chat Application`, v1.0, 20 Jul 2026).

## Run it

Two processes, in order:

```bash
# 1. Backend (blind relay) — needs a MongoDB Atlas connection string, see backend/README.md
cd backend
pip install -r requirements.txt --break-system-packages
export MONGODB_URI="mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority"
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000

# 2. Frontend (all the actual cryptography happens here)
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in two browser windows to register two
users and chat between them.

Full setup details (Atlas cluster creation, test commands) are in
`backend/README.md` and `frontend/README.md`.

## Architecture — the one rule everything follows

Anything secret — private keys, session keys, plaintext — is generated,
stored, and used **entirely inside the browser**. The server (FastAPI)
only ever sees things that are safe to store for this proof of concept:
usernames, public keys, ciphertext, handshake signatures, timestamps, and
sequence numbers. The UI does not automatically enumerate every account;
users are discovered through an authenticated username search.

```
Browser (React)                          Browser (React)
  ML-KEM-768 / ML-DSA-65                   ML-KEM-768 / ML-DSA-65
  (@noble/post-quantum)                    (@noble/post-quantum)
  HKDF-SHA256 / AES-256-GCM                HKDF-SHA256 / AES-256-GCM
  (WebCrypto)                              (WebCrypto)
  IndexedDB (wrapped keys only)            IndexedDB (wrapped keys only)
        │                                        │
        └──────────────── WSS + REST ────────────┘
                          │
                 FastAPI (blind relay)
                 auth · routing · storage
                 NEVER decrypts, NEVER
                 holds a private key
                          │
                    MongoDB
                 public keys · ciphertext
                 · routing metadata only
```

## What's verified, and how

- **Backend**: `backend/tests/test_relay.py` — tests, including a
  static check that the backend's own source code never references
  private keys or decrypt/decapsulate operations.
- **Frontend crypto logic**: `frontend/tests/crypto_stack.test.mjs` —
  cryptographic assertions covering identity, pending-session persistence,
  handshake verification, message encryption, tamper detection, and replay checks.
- **Full integration**: `frontend/tests/integration.test.mjs` — the
  real crypto modules driven against the real running backend over
  real HTTP/WebSocket, including a first-contact message encrypted and
  stored while the recipient has no live WebSocket, then decrypted after
  the recipient logs in.
- **Not verified**: actual React rendering in a browser (no headless
  browser was available in the sandbox this was built in). See
  `frontend/README.md`'s test section for what that means in practice.

## Deviation from v1

The first build of this app (delivered earlier, not part of this
directory) ran all PQC operations server-side. That directly
contradicted REQ-KEY-1 through REQ-KEY-3, REQ-HIST-2, and §5.3 of the
SRS. This is the corrected version — see the two documents' worth of
back-and-forth in the conversation history if you want the full
reasoning trail, but the short version: this version, not the server-side
one, is what satisfies the SRS.

## User discovery

The sidebar starts empty and searches only after at least three username
characters are entered. The authenticated `GET /api/users/search?q=...`
endpoint returns at most 10 prefix matches and excludes the signed-in user;
the unfiltered `GET /api/users` directory endpoint has been removed. This
reduces casual account enumeration but is not a privacy boundary: a deployment
that must hide membership should use invite-based discovery, rate limiting,
and a login flow that does not disclose whether a username exists.

## Scope

Explicitly not built (per SRS §2.5 / Appendix A): group chat,
multi-device sync, full offline queueing beyond simple store-and-forward,
federation, HSM/secure enclaves, Double-Ratchet-style out-of-order
handling, i18n.

## Conversation inbox and unread counts

The sidebar has two distinct sections: **Chats** and **Find People**. Chats are
built only from stored messages involving the signed-in user and are ordered by
latest activity. Each row shows the peer, a latest-message preview, time, and
unread count. The backend sends only the latest ciphertext/metadata; the React
client decrypts the preview locally if it has the corresponding session key.
If the key is unavailable, the preview remains `Encrypted message`.

The authenticated `GET /api/conversations` endpoint returns the user's inbox
summaries, while `POST /api/conversations/{peer}/read` marks messages addressed
to the signed-in user as read when a conversation is opened. New incoming
messages refresh the inbox immediately through the WebSocket event flow, with
a 10-second refresh interval as a fallback. Opening a conversation clears its
unread count after history is loaded.

## Chat UI and message status

The chat view groups nearby messages from the same sender, shows local-time
message timestamps and date separators, and displays a status beside outgoing
messages. `sending` is local; `sent` means FastAPI stored the ciphertext; and
`delivered` means the recipient client acknowledged that it successfully
authenticated/decrypted the message. It is a delivery receipt, not a read
receipt. The expandable header status shows relay connectivity and the named
cryptographic primitives, and explicitly labels this build as a research
prototype. These UI indicators are not a proof or independent attestation of
security.

### Offline-recipient store-and-forward

On first contact, the sender can derive a local session key from the
recipient's registered ML-KEM public key and queue the signed handshake even
when the recipient is not connected. The composer becomes available once the
local key is ready and the relay connection is available. Outgoing messages
are encrypted in the browser and stored by FastAPI/MongoDB as ciphertext. When
the recipient next logs in, the client retrieves the pending handshake,
verifies it, decapsulates locally, derives the same session key, downloads the
ciphertext history, decrypts it locally, and sends delivery acknowledgements.
The sender's pending handshake envelope is wrapped/stored locally with its
session-key record so the exact same handshake can be resent after a reload;
creating a different handshake while ciphertext is queued would make those
messages undecryptable.

This is basic store-and-forward, not a complete asynchronous messaging
protocol. The recipient must already be registered with public keys, and the
sender must be connected to the relay long enough for the handshake and
ciphertext to be persisted. Messages cannot be guaranteed delivered if the
relay is unavailable, and the design does not implement one-time prekeys, a
Double Ratchet, or production-grade forward secrecy.

History is returned in server-timestamp order because sequence numbers are
maintained per sender/direction. The integration test covers the
sent-to-delivered receipt flow and the offline-recipient queue when run against
a live backend.

## Handshake arbitration and session-key versions

Each new handshake has a distinct ID. The relay serializes handshakes for the same pair so two simultaneous initiations do not overwrite the same pending session record. New message envelopes carry this `key_id`; it is included in AES-GCM associated data and saved with ciphertext metadata. IndexedDB stores the wrapped key for each handshake ID as well as the active key, allowing messages from earlier retained versions to be decrypted locally after a re-handshake.

The full rationale and recovery steps are in `SESSION_KEY_VERSION_FIX.md`. Messages from earlier builds may remain unreadable if their original key was already overwritten and no copy remains in local IndexedDB.

## Deploy publicly (Render)

A single-service Docker deployment file is included at `Dockerfile`, with Render Blueprint configuration in `render.yaml`. The same FastAPI service serves the built React frontend, `/api` REST routes, and `/ws` WebSockets on one HTTPS origin. Follow `DEPLOY_RENDER.md`; set `MONGODB_URI` in Render's environment settings and never commit it to Git.
