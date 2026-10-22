# PQChat v2 — Backend (blind relay)

FastAPI service. Never sees a private key, never decrypts anything —
see `tests/test_relay.py`, which enforces that at the code level.

## Run it against MongoDB Atlas (recommended)

1. Create a free M0 cluster at [mongodb.com/cloud/atlas/register](https://www.mongodb.com/cloud/atlas/register).
2. **Database Access** → add a database user (username + password, read/write to any database).
3. **Network Access** → add your IP (or `0.0.0.0/0` for local dev — fine for a PoC, not for anything with real data).
4. **Database → Connect → Drivers → Python** → copy the connection string. It looks like:
   ```
   mongodb+srv://<db-user>:<db-password>@<cluster-host>/?retryWrites=true&w=majority
   ```

Then:

```bash
pip install -r requirements.txt --break-system-packages   # drop the flag if not needed
export MONGODB_URI="mongodb+srv://<db-user>:<db-password>@<cluster-host>/?retryWrites=true&w=majority"
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

`db.py` reads `MONGODB_URI` straight from the environment — no code
changes needed. `dnspython` (in `requirements.txt`) is required for the
`mongodb+srv://` scheme Atlas uses.

To verify it's actually connected: register a user through the app,
then check Atlas's web UI (**Database → Browse Collections**) — you
should see a `pqchat` database with a `users` collection containing
that registration (public keys only, no private key material).

## Run against any other real MongoDB

Same idea — just point `MONGODB_URI` at it:

```bash
export MONGODB_URI="mongodb://localhost:27017"   # self-hosted / Docker
```

```bash
docker run -d -p 27017:27017 --name pqchat-mongo mongo:7
```

## Run without any real database (quick local testing only)

```bash
export PQCHAT_USE_MONGOMOCK=1
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

In-memory mock, same query API — fine for kicking the tires or running
the test suite, but nothing persists across a restart. Don't use this
for your actual demo/benchmarks.

## Run the tests

```bash
PQCHAT_USE_MONGOMOCK=1 python3 -m pytest tests/test_relay.py -v
```

## Files

- `main.py` — REST endpoints (authenticated username-prefix search, ciphertext-only inbox summaries, read-state updates) + WebSocket relay (`/ws`, first frame auth)
- `auth.py` — account login only (PBKDF2 verifier, bearer tokens). Has
  nothing to do with the client-side password that wraps PQC private
  keys in the browser's IndexedDB — that value never reaches this file.
- `db.py` — Motor/MongoDB collections + indexes (`users`, `sessions`,
  `messages`); reads `MONGODB_URI` from the environment (defaults to
  `mongodb://localhost:27017` if unset); `PQCHAT_USE_MONGOMOCK=1` swaps
  in an in-memory mock
- `models.py` — Pydantic schemas; every field is something the server
  is allowed to see (usernames, public keys, ciphertext, nonces,
  handshake signatures, timestamps, sequence numbers) — never a
  private key or plaintext
- `tests/test_relay.py` — asserts (a) no backend source file references
  private keys/decrypt/decapsulate by name, and (b) a full
  register → login → key-lookup → history flow works using only public
  data

## User discovery endpoint

`GET /api/users/search?q=<prefix>` requires authentication, a query of at least
three characters, and returns at most 10 matching usernames. The old unfiltered
`GET /api/users` directory endpoint is removed. Search limits reduce casual
enumeration; they are not a strong privacy boundary on their own.

## Conversation inbox endpoints

- `GET /api/conversations` — requires a bearer token and returns peers with stored messages, latest ciphertext/metadata, timestamps, and per-user unread counts. It does not return plaintext previews.
- `POST /api/conversations/{peer}/read` — requires a bearer token and marks incoming records from that peer as read for the authenticated user.

The frontend derives preview text locally using the browser-held session key. If the key isn't available yet, it shows a generic encrypted-message preview until the handshake/session key is restored.

## What's still needed

The frontend (React + `@noble/post-quantum` + IndexedDB) is what
actually performs key generation, the handshake, and message
encryption/decryption — this backend only routes and stores what that
client sends it. See `../frontend/README.md`.
