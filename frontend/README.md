# PQChat v2 — Frontend

React 18 + Vite. This is where all the actual cryptography happens —
ML-KEM-768/ML-DSA-65 keygen, the handshake, and message
encryption/decryption all run here, in the browser, never on the server.

## Run it

Needs the backend running first (see `../backend/README.md`).

```bash
npm install
npm run dev
```

Opens on `http://localhost:5173`. The dev server proxies `/api` and `/ws`
to `http://localhost:8000` (see `vite.config.js`) — if your backend runs
on a different port, edit the proxy target there.

Open two browser windows (or one normal + one incognito) to register two
users and chat between them.

## Build for production

```bash
npm run build
```

Outputs to `dist/`. You'll need to point it at your backend's real URL
(the dev proxy only applies to `npm run dev`) — either serve it behind
the same reverse proxy as the backend, or adjust `src/api/rest.js` /
`src/api/ws.js` to use an absolute backend URL.

## Tests

Two test suites, both passing as of this build:

```bash
npm run test:crypto        # standalone: identity/handshake/session/AEAD logic, no network
npm run test:integration   # requires backend running on :8000 — real HTTP + WebSocket
```

`tests/crypto_stack.test.mjs` — 12 assertions: keygen, wrong-password
rejection, handshake, tampered-signature rejection, session key
derivation, message round-trip, tampered-ciphertext rejection,
AAD-tamper rejection, replay detection, key persistence across reload.

`tests/integration.test.mjs` — the same crypto modules driven against
the **real running backend** over real HTTP/WebSocket: register, login
(including real server-side wrong-password rejection), public-key
lookup, handshake relay, shared-secret match after a real network
round-trip, encrypted message send/receive, history fetch (proving the
server never stores plaintext), and offline handshake store-and-forward
(a third user who wasn't connected yet still completes the handshake
correctly once they "log in").

**What's not tested:** I don't have a working headless browser in the
environment I built this in (network-restricted sandbox couldn't fetch
Playwright's browser binary), so the React components themselves —
actual rendering, clicking through Register → Login → chat in a real
DOM — are unverified beyond a clean `vite build`. The crypto and
networking logic those components call is thoroughly tested; the UI
wiring on top of it (state updates, button handlers) is not. Worth
clicking through it yourself once before treating this as final —
if anything's off it's most likely in `App.jsx`'s state management,
not the crypto.

## Layout

```
src/
├── crypto/
│   ├── identity.js    ML-KEM-768 + ML-DSA-65 keygen, password wrapping, IndexedDB
│   ├── handshake.js    encapsulate/decapsulate + sign/verify
│   ├── session.js      HKDF-SHA256 session key derivation + wrapped persistence
│   ├── aead.js          AES-256-GCM encrypt/decrypt, AAD binding, sequence/replay tracking
│   ├── benchmark.js     timing harness + CSV/JSON export
│   ├── webcrypto.js     PBKDF2/HKDF/AES-GCM wrappers + encoding helpers
│   └── store.js          IndexedDB persistence (wrapped data only)
├── api/
│   ├── rest.js    fetch() wrappers
│   └── ws.js       WebSocket client with auto-reconnect
├── components/     Register, Login, ContactList, HandshakeStatus,
│                   ChatWindow, MessageComposer, BenchmarkPanel
├── App.jsx          orchestrates auth/handshake/messaging state
└── main.jsx
```

## Security notes specific to this client

- **Two separate passwords-in-spirit, one field in the UI.** The
  password you type derives two independent things via two independent
  salts: an account-login verifier (sent to the server) and a
  key-wrapping key (never sent anywhere, wraps your private keys in
  IndexedDB). See `identity.js` for the exact derivation.
- **Identity is local to this browser profile.** There's no
  cross-device sync (out of scope per the SRS) — registering in Chrome
  and logging in from Firefox, or a different machine, won't find your
  identity. The Login screen says so if it can't find one.
- **ML-DSA signs the handshake only, not every message** — see the
  comment at the top of `aead.js` for why (a per-message signature would
  blow the SRS's ~5ms message-crypto budget). Message integrity instead
  comes from AEAD with sender/recipient/sequence_number bound into the
  associated data.
