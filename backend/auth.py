"""
auth.py

Account authentication only — has nothing to do with the client-side
key-wrapping password used to encrypt ML-KEM/ML-DSA secret keys in
IndexedDB (that value and its derivation never reach this server at all).

Flow:
  1. Client derives `password_verifier = PBKDF2-SHA256(password, client_salt)`
     using a salt IT generates and keeps (client_salt == `password_salt`
     in the register/login request). This is a routine "don't send the
     raw password over the wire" step.
  2. This server treats `password_verifier` as the credential and never
     sees the underlying password. To avoid a bare pass-the-hash risk if
     the `users` collection ever leaks, the server re-hashes the verifier
     with its own server-side salt before persisting.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

# A deployment must keep PQCHAT_AUTH_SECRET stable across restarts. If it is
# omitted locally, a process-random signing key preserves the simple dev setup.
_AUTH_SIGNING_KEY = (os.environ.get("PQCHAT_AUTH_SECRET") or secrets.token_hex(32)).encode("utf-8")
TOKEN_TTL_SECONDS = int(os.environ.get("PQCHAT_TOKEN_TTL_SECONDS", str(12 * 60 * 60)))
REVOKED_TOKENS: set[str] = set()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _server_hash(verifier: str, server_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", verifier.encode("utf-8"), server_salt, 200_000, dklen=32)


def make_server_credential(password_verifier: str) -> dict:
    server_salt = os.urandom(16)
    h = _server_hash(password_verifier, server_salt)
    return {"server_salt": server_salt.hex(), "server_hash": h.hex()}


def check_server_credential(password_verifier: str, server_salt_hex: str, server_hash_hex: str) -> bool:
    server_salt = bytes.fromhex(server_salt_hex)
    h = _server_hash(password_verifier, server_salt)
    return hmac.compare_digest(h.hex(), server_hash_hex)


def issue_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
        "jti": secrets.token_urlsafe(18),
    }
    encoded = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64url(hmac.new(_AUTH_SIGNING_KEY, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def resolve_token(token: str) -> str | None:
    if not isinstance(token, str) or not token or token in REVOKED_TOKENS:
        return None
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected_signature = _b64url(
            hmac.new(_AUTH_SIGNING_KEY, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        payload = json.loads(_unb64url(encoded).decode("utf-8"))
        username = payload.get("sub")
        expires_at = payload.get("exp")
        if not isinstance(username, str) or not username:
            return None
        if not isinstance(expires_at, int) or expires_at <= int(time.time()):
            return None
        return username
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def revoke_token(token: str) -> None:
    # Logout revocation is immediate for the lifetime of this process. The
    # token also expires, limiting the impact of a token surviving a restart.
    if isinstance(token, str) and token:
        REVOKED_TOKENS.add(token)
