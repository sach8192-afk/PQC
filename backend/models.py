"""
models.py

Pydantic schemas for the blind-relay REST API. Every field here is
something the server is allowed to see: usernames, PUBLIC keys,
ciphertext, nonces, signatures (handshake only), timestamps, sequence
numbers. Nothing here is ever a private key or plaintext message.
"""

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password_verifier: str  # PBKDF2-SHA256 hex digest computed client-side; see README
    password_salt: str      # hex, client-generated, used only for login verification
    kem_public_key: str     # hex, ML-KEM-768, 1184 bytes
    sig_public_key: str     # hex, ML-DSA-65, 1952 bytes


class LoginRequest(BaseModel):
    username: str
    password_verifier: str


class PublicKeysResponse(BaseModel):
    username: str
    kem_public_key: str
    sig_public_key: str


class MessageOut(BaseModel):
    sender: str
    recipient: str
    ciphertext: str      # hex-encoded AES-GCM ciphertext
    nonce: str            # hex-encoded AES-GCM nonce
    sequence_number: int
    timestamp: str
    client_message_id: str | None = None
    key_id: str | None = None
    delivery_status: str | None = "sent"
