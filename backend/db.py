"""
db.py

MongoDB access layer via Motor (async driver), per SRS §3.3/§6.

Collections (see README for full schema docs):
  - users     : username, password auth material, PUBLIC keys only
  - sessions  : routing metadata only (participants, session_id)
  - messages  : ciphertext + metadata only, never plaintext

Default target is MongoDB Atlas (a free M0 cluster is enough for this
PoC). Set MONGODB_URI to your Atlas connection string, e.g.:
  mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
Any real MongoDB 6.x+ instance (Atlas, self-hosted, Docker) works
identically — nothing here is Atlas-specific beyond the URI itself.
Note: mongodb+srv:// URIs require the `dnspython` package (see
requirements.txt).

For quick local testing without any real database at all, set
PQCHAT_USE_MONGOMOCK=1 to swap in an in-memory mongomock client with
the same query interface. Convenient for running the test suite, but
nothing persists across a restart — don't use it for your actual demo
or benchmarks.
"""

import os

USE_MOCK = os.environ.get("PQCHAT_USE_MONGOMOCK") == "1"

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("PQCHAT_DB_NAME", "pqchat")

if USE_MOCK:
    import mongomock

    _client = mongomock.MongoClient()
    db = _client[DB_NAME]
else:
    from motor.motor_asyncio import AsyncIOMotorClient

    _client = AsyncIOMotorClient(MONGODB_URI)
    db = _client[DB_NAME]

users = db["users"]
sessions = db["sessions"]
messages = db["messages"]


async def _ensure_indexes_async():
    await users.create_index("username", unique=True)
    await sessions.create_index("session_id", unique=True)
    await messages.create_index([("session_id", 1), ("sequence_number", 1)])
    await messages.create_index([("session_id", 1), ("timestamp", 1)])
    await messages.create_index([("session_id", 1), ("key_id", 1)])
    await messages.create_index([("client_message_id", 1), ("sender", 1), ("recipient", 1)])
    await messages.create_index([("recipient", 1), ("read_at", 1), ("timestamp", 1)])


def _ensure_indexes_sync():
    users.create_index("username", unique=True)
    sessions.create_index("session_id", unique=True)
    messages.create_index([("session_id", 1), ("sequence_number", 1)])
    messages.create_index([("session_id", 1), ("timestamp", 1)])
    messages.create_index([("session_id", 1), ("key_id", 1)])
    messages.create_index([("client_message_id", 1), ("sender", 1), ("recipient", 1)])
    messages.create_index([("recipient", 1), ("read_at", 1), ("timestamp", 1)])


async def ensure_indexes():
    """Call once at startup. Handles both the mock (sync) and real
    (async) motor client transparently."""
    if USE_MOCK:
        _ensure_indexes_sync()
    else:
        await _ensure_indexes_async()


def session_id_for(user_a: str, user_b: str) -> str:
    return "|".join(sorted([user_a, user_b]))
