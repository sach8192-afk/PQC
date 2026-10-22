import { useState, useEffect, useRef, useCallback } from "react";
import Register from "./components/Register.jsx";
import Login from "./components/Login.jsx";
import ContactList from "./components/ContactList.jsx";
import HandshakeStatus from "./components/HandshakeStatus.jsx";
import ChatWindow from "./components/ChatWindow.jsx";
import MessageComposer from "./components/MessageComposer.jsx";
import BenchmarkPanel from "./components/BenchmarkPanel.jsx";

import { initiateHandshake, respondToHandshake } from "./crypto/handshake.js";
import { establishSessionKey, loadSessionKeyFor, loadSessionStatusFor, loadPendingHandshakeFor, loadActiveSessionKeyIdFor, markSessionEstablished } from "./crypto/session.js";
import { encryptMessage, decryptMessage, nextOutgoingSequence } from "./crypto/aead.js";
import { decryptStoredMessage } from "./crypto/history.js";
import {
  apiSearchUsers,
  apiGetPublicKeys,
  apiGetPendingHandshakes,
  apiConsumeHandshake,
  apiGetHistory,
  apiGetConversations,
  apiMarkConversationRead,
  apiLogout,
} from "./api/rest.js";
import { connectWebSocket } from "./api/ws.js";

export default function App() {
  const [screen, setScreen] = useState("auth"); // 'auth' | 'app'
  const [me, setMe] = useState(null); // { username, kemSecretKey, sigSecretKey, ..., wrappingKey }
  const [token, setToken] = useState(null);

  // Search results only. The app deliberately does not preload a global user directory.
  const [users, setUsers] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [inboxError, setInboxError] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchLoading, setSearchLoading] = useState(false);
  const [activePeer, setActivePeer] = useState(null);
  const [handshakeState, setHandshakeState] = useState({}); // peer -> 'idle'|'establishing'|'established'|'failed'
  const [sessionKeys, setSessionKeys] = useState({}); // peer -> CryptoKey
  const [messages, setMessages] = useState({}); // peer -> [{sender, text, timestamp, replayWarning, unverified}]
  const [showBenchmark, setShowBenchmark] = useState(false);
  const [relayConnected, setRelayConnected] = useState(false);
  const [error, setError] = useState(null);

  const wsRef = useRef(null);
  const meRef = useRef(null);
  const activePeerRef = useRef(activePeer);
  const inboxRefreshIdRef = useRef(0);
  const sessionKeysRef = useRef({});
  const sessionKeyIdsRef = useRef({}); // peer -> handshake/key version used for outgoing messages
  const pendingDeliveryAcksRef = useRef([]);
  const pendingHandshakeKeysRef = useRef({});
  const pendingHandshakeIdsRef = useRef({});
  const pendingHandshakeEnvelopesRef = useRef({});
  const pendingIncomingMessagesRef = useRef({});
  const handshakeTimersRef = useRef({});
  meRef.current = me;
  activePeerRef.current = activePeer;
  sessionKeysRef.current = sessionKeys;

  // Refresh conversation metadata from the relay, then decrypt only the latest
  // ciphertext on this client to build the sidebar preview. Plaintext is never
  // requested from or returned by the backend.
  const refreshConversations = useCallback(async () => {
    const identity = meRef.current;
    if (!token || !identity) return;
    const refreshId = ++inboxRefreshIdRef.current;
    try {
      const response = await apiGetConversations(token);
      const rows = Array.isArray(response.conversations) ? response.conversations : [];
      const hydrated = await Promise.all(rows.map(async (conversation) => {
        const peer = conversation.peer;
        const message = conversation.last_message;
        let preview = message ? "Encrypted message" : "";
        if (message) {
          const sessionId = [identity.username, peer].sort().join("|");
          try {
            const activeKeyId = sessionKeyIdsRef.current[peer]
              || await loadActiveSessionKeyIdFor(sessionId, identity.username, identity.wrappingKey).catch(() => null);
            let activeSessionKey = sessionKeysRef.current[peer] || null;
            if (!activeSessionKey) {
              activeSessionKey = await loadSessionKeyFor(
                sessionId,
                identity.wrappingKey,
                activeKeyId || null,
                identity.username
              ).catch(() => null);
            }
            const result = await decryptStoredMessage({
              message,
              sessionId,
              wrappingKey: identity.wrappingKey,
              activeSessionKey,
              activeKeyId,
              ownerUsername: identity.username,
            });
            const compact = result.plaintext.replace(/\s+/g, " ").trim();
            preview = compact || "Message";
          } catch (err) {
            // Keep previews opaque if no locally-held key can authenticate the
            // ciphertext. Never ask the server for plaintext or weaken AEAD.
            console.warn("Could not decrypt latest inbox preview", {
              peer,
              sequenceNumber: message.sequence_number,
              keyId: message.key_id || null,
              reason: err?.message || "decryption failed",
            });
            preview = "Encrypted message";
          }
          if (message.sender === identity.username) preview = `You: ${preview}`;
        }
        return { ...conversation, preview };
      }));
      if (refreshId === inboxRefreshIdRef.current) {
        setConversations(hydrated);
        setInboxError(null);
      }
    } catch (err) {
      console.warn("Could not refresh conversation inbox:", err);
      if (refreshId === inboxRefreshIdRef.current) {
        setInboxError(err?.message || "Inbox request failed");
      }
    }
  }, [token]);

  // ---------------- auth ----------------

  async function handleLoggedIn(identity, authToken) {
    setMe(identity);
    setToken(authToken);
    setScreen("app");
  }

  async function handleLogout() {
    if (token) await apiLogout(token).catch(() => {});
    wsRef.current?.close();
    wsRef.current = null;
    setMe(null);
    setToken(null);
    setScreen("auth");
    setUsers([]);
    setConversations([]);
    setInboxError(null);
    inboxRefreshIdRef.current += 1;
    setSearchQuery("");
    setSearchLoading(false);
    setActivePeer(null);
    setHandshakeState({});
    setSessionKeys({});
    sessionKeyIdsRef.current = {};
    setMessages({});
    setRelayConnected(false);
    pendingDeliveryAcksRef.current = [];
    pendingHandshakeKeysRef.current = {};
    pendingHandshakeIdsRef.current = {};
    pendingHandshakeEnvelopesRef.current = {};
    pendingIncomingMessagesRef.current = {};
    for (const timer of Object.values(handshakeTimersRef.current)) window.clearTimeout(timer);
    handshakeTimersRef.current = {};
  }

  // Delivery receipts can be generated while the WebSocket is still
  // reconnecting (for example while decrypting stored history). Queue these
  // metadata-only acknowledgements until the relay connection is open.
  function sendDeliveryAck(envelope) {
    if (wsRef.current?.send(envelope) === true) return true;
    const queue = pendingDeliveryAcksRef.current;
    const duplicate = queue.some((item) =>
      item.client_message_id === envelope.client_message_id && item.to === envelope.to
    );
    if (!duplicate) queue.push(envelope);
    return false;
  }

  // Apply server-confirmed status without allowing a late `sent` event to
  // downgrade a bubble that has already been marked delivered.
  const handleMessageStatus = useCallback((envelope) => {
    if (!envelope?.client_message_id || !envelope?.status) return;
    if (envelope.status === "failed" && envelope.reason === "session_key_epoch_not_reserved") {
      const peer = envelope.peer || activePeerRef.current;
      const activeKeyId = peer ? (sessionKeyIdsRef.current[peer] || null) : null;
      if (peer && activeKeyId === (envelope.key_id || null)) {
        const nextKeys = { ...sessionKeysRef.current };
        delete nextKeys[peer];
        sessionKeysRef.current = nextKeys;
        setSessionKeys(nextKeys);
        const nextIds = { ...sessionKeyIdsRef.current };
        delete nextIds[peer];
        sessionKeyIdsRef.current = nextIds;
        setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
        setError("This browser's session key does not match the relay's accepted handshake. Retry the secure session to synchronize both accounts.");
      }
    }
    const rank = { sending: 0, sent: 1, failed: 2, delivered: 3 };
    setMessages((prev) => {
      let anyChanged = false;
      const next = { ...prev };
      for (const [peer, items] of Object.entries(prev)) {
        let peerChanged = false;
        const updated = items.map((message) => {
          if (message.clientMessageId !== envelope.client_message_id) return message;
          const current = message.deliveryStatus || "sent";
          const incoming = envelope.status;
          if (rank[incoming] === undefined || (rank[current] ?? 0) > rank[incoming]) return message;
          if (current === incoming) return message;
          peerChanged = true;
          return { ...message, deliveryStatus: incoming };
        });
        if (peerChanged) {
          next[peer] = updated;
          anyChanged = true;
        }
      }
      return anyChanged ? next : prev;
    });
  }, []);

  // ---------------- data load + websocket wiring ----------------

  useEffect(() => {
    if (screen !== "app" || !token) return;

    // User discovery is handled by a separate search effect below. Do not
    // enumerate every registered account when a user logs in.

    // Fetch offline handshakes only after the WebSocket is open; otherwise
    // a handshake ACK can be dropped before wsRef.current is assigned.
    async function processPendingHandshakes() {
      try {
        const { pending } = await apiGetPendingHandshakes(token);
        for (const envelope of pending) {
          const established = await completeIncomingHandshake(envelope);
          const responseEnvelope = established
            ? {
                type: "handshake_ack",
                to: envelope.from,
                session_id: envelope.session_id,
                handshake_id: envelope.handshake_id,
              }
            : {
                type: "handshake_reject",
                to: envelope.from,
                session_id: envelope.session_id,
                handshake_id: envelope.handshake_id,
              };
          const responseSent = wsRef.current?.send(responseEnvelope) === true;
          // Don't consume the pending handshake unless its result can be
          // acknowledged over an open socket. It will be retried on reconnect.
          if (established && responseSent) {
            await apiConsumeHandshake(token, envelope.session_id).catch(() => {});
          }
        }
      } catch (err) {
        console.warn("Could not fetch pending handshakes:", err);
      }
    }

    const ws = connectWebSocket(token, {
      onHandshakeInit: async (envelope) => {
        const established = await completeIncomingHandshake(envelope);
        if (established) {
          wsRef.current?.send({
            type: "handshake_ack",
            to: envelope.from,
            session_id: envelope.session_id,
            handshake_id: envelope.handshake_id,
          });
          await apiConsumeHandshake(token, envelope.session_id).catch(() => {});
        } else {
          wsRef.current?.send({
            type: "handshake_reject",
            to: envelope.from,
            session_id: envelope.session_id,
            handshake_id: envelope.handshake_id,
          });
        }
      },
      onHandshakeAccepted: async (envelope) => {
        const peer = envelope.from;
        const identity = meRef.current;
        if (!identity || envelope.session_id !== [identity.username, peer].sort().join("|")) return;
        // Acceptance is specific to the current attempt. A stale accept from a
        // prior handshake must never enable the composer with the wrong key.
        if (!envelope.handshake_id || pendingHandshakeIdsRef.current[peer] !== envelope.handshake_id) return;
        let key = pendingHandshakeKeysRef.current[peer] || null;
        if (!key) {
          key = await loadSessionKeyFor(envelope.session_id, identity.wrappingKey, envelope.handshake_id, identity.username).catch(() => null);
        }
        if (!key) {
          setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
          setError("The relay accepted the handshake, but its local session key is unavailable. Retry the secure session.");
          return;
        }
        sessionKeysRef.current = { ...sessionKeysRef.current, [peer]: key };
        sessionKeyIdsRef.current = { ...sessionKeyIdsRef.current, [peer]: envelope.handshake_id };
        setSessionKeys((prev) => ({ ...prev, [peer]: key }));
        if (envelope.status === "established") {
          setHandshakeState((prev) => ({ ...prev, [peer]: "established" }));
          await markSessionEstablished(envelope.session_id, envelope.handshake_id, identity.username).catch(() => {});
          delete pendingHandshakeKeysRef.current[peer];
          delete pendingHandshakeIdsRef.current[peer];
          delete pendingHandshakeEnvelopesRef.current[peer];
          await loadHistory(peer, key, activePeerRef.current === peer).catch((err) => {
            console.warn("Could not load history after accepted established session:", err);
          });
        } else {
          // The relay has reserved this exact handshake. The peer may be
          // offline, so queued messaging is now safe even without peer ACK.
          setHandshakeState((prev) => ({ ...prev, [peer]: "pending" }));
        }
        setError(null);
      },
      onHandshakeAck: async (envelope) => {
        const peer = envelope.from;
        const identity = meRef.current;
        if (!identity || envelope.session_id !== [identity.username, peer].sort().join("|")) return;
        const expectedHandshakeId = pendingHandshakeIdsRef.current[peer];
        // A delayed ACK from an older/retried handshake must not confirm the
        // key derived by a different attempt.
        if (!expectedHandshakeId || envelope.handshake_id !== expectedHandshakeId) return;
        let key = pendingHandshakeIdsRef.current[peer] === envelope.handshake_id
          ? pendingHandshakeKeysRef.current[peer]
          : null;
        if (!key) {
          key = await loadSessionKeyFor(
            envelope.session_id,
            identity.wrappingKey,
            envelope.handshake_id,
            identity.username
          ).catch(() => null);
        }
        if (!key) return;
        if (handshakeTimersRef.current[peer]) {
          window.clearTimeout(handshakeTimersRef.current[peer]);
          delete handshakeTimersRef.current[peer];
        }
        setHandshakeState((prev) => ({ ...prev, [peer]: "established" }));
        sessionKeysRef.current = { ...sessionKeysRef.current, [peer]: key };
        sessionKeyIdsRef.current = { ...sessionKeyIdsRef.current, [peer]: envelope.handshake_id };
        await markSessionEstablished(envelope.session_id, envelope.handshake_id, identity.username).catch((err) => {
          console.warn("Could not persist peer-confirmed session status:", err);
        });
        delete pendingHandshakeKeysRef.current[peer];
        delete pendingHandshakeIdsRef.current[peer];
        delete pendingHandshakeEnvelopesRef.current[peer];
        setError(null);
        try {
          await loadHistory(peer, key, activePeerRef.current === peer);
          await flushPendingChatMessages(peer);
          await refreshConversations();
        } catch (err) {
          console.error("Could not load chat history:", err);
          setError("Secure session established, but message history could not be loaded.");
        }
      },
      onHandshakeError: async (envelope) => {
        const peer = envelope.from;
        const failedId = envelope.handshake_id;
        if (peer && failedId && pendingHandshakeIdsRef.current[peer] !== failedId) return;
        if (peer && handshakeTimersRef.current[peer]) {
          window.clearTimeout(handshakeTimersRef.current[peer]);
          delete handshakeTimersRef.current[peer];
        }

        // If this was a crossed-handshake race, the relay's winning attempt
        // may be waiting for this account. Adopt that exact pending envelope
        // rather than launching another conflicting KEM exchange.
        if (peer && envelope.reason === "another_handshake_pending" && envelope.session_id) {
          try {
            const { pending } = await apiGetPendingHandshakes(token);
            const winningEnvelope = (pending || []).find((item) =>
              item.session_id === envelope.session_id && item.from === peer && item.handshake_id !== failedId
            );
            if (winningEnvelope) {
              const received = await completeIncomingHandshake(winningEnvelope);
              if (received) {
                wsRef.current?.send({
                  type: "handshake_ack",
                  to: peer,
                  session_id: winningEnvelope.session_id,
                  handshake_id: winningEnvelope.handshake_id,
                });
                await apiConsumeHandshake(token, winningEnvelope.session_id).catch(() => {});
                if (pendingHandshakeIdsRef.current[peer] === failedId) {
                  delete pendingHandshakeKeysRef.current[peer];
                  delete pendingHandshakeIdsRef.current[peer];
                  delete pendingHandshakeEnvelopesRef.current[peer];
                }
                setError(null);
                return;
              }
            }
          } catch (recoveryError) {
            console.warn("Could not adopt the relay's winning handshake:", recoveryError);
          }
        }

        if (peer) {
          const activeId = sessionKeyIdsRef.current[peer];
          // A different key version may already have won and been installed by
          // the incoming handshake handler. Do not clear it or show a stale
          // failure message just because the competing attempt was rejected.
          if (failedId && activeId && activeId !== failedId) {
            if (pendingHandshakeIdsRef.current[peer] === failedId) {
              delete pendingHandshakeKeysRef.current[peer];
              delete pendingHandshakeIdsRef.current[peer];
              delete pendingHandshakeEnvelopesRef.current[peer];
            }
            return;
          }
          setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
          const nextKeys = { ...sessionKeysRef.current };
          delete nextKeys[peer];
          sessionKeysRef.current = nextKeys;
          setSessionKeys(nextKeys);
          const nextIds = { ...sessionKeyIdsRef.current };
          delete nextIds[peer];
          sessionKeyIdsRef.current = nextIds;
          if (!failedId || pendingHandshakeIdsRef.current[peer] === failedId) {
            delete pendingHandshakeKeysRef.current[peer];
            delete pendingHandshakeIdsRef.current[peer];
            delete pendingHandshakeEnvelopesRef.current[peer];
          }
        }
        setError("A handshake attempt was rejected or superseded. Retry the secure session if no matching session is available.");
      },
      onChatMessage: async (envelope) => {
        await receiveChatMessage(envelope);
        await refreshConversations();
      },
      onMessageStatus: (envelope) => {
        handleMessageStatus(envelope);
        if (["sent", "delivered", "failed"].includes(envelope?.status)) {
          refreshConversations();
        }
      },
      onOpen: () => {
        setRelayConnected(true);
        refreshConversations();
        processPendingHandshakes();
        const queued = pendingDeliveryAcksRef.current.splice(0);
        for (const acknowledgement of queued) {
          if (wsRef.current?.send(acknowledgement) !== true) {
            pendingDeliveryAcksRef.current.unshift(acknowledgement);
            break;
          }
        }
      },
      onAuthError: () => {
        setError("Your login session has expired. Please log in again.");
        handleLogout();
      },
      onClose: () => setRelayConnected(false),
    });
    wsRef.current = ws;

    return () => {
      ws.close();
      wsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screen, token]);

  // Search only after at least three characters, debounce requests, and
  // ignore stale responses when the query changes quickly.
  useEffect(() => {
    if (screen !== "app" || !token) return;

    const query = searchQuery.trim();
    if (query.length < 3) {
      setUsers([]);
      setSearchLoading(false);
      return;
    }

    let cancelled = false;
    setSearchLoading(true);
    const timer = window.setTimeout(async () => {
      try {
        const results = await apiSearchUsers(token, query);
        if (!cancelled) setUsers(results);
      } catch (err) {
        if (!cancelled) {
          setUsers([]);
          setError(err.message || "Could not search users.");
        }
      } finally {
        if (!cancelled) setSearchLoading(false);
      }
    }, 250);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [screen, token, searchQuery]);

  // Keep the inbox current even if a connection event was missed during a
  // reconnect. WebSocket events still trigger immediate refreshes above.
  useEffect(() => {
    if (screen !== "app" || !token) return;
    refreshConversations();
    const timer = window.setInterval(refreshConversations, 10000);
    return () => window.clearInterval(timer);
  }, [screen, token, refreshConversations]);

  // ---------------- handshake ----------------

  const startHandshake = useCallback(
    async (peer) => {
      const identity = meRef.current;
      if (!identity || !token || !peer || peer === identity.username) return;

      const sessionId = [identity.username, peer].sort().join("|");
      // If this is a pending offline session, resend the exact same handshake
      // rather than generating a new secret that would strand queued messages.
      let pendingEnvelope = handshakeState[peer] === "failed" ? null : pendingHandshakeEnvelopesRef.current[peer];
      if (!pendingEnvelope && handshakeState[peer] !== "failed") {
        pendingEnvelope = await loadPendingHandshakeFor(sessionId, identity.username, identity.wrappingKey).catch(() => null);
      }
      if (pendingEnvelope) {
        try {
          setHandshakeState((prev) => ({ ...prev, [peer]: "establishing" }));
          const key = sessionKeyIdsRef.current[peer] === pendingEnvelope.handshake_id
            ? sessionKeysRef.current[peer]
            : await loadSessionKeyFor(sessionId, identity.wrappingKey, pendingEnvelope.handshake_id, identity.username);
          if (!key) throw new Error("Pending handshake has no corresponding local key version");
          sessionKeysRef.current = { ...sessionKeysRef.current, [peer]: key };
          sessionKeyIdsRef.current = { ...sessionKeyIdsRef.current, [peer]: pendingEnvelope.handshake_id };
          setSessionKeys((prev) => ({ ...prev, [peer]: key }));
          pendingHandshakeKeysRef.current[peer] = key;
          pendingHandshakeIdsRef.current[peer] = pendingEnvelope.handshake_id;
          pendingHandshakeEnvelopesRef.current[peer] = pendingEnvelope;
          const queued = wsRef.current?.send(pendingEnvelope) === true;
          if (!queued) throw new Error("WebSocket is not connected; handshake could not be queued");
          // Keep sending disabled until `handshake_accepted` confirms that
          // the relay reserved this exact ID (works offline and prevents races).
          setError(null);
          await loadHistory(peer, key, activePeerRef.current === peer).catch((err) => {
            console.warn("Could not load history for pending session:", err);
          });
          await refreshConversations();
          return;
        } catch (err) {
          console.error("Could not resend pending handshake:", err);
          setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
          setError("The handshake could not be reserved by the relay. Reconnect and retry the secure session.");
          return;
        }
      }

      setHandshakeState((prev) => ({ ...prev, [peer]: "establishing" }));
      setError(null);
      try {
        const { kem_public_key } = await apiGetPublicKeys(token, peer);
        const { sharedSecret, sessionId: derivedSessionId, envelope } = initiateHandshake({
          myUsername: identity.username,
          mySigSecretKey: identity.sigSecretKey,
          peerUsername: peer,
          peerKemPublicKeyHex: kem_public_key,
        });
        const handshakeId = makeClientMessageId();
        envelope.handshake_id = handshakeId;

        // The initiator can derive its local key immediately. Persist the
        // matching handshake envelope with the wrapped key so messages can be
        // queued offline and the exact handshake can be resent after reload.
        const key = await establishSessionKey({
          sharedSecret,
          sessionId: derivedSessionId,
          wrappingKey: identity.wrappingKey,
          status: "pending",
          pendingHandshake: envelope,
          handshakeId,
          ownerUsername: identity.username,
        });
        sessionKeysRef.current = { ...sessionKeysRef.current, [peer]: key };
        sessionKeyIdsRef.current = { ...sessionKeyIdsRef.current, [peer]: handshakeId };
        setSessionKeys((prev) => ({ ...prev, [peer]: key }));
        pendingHandshakeKeysRef.current[peer] = key;
        pendingHandshakeIdsRef.current[peer] = handshakeId;
        pendingHandshakeEnvelopesRef.current[peer] = envelope;

        const queued = wsRef.current?.send(envelope) === true;
        if (!queued) throw new Error("WebSocket is closing; handshake could not be queued");

        // Stay in `establishing` until the backend confirms reservation. This
        // still supports offline messaging; `handshake_accepted` transitions
        // to pending even when the recipient has no live socket.
        await loadHistory(peer, key, activePeerRef.current === peer).catch((historyError) => {
          console.warn("Could not load history for new local session:", historyError);
        });
        await refreshConversations();
      } catch (err) {
        console.error("Handshake initiation failed:", err);
        const storedKey = sessionKeysRef.current[peer];
        if (storedKey && pendingHandshakeEnvelopesRef.current[peer]) {
          setHandshakeState((prev) => ({ ...prev, [peer]: "pending" }));
          setError("The local session key is ready, but the handshake is waiting for the relay. Reconnect and retry; messages can be sent once the relay is connected.");
        } else {
          delete pendingHandshakeKeysRef.current[peer];
          delete pendingHandshakeIdsRef.current[peer];
          delete pendingHandshakeEnvelopesRef.current[peer];
          setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
          setError("Could not prepare the secure session. Check the connection and retry.");
        }
      }
    },
    [token, handshakeState]
  );

  async function completeIncomingHandshake(envelope) {
    const identity = meRef.current;
    const peer = envelope?.from;
    try {
      if (!identity || !peer || peer === identity.username) throw new Error("Invalid handshake peer");
      const expectedSessionId = [identity.username, peer].sort().join("|");
      if (envelope.session_id !== expectedSessionId) throw new Error("Handshake session ID mismatch");
      const { sig_public_key } = await apiGetPublicKeys(token, peer);
      const { sharedSecret, sessionId } = respondToHandshake({
        envelope,
        peerSigPublicKeyHex: sig_public_key,
        myKemSecretKey: identity.kemSecretKey,
      });
      if (sessionId !== expectedSessionId) throw new Error("Handshake session ID mismatch");
      const key = await establishSessionKey({
        sharedSecret,
        sessionId,
        wrappingKey: identity.wrappingKey,
        status: "established",
        handshakeId: envelope.handshake_id || null,
        ownerUsername: identity.username,
      });
      sessionKeysRef.current = { ...sessionKeysRef.current, [peer]: key };
      if (envelope.handshake_id) {
        sessionKeyIdsRef.current = { ...sessionKeyIdsRef.current, [peer]: envelope.handshake_id };
      } else {
        const nextIds = { ...sessionKeyIdsRef.current };
        delete nextIds[peer];
        sessionKeyIdsRef.current = nextIds;
      }
      setSessionKeys((prev) => ({ ...prev, [peer]: key }));
      setHandshakeState((prev) => ({ ...prev, [peer]: "established" }));
      // History failure should not invalidate a cryptographically successful
      // handshake; report it separately.
      await loadHistory(peer, key, activePeerRef.current === peer).catch((err) => {
        console.error("Could not load history after handshake:", err);
      });
      await flushPendingChatMessages(peer);
      await refreshConversations();
      return true;
    } catch (err) {
      setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
      setError("Secure connection could not be established.");
      console.error("Incoming handshake failed:", err);
      return false;
    }
  }

  // ---------------- messaging ----------------

  async function selectPeer(peer) {
    setActivePeer(peer);
    setError(null);
    if (peer === meRef.current?.username) return;
    if (handshakeState[peer] === "establishing") return;
    if ((handshakeState[peer] === "established" || handshakeState[peer] === "pending") && sessionKeysRef.current[peer]) {
      await loadHistory(peer, sessionKeysRef.current[peer], true).catch((err) => {
        console.error("Could not load selected conversation:", err);
        setError("Session key is available, but message history could not be loaded.");
      });
      return;
    }

    const identity = meRef.current;
    const sessionId = [identity.username, peer].sort().join("|");
    try {
      let existingKey = null;
      try {
        existingKey = await loadSessionKeyFor(sessionId, identity.wrappingKey, null, identity.username);
      } catch (storageError) {
        // A stale key may have been wrapped with an older browser identity or
        // password-derived wrapping key. Do not strand the user in idle state.
        console.warn("Saved session key could not be unlocked; re-establishing session:", storageError);
        setError("The saved session key could not be unlocked. Establishing a new session; older messages may be unreadable.");
      }

      const activeKeyId = await loadActiveSessionKeyIdFor(sessionId, identity.username, identity.wrappingKey).catch(() => null);
      if (existingKey && activeKeyId && handshakeState[peer] !== "failed") {
        const savedStatus = await loadSessionStatusFor(sessionId, activeKeyId, identity.username, identity.wrappingKey).catch(() => "pending");
        const matchingKey = await loadSessionKeyFor(sessionId, identity.wrappingKey, activeKeyId, identity.username).catch(() => null);
        if (!matchingKey) {
          await startHandshake(peer);
          return;
        }
        sessionKeysRef.current = { ...sessionKeysRef.current, [peer]: matchingKey };
        sessionKeyIdsRef.current = { ...sessionKeyIdsRef.current, [peer]: activeKeyId };
        setSessionKeys((prev) => ({ ...prev, [peer]: matchingKey }));
        setHandshakeState((prev) => ({ ...prev, [peer]: savedStatus === "established" ? "established" : "establishing" }));
        await loadHistory(peer, matchingKey, true).catch((err) => {
          console.error("Could not load history:", err);
          setError("Session key loaded, but history could not be retrieved.");
        });
        if (savedStatus !== "established") {
          const savedEnvelope = await loadPendingHandshakeFor(sessionId, identity.username, identity.wrappingKey).catch(() => null);
          if (savedEnvelope?.handshake_id) {
            pendingHandshakeEnvelopesRef.current[peer] = savedEnvelope;
            pendingHandshakeIdsRef.current[peer] = savedEnvelope.handshake_id;
            pendingHandshakeKeysRef.current[peer] = matchingKey;
            const queued = wsRef.current?.send(savedEnvelope) === true;
            if (!queued) {
              setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
              setError("Could not resend the saved handshake. Reconnect and retry.");
            }
          } else {
            await startHandshake(peer);
          }
        }
      } else {
        // Keys from builds before handshake versioning cannot be associated
        // with a specific handshake. Establish a new version rather than
        // trusting that the other browser retained the same key.
        await startHandshake(peer);
      }
    } catch (err) {
      console.error("Could not select chat:", err);
      setHandshakeState((prev) => ({ ...prev, [peer]: "failed" }));
      setError("Could not open this chat. Check your connection and retry.");
    }
  }

  async function loadHistory(peer, sessionKey, markRead = false) {
    const identity = meRef.current;
    const sessionId = [identity.username, peer].sort().join("|");
    const { messages: history } = await apiGetHistory(token, peer);
    const decoded = [];
    const historySequenceBySender = new Map();
    const activeKeyId = sessionKeyIdsRef.current[peer]
      || await loadActiveSessionKeyIdFor(sessionId, identity.username, identity.wrappingKey).catch(() => null);
    for (const m of history) {
      let plaintext;
      let decryptedKeyId = m.key_id || null;
      try {
        // History records from older backend builds may lack `key_id` even
        // though their ciphertext was authenticated with that ID as AAD.
        // Try retained local key versions with their matching AAD first, then
        // the legacy AAD format. AES-GCM still has to authenticate successfully.
        const result = await decryptStoredMessage({
          message: m,
          sessionId,
          wrappingKey: identity.wrappingKey,
          activeSessionKey: sessionKey,
          activeKeyId,
          ownerUsername: identity.username,
        });
        plaintext = result.plaintext;
        decryptedKeyId = m.key_id || result.keyIdUsed || null;
        const priorHistorySequence = historySequenceBySender.get(m.sender);
        const replayWarning = Number.isInteger(m.sequence_number) &&
          priorHistorySequence !== undefined && m.sequence_number <= priorHistorySequence;
        if (Number.isInteger(m.sequence_number)) {
          historySequenceBySender.set(m.sender, Math.max(priorHistorySequence ?? -1, m.sequence_number));
        }
        decoded.push({
          clientMessageId: m.client_message_id || null,
          sender: m.sender,
          text: plaintext,
          timestamp: m.timestamp,
          replayWarning,
          deliveryStatus: m.sender === identity.username ? (m.delivery_status || "sent") : undefined,
          sequenceNumber: m.sequence_number,
          keyId: decryptedKeyId,
        });
        // History can include messages that arrived while this user was offline.
        // Acknowledge only after local AEAD verification/decryption succeeds.
        if (m.sender !== identity.username && m.client_message_id && m.delivery_status !== "delivered") {
          sendDeliveryAck({
            type: "delivery_ack",
            to: m.sender,
            session_id: sessionId,
            client_message_id: m.client_message_id,
            sequence_number: m.sequence_number,
          });
        }
      } catch (err) {
        // Safe diagnostics: never log ciphertext, plaintext, or key material.
        console.warn("History message could not be authenticated/decrypted", {
          peer,
          sender: m.sender,
          sequenceNumber: m.sequence_number,
          keyId: m.key_id || null,
          reason: err?.message || "decryption failed",
        });
        decoded.push({
          clientMessageId: m.client_message_id || null,
          sender: m.sender,
          text: null,
          timestamp: m.timestamp,
          unverified: true,
          deliveryStatus: m.sender === identity.username ? (m.delivery_status || "sent") : undefined,
          sequenceNumber: m.sequence_number,
        });
      }
    }
    setMessages((prev) => {
      // Merge rather than overwrite: live messages can arrive while the REST
      // history request is in flight.
      const combined = [...decoded, ...(prev[peer] || [])];
      const seen = new Set();
      const unique = combined.filter((message) => {
        const key = message.clientMessageId || `${message.sender}|${message.sequenceNumber}|${message.timestamp}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
      unique.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      return { ...prev, [peer]: unique };
    });
    if (markRead) await apiMarkConversationRead(token, peer).catch((err) => {
      console.warn("Could not mark selected history as read:", err);
    });
    await refreshConversations();
  }

  async function receiveChatMessage(envelope) {
    const peer = envelope.from;
    const identity = meRef.current;
    const sessionId = [identity.username, peer].sort().join("|");
    const messageKeyId = envelope.key_id || null;
    let sessionKey = null;
    if (messageKeyId) {
      sessionKey = sessionKeyIdsRef.current[peer] === messageKeyId
        ? sessionKeysRef.current[peer]
        : await loadSessionKeyFor(sessionId, identity.wrappingKey, messageKeyId, identity.username).catch(() => null);
    } else {
      sessionKey = sessionKeysRef.current[peer]
        || await loadSessionKeyFor(sessionId, identity.wrappingKey, null, identity.username).catch(() => null);
    }
    if (!sessionKey) {
      const queue = pendingIncomingMessagesRef.current[peer] || [];
      if (!queue.some((item) => item.client_message_id && item.client_message_id === envelope.client_message_id)) {
        pendingIncomingMessagesRef.current[peer] = [...queue, envelope];
      }
      return; // retain until handshake completes; do not discard a stored ciphertext race
    }

    try {
      const { plaintext, replayWarning } = await decryptMessage({
        sessionKey,
        sessionId,
        sender: peer,
        recipient: identity.username,
        sequenceNumber: envelope.sequence_number,
        nonceHex: envelope.nonce,
        ciphertextHex: envelope.ciphertext,
        keyId: messageKeyId,
        ownerUsername: identity.username,
      });
      setMessages((prev) => {
        const current = prev[peer] || [];
        if (envelope.client_message_id && current.some((item) => item.clientMessageId === envelope.client_message_id)) {
          return prev;
        }
        return {
          ...prev,
          [peer]: [...current, {
            clientMessageId: envelope.client_message_id || null,
            sender: peer,
            text: plaintext,
            timestamp: envelope.timestamp || new Date().toISOString(),
            replayWarning,
            sequenceNumber: envelope.sequence_number,
            keyId: messageKeyId,
          }],
        };
      });
      // If this conversation is open, mark it read only after authentication
      // and decryption succeeds. Otherwise leave it unread in the inbox.
      if (activePeerRef.current === peer) {
        await apiMarkConversationRead(token, peer).catch((err) => {
          console.warn("Could not mark incoming message as read:", err);
        });
      }
      // This is a delivery receipt, not a read receipt: it means the recipient
      // successfully authenticated and decrypted the message in the browser.
      if (envelope.client_message_id) {
        sendDeliveryAck({
          type: "delivery_ack",
          to: peer,
          session_id: sessionId,
          client_message_id: envelope.client_message_id,
          sequence_number: envelope.sequence_number,
        });
      }
    } catch {
      setMessages((prev) => ({
        ...prev,
        [peer]: [...(prev[peer] || []), {
          clientMessageId: envelope.client_message_id || null,
          sender: peer,
          text: null,
          timestamp: envelope.timestamp || new Date().toISOString(),
          unverified: true,
          sequenceNumber: envelope.sequence_number,
        }],
      }));
    }
  }

  async function flushPendingChatMessages(peer) {
    const queued = pendingIncomingMessagesRef.current[peer] || [];
    delete pendingIncomingMessagesRef.current[peer];
    for (const envelope of queued) {
      await receiveChatMessage(envelope);
    }
    await refreshConversations();
  }

  async function sendMessage(text) {
    const identity = meRef.current;
    const peer = activePeer;
    const sessionKey = sessionKeysRef.current[peer];
    const keyId = sessionKeyIdsRef.current[peer] || null;
    if (!sessionKey || !peer) return;
    const sessionId = [identity.username, peer].sort().join("|");
    const seq = await nextOutgoingSequence(sessionId, identity.username);
    const encrypted = await encryptMessage({
      sessionKey,
      sessionId,
      sender: identity.username,
      recipient: peer,
      sequenceNumber: seq,
      plaintext: text,
      keyId,
    });
    const clientMessageId = makeClientMessageId();
    const envelope = {
      type: "chat_message",
      to: peer,
      session_id: sessionId,
      client_message_id: clientMessageId,
      nonce: encrypted.nonce,
      ciphertext: encrypted.ciphertext,
      sequence_number: encrypted.sequence_number,
      ...(encrypted.key_id ? { key_id: encrypted.key_id } : {}),
    };
    const localMessage = {
      clientMessageId,
      sender: identity.username,
      text,
      timestamp: new Date().toISOString(),
      sequenceNumber: seq,
      keyId,
      deliveryStatus: "sending",
    };
    setMessages((prev) => ({ ...prev, [peer]: [...(prev[peer] || []), localMessage] }));
    const sent = wsRef.current?.send(envelope) === true;
    if (!sent) {
      handleMessageStatus({ client_message_id: clientMessageId, status: "failed" });
    }
  }

  // ---------------- render ----------------

  if (screen === "auth") {
    return <AuthScreen onLoggedIn={handleLoggedIn} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="me-bar">
          <span className="me-name">{me.username}</span>
          <button className="icon-btn" onClick={handleLogout} title="Log out">
            ⎋
          </button>
        </div>
        <ContactList
          conversations={conversations}
          users={users}
          activePeer={activePeer}
          onSelect={selectPeer}
          handshakeState={handshakeState}
          inboxError={inboxError}
          onRetryInbox={refreshConversations}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          searchLoading={searchLoading}
        />
        <button className="ghost-btn" onClick={() => setShowBenchmark(true)}>
          Run PQC benchmark
        </button>
      </aside>
      <main className="chat-pane">
        {activePeer ? (
          <>
            <div className="chat-header">
              <span>{activePeer}</span>
              <HandshakeStatus state={handshakeState[activePeer] || "idle"} relayConnected={relayConnected} />
              {handshakeState[activePeer] !== "established" && (
                <button
                  type="button"
                  className="handshake-action"
                  disabled={handshakeState[activePeer] === "establishing" || !relayConnected}
                  onClick={() => startHandshake(activePeer)}
                  title={!relayConnected ? "Waiting for the relay connection" : handshakeState[activePeer] === "pending" ? "Resend the same pending handshake" : "Start or retry secure session"}
                >
                  {handshakeState[activePeer] === "establishing"
                    ? "Preparing…"
                    : handshakeState[activePeer] === "pending"
                      ? "Resend handshake"
                      : handshakeState[activePeer] === "failed"
                        ? "Retry secure session"
                        : "Start secure session"}
                </button>
              )}
            </div>
            <ChatWindow messages={messages[activePeer] || []} me={me.username} offlinePending={handshakeState[activePeer] === "pending"} />
            <MessageComposer
              disabled={!relayConnected || !sessionKeys[activePeer] || !["pending", "established"].includes(handshakeState[activePeer])}
              placeholder={handshakeState[activePeer] === "pending" ? "Message will be queued until recipient reconnects…" : undefined}
              onSend={sendMessage}
            />
          </>
        ) : (
          <div className="empty-state">Select a user to start a secure chat</div>
        )}
        {error && <div className="error-toast" onClick={() => setError(null)}>{error}</div>}
      </main>
      {showBenchmark && <BenchmarkPanel onClose={() => setShowBenchmark(false)} />}
    </div>
  );
}

function makeClientMessageId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const parts = new Uint32Array(4);
  crypto.getRandomValues(parts);
  return Array.from(parts, (part) => part.toString(16).padStart(8, "0")).join("");
}

function AuthScreen({ onLoggedIn }) {
  const [mode, setMode] = useState("login");
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <h1>PQChat</h1>
        <p className="subtitle">ML-KEM-768 + ML-DSA-65 · client-side, blind-relay architecture</p>
        <div className="tabs">
          <button className={`tab ${mode === "login" ? "active" : ""}`} onClick={() => setMode("login")}>
            Log in
          </button>
          <button className={`tab ${mode === "register" ? "active" : ""}`} onClick={() => setMode("register")}>
            Register
          </button>
        </div>
        {mode === "login" ? (
          <Login onLoggedIn={onLoggedIn} />
        ) : (
          <Register onRegistered={() => setMode("login")} />
        )}
      </div>
    </div>
  );
}
