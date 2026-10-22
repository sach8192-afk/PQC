/**
 * WebSocket relay client.
 * Outbound envelopes are queued while the browser socket is connecting or
 * reconnecting so an immediate handshake is not silently dropped.
 */
export function connectWebSocket(
  token,
  { onHandshakeInit, onHandshakeAccepted, onHandshakeAck, onHandshakeError, onChatMessage, onMessageStatus, onOpen, onClose, onAuthError }
) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const socketUrl = `${proto}://${location.host}/ws`;
  let socket = new WebSocket(socketUrl);
  let authorizedSocket = null;
  let closedByCaller = false;
  let reconnectTimer = null;
  const outboundQueue = [];

  function flushQueue(ws) {
    while (outboundQueue.length && ws.readyState === WebSocket.OPEN) {
      const payload = outboundQueue[0];
      try {
        ws.send(payload);
        outboundQueue.shift();
      } catch {
        break;
      }
    }
  }

  function attach(ws) {
    ws.onopen = () => {
      // Keep bearer tokens out of the URL/access logs. The first frame is
      // sent over the already-upgraded WSS connection and must be accepted
      // before any queued application envelope is flushed.
      try {
        ws.send(JSON.stringify({ type: "auth", token }));
      } catch {
        ws.close();
      }
    };
    ws.onmessage = (event) => {
      let envelope;
      try {
        envelope = JSON.parse(event.data);
      } catch {
        return;
      }
      if (envelope.type === "auth_ok") {
        authorizedSocket = ws;
        flushQueue(ws);
        if (onOpen) onOpen();
        return;
      }
      if (envelope.type === "auth_error") {
        closedByCaller = true;
        authorizedSocket = null;
        outboundQueue.length = 0;
        if (reconnectTimer !== null) clearTimeout(reconnectTimer);
        if (onAuthError) onAuthError(envelope);
        ws.close();
        return;
      }
      switch (envelope.type) {
        case "handshake_init":
          if (onHandshakeInit) onHandshakeInit(envelope);
          break;
        case "handshake_accepted":
          if (onHandshakeAccepted) onHandshakeAccepted(envelope);
          break;
        case "handshake_ack":
          if (onHandshakeAck) onHandshakeAck(envelope);
          break;
        case "handshake_error":
          if (onHandshakeError) onHandshakeError(envelope);
          break;
        case "chat_message":
          if (onChatMessage) onChatMessage(envelope);
          break;
        case "message_status":
          if (onMessageStatus) onMessageStatus(envelope);
          break;
        default:
          break;
      }
    };
    ws.onclose = () => {
      if (authorizedSocket === ws) authorizedSocket = null;
      if (onClose) onClose();
      if (!closedByCaller) {
        reconnectTimer = setTimeout(() => {
          socket = new WebSocket(socketUrl);
          attach(socket);
        }, 2000);
      }
    };
  }
  attach(socket);

  return {
    send(envelope) {
      if (closedByCaller) return false;
      let payload;
      try {
        payload = JSON.stringify(envelope);
      } catch {
        return false;
      }
      if (socket.readyState === WebSocket.OPEN && authorizedSocket === socket) {
        try {
          socket.send(payload);
          return true;
        } catch {
          return false;
        }
      }
      // Queue while connecting, authenticating, or temporarily reconnecting.
      // Nothing is sent until the relay confirms this socket's bearer token.
      if (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.CLOSED ||
          (socket.readyState === WebSocket.OPEN && authorizedSocket !== socket)) {
        outboundQueue.push(payload);
        return true;
      }
      return false;
    },
    close() {
      closedByCaller = true;
      if (reconnectTimer !== null) clearTimeout(reconnectTimer);
      outboundQueue.length = 0;
      socket.close();
    },
  };
}
