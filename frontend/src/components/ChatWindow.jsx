import { useEffect, useMemo, useRef } from "react";

function dateKey(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown-date";
  return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
}

function dateLabel(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Earlier";
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  if (dateKey(date) === dateKey(today)) return "Today";
  if (dateKey(date) === dateKey(yesterday)) return "Yesterday";
  return date.toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" });
}

function timeLabel(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "time unavailable"
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function DeliveryIndicator({ status }) {
  const state = status || "sent";
  const labels = {
    sending: ["◷", "Sending"],
    sent: ["✓", "Saved by server; recipient has not acknowledged decryption"],
    delivered: ["✓✓", "Recipient client acknowledged successful message authentication/decryption; not a read receipt"],
    failed: ["!", "Message was not accepted by the relay"],
  };
  const [symbol, label] = labels[state] || labels.sent;
  return (
    <span className={`delivery-status delivery-${state}`} title={label} aria-label={label}>
      <span aria-hidden="true">{symbol}</span>
    </span>
  );
}

export default function ChatWindow({ messages, me, offlinePending = false }) {
  const endRef = useRef(null);
  const renderedMessages = useMemo(() => {
    let previousDay = null;
    return messages.map((message, index) => {
      const key = message.clientMessageId || `${message.sender}-${message.sequenceNumber ?? index}-${message.timestamp ?? index}`;
      const currentDay = dateKey(message.timestamp);
      const showDate = currentDay !== previousDay;
      previousDay = currentDay;
      const mine = message.sender === me;
      const previous = messages[index - 1];
      const currentTime = new Date(message.timestamp).getTime();
      const previousTime = previous ? new Date(previous.timestamp).getTime() : Number.NaN;
      const grouped = Boolean(
        previous && previous.sender === message.sender &&
        dateKey(previous.timestamp) === currentDay &&
        Number.isFinite(currentTime) && Number.isFinite(previousTime) &&
        currentTime - previousTime >= 0 && currentTime - previousTime < 5 * 60 * 1000
      );
      return { ...message, key, mine, showDate, grouped, dateText: dateLabel(message.timestamp), timeText: timeLabel(message.timestamp) };
    });
  }, [messages, me]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  return (
    <div className="chat-messages" aria-live="polite" aria-relevant="additions text">
      {renderedMessages.length === 0 ? (
        <div className="chat-empty-state">
          <div className="chat-empty-icon" aria-hidden="true">✳</div>
          <strong>{offlinePending ? "Recipient is not confirmed yet" : "Start the conversation"}</strong>
          <span>{offlinePending
            ? "You can send messages now. Encrypted messages will be stored by the relay and decrypted when the recipient reconnects."
            : "Messages are encrypted in your browser before they are sent."}</span>
        </div>
      ) : (
        renderedMessages.map((message) => (
          <div className="message-block" key={message.key}>
            {message.showDate && <div className="message-date-divider"><span>{message.dateText}</span></div>}
            <div className={`msg-row ${message.mine ? "row-mine" : "row-theirs"}`}>
              <article className={`msg ${message.mine ? "mine" : "theirs"} ${message.grouped ? "msg-grouped" : ""} ${message.unverified ? "msg-is-unverified" : ""}`}>
                {!message.grouped && <div className="msg-sender">{message.mine ? "You" : message.sender}</div>}
                <div className="msg-body">
                  {message.unverified ? (
                    <span className="msg-unverified">⚠ Could not decrypt with this session key</span>
                  ) : (
                    <>
                      {message.text}
                      {message.replayWarning && <span className="msg-replay-badge" title="Repeated or out-of-order sequence number">⚠ possible replay</span>}
                    </>
                  )}
                </div>
                <div className="msg-meta">
                  <time dateTime={message.timestamp || undefined}>{message.timeText}</time>
                  {message.mine && <DeliveryIndicator status={message.deliveryStatus} />}
                </div>
              </article>
            </div>
          </div>
        ))
      )}
      <div ref={endRef} />
    </div>
  );
}
