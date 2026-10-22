function listTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const now = new Date();
  const sameDay = date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() && date.getDate() === now.getDate();
  return sameDay
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString([], { day: "numeric", month: "short" });
}

function previewText(value) {
  const compact = String(value || "").replace(/\s+/g, " ").trim();
  return compact.length > 42 ? `${compact.slice(0, 39)}…` : compact;
}

export default function ContactList({
  conversations = [],
  users,
  activePeer,
  onSelect,
  handshakeState,
  inboxError,
  onRetryInbox,
  searchQuery,
  onSearchChange,
  searchLoading,
}) {
  const queryLength = searchQuery.trim().length;

  return (
    <div className="contacts">
      <section className="contact-section" aria-label="Your chats">
        <div className="contacts-header inbox-heading">
          <span>Chats</span>
          {conversations.length > 0 && <span className="section-count">{conversations.length}</span>}
        </div>
        {inboxError ? (
          <div className="inbox-load-error" role="alert">
            <span>Could not load Chats. Check that the updated backend is running.</span>
            <small>{inboxError}</small>
            <button type="button" onClick={onRetryInbox}>Retry</button>
          </div>
        ) : conversations.length === 0 ? (
          <div className="contacts-empty">Your conversations will appear here.</div>
        ) : (
          <ul className="contacts-list inbox-list">
            {conversations.map((conversation) => {
              const peer = conversation.peer;
              return (
                <li key={peer} className="inbox-row">
                  <button
                    type="button"
                    className={`inbox-item ${peer === activePeer ? "active" : ""}`}
                    onClick={() => onSelect(peer)}
                    aria-current={peer === activePeer ? "page" : undefined}
                  >
                    <span className="inbox-avatar" aria-hidden="true">
                      {(peer || "?").slice(0, 1).toUpperCase()}
                    </span>
                    <span className="inbox-main">
                      <span className="inbox-topline">
                        <span className="inbox-peer">{peer}</span>
                        <time className="inbox-time" dateTime={conversation.updated_at || undefined}>
                          {listTime(conversation.updated_at)}
                        </time>
                      </span>
                      <span className="inbox-bottomline">
                        <span className="inbox-preview">{previewText(conversation.preview || "Encrypted message")}</span>
                        {conversation.unread_count > 0 && (
                          <span className="unread-badge" aria-label={`${conversation.unread_count} unread messages`}>
                            {conversation.unread_count > 99 ? "99+" : conversation.unread_count}
                          </span>
                        )}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="contact-section" aria-label="Find people">
        <div className="contacts-header">Find people</div>
        <div className="user-search">
          <input
            type="search"
            value={searchQuery}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="Search username…"
            aria-label="Search usernames"
            autoComplete="off"
            spellCheck="false"
          />
          <p className="search-hint" aria-live="polite">
            {queryLength < 3
              ? "Enter at least 3 characters to search."
              : searchLoading
                ? "Searching…"
                : users.length > 0
                  ? `${users.length} matching user${users.length === 1 ? "" : "s"}`
                  : "No matching users found."}
          </p>
        </div>
        <ul className="contacts-list search-results-list">
          {users.map((username) => (
            <li
              key={username}
              className={`contact-result ${username === activePeer ? "active" : ""}`}
              onClick={() => onSelect(username)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") onSelect(username);
              }}
              role="button"
              tabIndex={0}
              aria-current={username === activePeer ? "page" : undefined}
            >
              <span>{username}</span>
              <StatusDot state={handshakeState[username]} />
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function StatusDot({ state }) {
  if (!state || state === "idle") return null;
  const label = { establishing: "…", pending: "…", established: "●", failed: "✕" }[state] || "";
  const cls = { establishing: "dot-pending", pending: "dot-pending", established: "dot-ok", failed: "dot-fail" }[state] || "";
  return <span className={`status-dot ${cls}`} aria-label={state}>{label}</span>;
}
