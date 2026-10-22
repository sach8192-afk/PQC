import { useState } from "react";

export default function MessageComposer({ onSend, disabled, placeholder }) {
  const [text, setText] = useState("");

  function handleSubmit(e) {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setText("");
  }

  return (
    <form className="composer" onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder={disabled ? "Waiting for local session key…" : (placeholder || "Type a message…")}
        value={text}
        onChange={(e) => setText(e.target.value)}
        disabled={disabled}
        autoComplete="off"
      />
      <button type="submit" disabled={disabled}>
        Send
      </button>
    </form>
  );
}
