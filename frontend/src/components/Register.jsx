import { useState } from "react";
import { createIdentity } from "../crypto/identity.js";
import { saveIdentity } from "../crypto/store.js";
import { apiRegister } from "../api/rest.js";

export default function Register({ onRegistered }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("idle"); // idle | generating | error
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    if (password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    setStatus("generating");
    try {
      // REQ-KEY-1/2: both keypairs generated locally, right here.
      const { forServer, localRecord } = await createIdentity(username, password, { persist: false });
      // REQ-KEY-3: only public keys + login verifier leave the browser.
      await apiRegister(forServer);
      // Persist only after the server accepted registration, so a duplicate
      // username/network failure cannot overwrite this browser's existing private identity.
      await saveIdentity(localRecord);
      setStatus("idle");
      onRegistered();
    } catch (err) {
      // REQ-KEY-4: keygen/registration failure surfaces a retry option —
      // the form simply remains editable and submittable again.
      setStatus("error");
      setError(err.message || "Registration failed. Please try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        minLength={3}
        required
      />
      <input
        type="password"
        placeholder="Password (min 6 chars)"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
      />
      <button type="submit" disabled={status === "generating"}>
        {status === "generating" ? "Generating ML-KEM-768 + ML-DSA-65 keys…" : "Register"}
      </button>
      <p className="hint">
        Keys are generated in your browser and never leave it. This identity lives only in this
        browser profile.
      </p>
      {error && <p className="error">{error}</p>}
    </form>
  );
}
