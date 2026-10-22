import { useState } from "react";
import { unlockIdentity, hasLocalIdentity } from "../crypto/identity.js";
import { apiLogin } from "../api/rest.js";

export default function Login({ onLoggedIn }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const exists = await hasLocalIdentity(username);
      if (!exists) {
        setError(
          "No identity found for this username in this browser. Register here first — identities don't sync across devices/browsers."
        );
        setBusy(false);
        return;
      }

      let identity;
      try {
        identity = await unlockIdentity(username, password);
      } catch {
        setError("Invalid username or password.");
        setBusy(false);
        return;
      }

      const { token } = await apiLogin({ username, password_verifier: identity.loginVerifier });
      onLoggedIn(identity, token);
    } catch (err) {
      setError(err.message || "Login failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        required
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
      />
      <button type="submit" disabled={busy}>
        {busy ? "Unlocking…" : "Log in"}
      </button>
      {error && <p className="error">{error}</p>}
    </form>
  );
}
