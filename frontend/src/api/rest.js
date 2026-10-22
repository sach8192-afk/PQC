/**
 * rest.js
 *
 * fetch() wrappers for the REST endpoints. Everything sent here is
 * public/opaque data — see the crypto/ modules for where the actual
 * secret-touching work happens before anything gets to this layer.
 */

function authHeaders(token) {
  return { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) };
}

async function handle(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `Request failed (${res.status})`);
  }
  return data;
}

export async function apiRegister(payload) {
  const res = await fetch("/api/register", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(payload),
  });
  return handle(res);
}

export async function apiLogin(payload) {
  const res = await fetch("/api/login", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(payload),
  });
  return handle(res);
}

export async function apiLogout(token) {
  const res = await fetch("/api/logout", { method: "POST", headers: authHeaders(token) });
  return handle(res);
}

export async function apiSearchUsers(token, query) {
  const res = await fetch(`/api/users/search?q=${encodeURIComponent(query)}`, {
    headers: authHeaders(token),
  });
  return handle(res);
}

export async function apiGetPublicKeys(token, username) {
  const res = await fetch(`/api/users/${encodeURIComponent(username)}/public-keys`, { headers: authHeaders(token) });
  return handle(res);
}

export async function apiGetPendingHandshakes(token) {
  const res = await fetch("/api/handshakes/pending", { headers: authHeaders(token) });
  return handle(res);
}

export async function apiConsumeHandshake(token, sessionId) {
  const res = await fetch(`/api/handshakes/${encodeURIComponent(sessionId)}/consume`, {
    method: "POST",
    headers: authHeaders(token),
  });
  return handle(res);
}

export async function apiGetHistory(token, peer) {
  const res = await fetch(`/api/messages/${encodeURIComponent(peer)}`, { headers: authHeaders(token) });
  return handle(res);
}

export async function apiGetConversations(token) {
  const res = await fetch("/api/conversations", { headers: authHeaders(token) });
  return handle(res);
}

export async function apiMarkConversationRead(token, peer) {
  const res = await fetch(`/api/conversations/${encodeURIComponent(peer)}/read`, {
    method: "POST",
    headers: authHeaders(token),
  });
  return handle(res);
}
