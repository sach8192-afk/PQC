import { useState } from "react";

const STATUS = {
  idle: { icon: "◌", label: "No session key", className: "idle" },
  establishing: { icon: "⌁", label: "Preparing PQC session", className: "establishing" },
  pending: { icon: "◷", label: "Waiting for recipient", className: "pending" },
  established: { icon: "▣", label: "Peer confirmed session", className: "established" },
  failed: { icon: "!", label: "Session setup failed", className: "failed" },
};

export default function HandshakeStatus({ state, relayConnected = false }) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const status = STATUS[state] || STATUS.idle;

  return (
    <div className="security-status-wrap">
      <button
        type="button"
        className={`security-chip security-${status.className}`}
        onClick={() => setDetailsOpen((open) => !open)}
        aria-expanded={detailsOpen}
        aria-label="Show encryption and connection details"
        title="View encryption details"
      >
        <span className="security-chip-icon" aria-hidden="true">{status.icon}</span>
        <span className="security-chip-label">{status.label}</span>
        <span className={`relay-dot ${relayConnected ? "relay-online" : "relay-offline"}`} aria-hidden="true" />
        <span className="security-chip-chevron" aria-hidden="true">{detailsOpen ? "▴" : "▾"}</span>
      </button>
      {detailsOpen && (
        <div className="security-details" role="status">
          <div className="security-details-heading">Connection & encryption</div>
          <div className="security-detail-row">
            <span className={`relay-dot ${relayConnected ? "relay-online" : "relay-offline"}`} />
            <span>Relay connection: <strong>{relayConnected ? "Connected" : "Reconnecting / offline"}</strong></span>
          </div>
          <div className="security-detail-row">
            <span className="security-detail-mark">K</span>
            <span>Local session key: <strong>{state === "pending" || state === "established" ? "Available" : "Not available"}</strong></span>
          </div>
          <div className="security-detail-row">
            <span className="security-detail-mark">P</span>
            <span>Key establishment primitive: <strong>ML-KEM-768</strong></span>
          </div>
          <div className="security-detail-row">
            <span className="security-detail-mark">S</span>
            <span>Handshake signatures: <strong>ML-DSA-65</strong></span>
          </div>
          <div className="security-detail-row">
            <span className="security-detail-mark">E</span>
            <span>Message protection: <strong>AES-256-GCM</strong></span>
          </div>
          {state === "pending" && (
            <p className="security-pending-note">The key is available in this browser. You can send messages now; the relay will queue encrypted messages until the recipient reconnects. Peer confirmation is still pending.</p>
          )}
          <p className="security-prototype-note">
            This panel reports local app state and relay connectivity; it is not a cryptographic attestation. PQChat is
            a research prototype, not an independently audited messenger. Peer-key trust and authenticated handshake
            confirmation still need hardening, and there is no Double Ratchet. Do not treat this label as a
            production-grade security guarantee.
          </p>
        </div>
      )}
    </div>
  );
}
