/**
 * benchmark.js
 *
 * REQ-BENCH-1: timing for keygen/encapsulation/decapsulation/signing/verification.
 * REQ-BENCH-2: byte sizes of public keys, ciphertexts, signatures.
 * REQ-BENCH-3: export in a structured format (CSV/JSON).
 *
 * Runs in the actual browser JS engine — this is the number that matters
 * for real usability (§5.1's <500ms handshake budget), not a server-side
 * proxy for it.
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

function timeOp(fn, iterations) {
  const times = [];
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    fn();
    times.push(performance.now() - t0);
  }
  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  return {
    mean_ms: Number(mean.toFixed(4)),
    min_ms: Number(Math.min(...times).toFixed(4)),
    max_ms: Number(Math.max(...times).toFixed(4)),
    iterations,
  };
}

export function runBenchmark(iterations = 50) {
  const bobKeys = ml_kem768.keygen();
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(bobKeys.publicKey);
  const signer = ml_dsa65.keygen();
  const msg = new TextEncoder().encode("benchmark message payload for signing");
  const signature = ml_dsa65.sign(msg, signer.secretKey);

  const timings = {
    kem_keygen: timeOp(() => ml_kem768.keygen(), iterations),
    kem_encaps: timeOp(() => ml_kem768.encapsulate(bobKeys.publicKey), iterations),
    kem_decaps: timeOp(() => ml_kem768.decapsulate(cipherText, bobKeys.secretKey), iterations),
    dsa_keygen: timeOp(() => ml_dsa65.keygen(), iterations),
    dsa_sign: timeOp(() => ml_dsa65.sign(msg, signer.secretKey), iterations),
    dsa_verify: timeOp(() => ml_dsa65.verify(signature, msg, signer.publicKey), iterations),
  };

  const sizes = {
    kem_public_key: bobKeys.publicKey.length,
    kem_secret_key: bobKeys.secretKey.length,
    kem_ciphertext: cipherText.length,
    kem_shared_secret: sharedSecret.length,
    sig_public_key: signer.publicKey.length,
    sig_secret_key: signer.secretKey.length,
    signature: signature.length,
  };

  return {
    iterations,
    algorithms: { kem: "ML-KEM-768", signature: "ML-DSA-65" },
    engine: navigator.userAgent,
    timestamp: new Date().toISOString(),
    timings_ms: timings,
    sizes_bytes: sizes,
  };
}

export function benchmarkToJson(result) {
  return JSON.stringify(result, null, 2);
}

export function benchmarkToCsv(result) {
  const rows = [["operation", "mean_ms", "min_ms", "max_ms", "iterations"]];
  for (const [op, t] of Object.entries(result.timings_ms)) {
    rows.push([op, t.mean_ms, t.min_ms, t.max_ms, t.iterations]);
  }
  rows.push([]);
  rows.push(["artifact", "size_bytes"]);
  for (const [name, size] of Object.entries(result.sizes_bytes)) {
    rows.push([name, size]);
  }
  return rows.map((r) => r.join(",")).join("\n");
}

export function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
