import { useState } from "react";
import { runBenchmark, benchmarkToJson, benchmarkToCsv, downloadBlob } from "../crypto/benchmark.js";

export default function BenchmarkPanel({ onClose }) {
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const [iterations, setIterations] = useState(50);

  async function run() {
    setRunning(true);
    // Let the UI paint the "running" state before the (synchronous, CPU-bound) benchmark blocks the thread.
    await new Promise((r) => setTimeout(r, 30));
    const r = runBenchmark(iterations);
    setResult(r);
    setRunning(false);
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>×</button>
        <h2>PQC Benchmark</h2>
        <p className="hint">Runs in this browser's own JS engine — the number that matters for real usability.</p>

        <div className="benchmark-controls">
          <label>
            Iterations:{" "}
            <input
              type="number"
              min={1}
              max={500}
              value={iterations}
              onChange={(e) => setIterations(Number(e.target.value))}
            />
          </label>
          <button onClick={run} disabled={running}>
            {running ? "Running…" : "Run benchmark"}
          </button>
        </div>

        {result && (
          <>
            <table>
              <thead>
                <tr><th>Operation</th><th>Mean (ms)</th><th>Min</th><th>Max</th></tr>
              </thead>
              <tbody>
                {Object.entries(result.timings_ms).map(([op, t]) => (
                  <tr key={op}>
                    <td>{op}</td><td>{t.mean_ms}</td><td>{t.min_ms}</td><td>{t.max_ms}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <p className="hint" style={{ marginTop: 14 }}>Artifact sizes (bytes)</p>
            <table>
              <tbody>
                {Object.entries(result.sizes_bytes).map(([name, size]) => (
                  <tr key={name}><td>{name}</td><td>{size}</td></tr>
                ))}
              </tbody>
            </table>

            <div className="benchmark-export">
              <button onClick={() => downloadBlob(benchmarkToJson(result), "pqchat-benchmark.json", "application/json")}>
                Download JSON
              </button>
              <button onClick={() => downloadBlob(benchmarkToCsv(result), "pqchat-benchmark.csv", "text/csv")}>
                Download CSV
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
