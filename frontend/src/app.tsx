import React, { useMemo, useState } from "react";

type ResultRow = Record<string, any> & {
  severity?: string;          // "Benign" / "Reconnaissance" / ...
  is_anomaly?: boolean;       // true/false
  confidence?: number;        // 0..1 (optional)
  pred_class?: number;        // 0..4 (optional)
};

const API_URL = "http://localhost:8001/predict-csv";

function badgeForSeverity(sev?: string) {
  const s = (sev || "").toLowerCase();
  if (!sev || s === "benign" || s === "none") {
    return "bg-green-100 text-green-800 border-green-200";
  }
  if (s.includes("recon")) return "bg-yellow-100 text-yellow-800 border-yellow-200";
  if (s.includes("fuzz") || s.includes("generic")) return "bg-orange-100 text-orange-800 border-orange-200";
  if (s.includes("dos") || s.includes("default")) return "bg-red-100 text-red-800 border-red-200";
  // exploits/other
  return "bg-purple-100 text-purple-800 border-purple-200";
}

function toBool(v: any): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") return ["true", "1", "yes"].includes(v.toLowerCase());
  return false;
}

export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [rows, setRows] = useState<ResultRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);

  // Pick some columns to show (keeps table readable even with huge CSVs)
  const displayCols = useMemo(() => {
    if (!rows.length) return [];
    const keys = Object.keys(rows[0]);

    // Prefer these if they exist (common network-ish columns)
    const preferred = [
      "TIME_FIRST", "TIME_LAST", "timestamp", "time",
      "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT",
      "PROTOCOL", "PROTO", "src_ip", "dst_ip", "src_port", "dst_port",
    ];

    const picked: string[] = [];
    for (const p of preferred) if (keys.includes(p)) picked.push(p);

    // Always include model outputs if present
    for (const must of ["is_anomaly", "severity", "confidence", "pred_class"]) {
      if (keys.includes(must) && !picked.includes(must)) picked.push(must);
    }

    // If we still have too few, add some extra numeric-like columns
    for (const k of keys) {
      if (picked.length >= 8) break;
      if (!picked.includes(k) && !["Attack", "Label"].includes(k)) picked.push(k);
    }

    return picked;
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();

    return rows.filter((r) => {
      const anomaly = toBool(r.is_anomaly);
      if (onlyAnomalies && !anomaly) return false;

      if (!q) return true;

      // Simple search across displayed columns + severity
      const hay = displayCols
        .map((c) => String(r[c] ?? ""))
        .concat(String(r.severity ?? ""))
        .join(" ")
        .toLowerCase();

      return hay.includes(q);
    });
  }, [rows, query, onlyAnomalies, displayCols]);

  async function runPredict() {
    if (!file) return;
    setLoading(true);
    setError(null);

    try {
      const fd = new FormData();
      fd.append("file", file);

      const res = await fetch(API_URL, { method: "POST", body: fd });

      if (!res.ok) {
        let msg = `Request failed (${res.status})`;
        try {
          const j = await res.json();
          msg = j?.detail ?? msg;
        } catch {}
        throw new Error(msg);
      }

      const data = (await res.json()) as ResultRow[];
      setRows(data);
    } catch (e: any) {
      setError(e?.message ?? "Unknown error");
      setRows([]);
    } finally {
      setLoading(false);
    }
  }

  const anomalyCount = useMemo(
    () => rows.reduce((acc, r) => acc + (toBool(r.is_anomaly) ? 1 : 0), 0),
    [rows]
  );

  return (
    <div className="min-h-screen">
      <div className="mx-auto max-w-6xl px-4 py-8">
        <header className="mb-6">
          <h1 className="text-2xl font-semibold tracking-tight">Anoseek Demo — Flow History</h1>
          <p className="mt-1 text-sm text-slate-600">
            Upload a CSV, send it to the local FastAPI model, and view predicted anomalies + severity.
          </p>
        </header>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
            <div className="flex-1">
              <label className="block text-sm font-medium text-slate-700">CSV file</label>
              <div className="mt-1 flex items-center gap-3">
                <input
                  type="file"
                  accept=".csv"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                  className="block w-full text-sm file:mr-4 file:rounded-xl file:border-0 file:bg-slate-900 file:px-4 file:py-2 file:text-white hover:file:bg-slate-800"
                />
                <button
                  onClick={runPredict}
                  disabled={!file || loading}
                  className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50 hover:bg-blue-500"
                >
                  {loading ? "Analyzing..." : "Analyze"}
                </button>
              </div>
              <p className="mt-2 text-xs text-slate-500">
                Backend runs at <span className="font-mono">http://localhost:8001</span>.
              </p>
            </div>

            <div className="flex flex-col gap-2 md:w-80">
              <label className="text-sm font-medium text-slate-700">Search</label>
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="IP, port, protocol, severity..."
                className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200"
              />
              <label className="inline-flex items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={onlyAnomalies}
                  onChange={(e) => setOnlyAnomalies(e.target.checked)}
                  className="h-4 w-4 rounded border-slate-300"
                />
                Show anomalies only
              </label>
            </div>
          </div>

          {error && (
            <div className="mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
              {error}
            </div>
          )}

          <div className="mt-4 flex flex-wrap gap-2 text-sm text-slate-700">
            <span className="rounded-full bg-slate-100 px-3 py-1">
              Rows: <b>{rows.length}</b>
            </span>
            <span className="rounded-full bg-slate-100 px-3 py-1">
              Anomalies: <b>{anomalyCount}</b>
            </span>
            <span className="rounded-full bg-slate-100 px-3 py-1">
              Showing: <b>{filtered.length}</b>
            </span>
          </div>

          <div className="mt-4 overflow-x-auto rounded-xl border border-slate-200">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-50 text-slate-700">
                <tr>
                  {displayCols.map((c) => (
                    <th key={c} className="whitespace-nowrap px-3 py-2 font-semibold">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {filtered.slice(0, 500).map((r, idx) => {
                  const isA = toBool(r.is_anomaly);
                  const sev = r.severity ?? (isA ? "Attack" : "Benign");
                  const conf =
                    typeof r.confidence === "number" ? r.confidence : undefined;

                  return (
                    <tr key={idx} className={isA ? "bg-red-50/40" : ""}>
                      {displayCols.map((c) => {
                        if (c === "severity") {
                          return (
                            <td key={c} className="px-3 py-2">
                              <span
                                className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-semibold ${badgeForSeverity(sev)}`}
                              >
                                {sev}
                              </span>
                            </td>
                          );
                        }

                        if (c === "is_anomaly") {
                          return (
                            <td key={c} className="px-3 py-2">
                              <span
                                className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-semibold ${
                                  isA
                                    ? "bg-red-100 text-red-800 border-red-200"
                                    : "bg-green-100 text-green-800 border-green-200"
                                }`}
                              >
                                {isA ? "Anomaly" : "Normal"}
                              </span>
                            </td>
                          );
                        }

                        if (c === "confidence") {
                          return (
                            <td key={c} className="px-3 py-2 font-mono">
                              {conf === undefined ? "-" : conf.toFixed(3)}
                            </td>
                          );
                        }

                        const v = r[c];
                        return (
                          <td key={c} className="px-3 py-2 whitespace-nowrap">
                            {v === null || v === undefined ? "-" : String(v)}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}

                {!rows.length && (
                  <tr>
                    <td className="px-3 py-6 text-center text-slate-500" colSpan={displayCols.length || 1}>
                      Upload a CSV to see results.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {filtered.length > 500 && (
            <p className="mt-2 text-xs text-slate-500">
              Showing first 500 rows for performance. Add filters/search to narrow results.
            </p>
          )}
        </div>

        <footer className="mt-6 text-xs text-slate-500">
          <span className="font-mono">http://localhost:5173</span>
        </footer>
      </div>
    </div>
  );
}
