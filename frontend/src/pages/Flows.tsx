import { useMemo, useState } from "react";
import { predictCsv, type FlowResult } from "../api/client";
import { badgeForSeverity, badgeForAction, toBool } from "../lib/severity";
import { getStreamGapSeconds } from "../lib/settings";

export default function Flows() {
  const [file, setFile] = useState<File | null>(null);
  const [rows, setRows] = useState<FlowResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);

  const displayCols = useMemo(() => {
    if (!rows.length) return [];
    const keys = Object.keys(rows[0]);

    const preferred = [
      "TIME_FIRST", "TIME_LAST", "timestamp", "time",
      "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT",
      "PROTOCOL", "PROTO", "src_ip", "dst_ip", "src_port", "dst_port",
    ];
    const picked: string[] = [];
    for (const p of preferred) if (keys.includes(p)) picked.push(p);

    for (const must of [
      "is_anomaly", "severity", "confidence", "predicted_class",
      "action", "agent_state", "event_id", "note",
    ]) {
      if (keys.includes(must) && !picked.includes(must)) picked.push(must);
    }

    for (const k of keys) {
      if (picked.length >= 10) break;
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
    setRows([]);
    try {
      await predictCsv(file, getStreamGapSeconds(), (row) => {
        setRows((prev) => [...prev, row]);
      });
    } catch (e: any) {
      setError(e?.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  const anomalyCount = useMemo(
    () => rows.reduce((acc, r) => acc + (toBool(r.is_anomaly) ? 1 : 0), 0),
    [rows],
  );

  return (
    <div className="mx-auto max-w-7xl">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Flows</h1>
        <p className="mt-1 text-sm text-slate-600">
          Upload a CSV, send it through the model and policy agent, view the results.
        </p>
      </header>

      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
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
                className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? "Analyzing..." : "Analyze"}
              </button>
            </div>
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
          <span className="rounded-full bg-slate-100 px-3 py-1">Rows: <b>{rows.length}</b></span>
          <span className="rounded-full bg-slate-100 px-3 py-1">Anomalies: <b>{anomalyCount}</b></span>
          <span className="rounded-full bg-slate-100 px-3 py-1">Showing: <b>{filtered.length}</b></span>
        </div>

        <div className="mt-4 overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-50 text-slate-700 dark:bg-slate-700 dark:text-slate-200">
              <tr>
                {displayCols.map((c) => (
                  <th key={c} className="whitespace-nowrap px-3 py-2 font-semibold">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 bg-white dark:divide-slate-700 dark:bg-slate-800">
              {filtered.slice(0, 500).map((r, idx) => {
                const isA = toBool(r.is_anomaly);
                const sev = r.severity ?? (isA ? "Attack" : "Benign");
                const conf = typeof r.confidence === "number" ? r.confidence : undefined;

                return (
                  <tr key={idx} className={isA ? "bg-red-50/40" : ""}>
                    {displayCols.map((c) => {
                      if (c === "severity") {
                        return (
                          <td key={c} className="px-3 py-2">
                            <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-semibold ${badgeForSeverity(sev)}`}>
                              {sev}
                            </span>
                          </td>
                        );
                      }
                      if (c === "is_anomaly") {
                        return (
                          <td key={c} className="px-3 py-2">
                            <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-semibold ${
                              isA ? "bg-red-100 text-red-800 border-red-200" : "bg-green-100 text-green-800 border-green-200"
                            }`}>
                              {isA ? "Anomaly" : "Normal"}
                            </span>
                          </td>
                        );
                      }
                      if (c === "action") {
                        return (
                          <td key={c} className="px-3 py-2">
                            <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-medium ${badgeForAction(r.action)}`}>
                              {r.action ?? "-"}
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
                        <td key={c} className="whitespace-nowrap px-3 py-2">
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
    </div>
  );
}