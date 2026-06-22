import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Radio, FileSpreadsheet } from "lucide-react";
import { predictCsv } from "../api/client";
import { useSettings } from "../context/SettingsContext";

type Mode = "csv" | "live";

export default function Modes() {
  const [mode, setMode] = useState<Mode>("csv");
  const { streamGapSeconds } = useSettings();
  const navigate = useNavigate();

  // CSV state
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [processedCount, setProcessedCount] = useState<number | null>(null);

  async function runPredict() {
    if (!file) return;

    setLoading(true);
    setError(null);
    setProcessedCount(0);

    try {
      await predictCsv(file, streamGapSeconds, () => {
        setProcessedCount((n) => (n ?? 0) + 1);
      });
    } catch (e: any) {
      setError(e?.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Modes</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Choose how to feed data into Anoseek.
        </p>
      </header>

      {/* Mode toggle */}
      <div className="mb-6 flex gap-1.5 rounded-2xl border border-slate-200 bg-white p-1.5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
        <ModeTab
          active={mode === "csv"}
          icon={FileSpreadsheet}
          label="CSV"
          desc="Batch analysis from a file"
          onClick={() => setMode("csv")}
        />
        <ModeTab
          active={mode === "live"}
          icon={Radio}
          label="Live"
          desc="Real-time traffic monitoring"
          onClick={() => setMode("live")}
        />
      </div>

      {/* CSV panel */}
      {mode === "csv" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <h2 className="mb-1 text-sm font-semibold text-slate-900 dark:text-white">
            Batch CSV analysis
          </h2>
          <p className="mb-5 text-sm text-slate-500 dark:text-slate-400">
            Upload a network flow CSV. Each row is replayed using its actual
            flow duration as the inter-row delay, scaled by ×{streamGapSeconds} (set in Settings).
            Detected anomalies appear in the Alerts page.
          </p>

          <div className="flex flex-col gap-4">
            <input
              type="file"
              accept=".csv"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
                setProcessedCount(null);
                setError(null);
              }}
              className="block w-full text-sm text-slate-700 dark:text-slate-300
                file:mr-4 file:cursor-pointer file:rounded-xl file:border-0
                file:bg-slate-900 file:px-4 file:py-2 file:text-sm file:font-medium file:text-white
                hover:file:bg-slate-700
                dark:file:bg-slate-600 dark:hover:file:bg-slate-500"
            />

            <div className="flex items-center gap-3">
              <button
                onClick={runPredict}
                disabled={!file || loading}
                className="rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? "Analyzing…" : "Analyze"}
              </button>

              {loading && (
                <span className="text-sm text-slate-500 dark:text-slate-400">
                  Streaming rows — this may take a while…
                </span>
              )}

              {processedCount !== null && !loading && (
                <span className="text-sm font-medium text-green-600 dark:text-green-400">
                  ✓ {processedCount} rows processed — check Alerts for results
                </span>
              )}
            </div>

            {error && (
              <div className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300">
                {error}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Live panel */}
      {mode === "live" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <h2 className="mb-1 text-sm font-semibold text-slate-900 dark:text-white">
            Live monitoring
          </h2>
          <p className="mb-5 text-sm text-slate-500 dark:text-slate-400">
            Live mode processes one JSON flow at a time through the backend
            <span className="font-mono"> /predict </span>
            endpoint. This is the path the Raspberry Pi / sniffer should use for
            real-time flows.
          </p>

          <div className="mb-5 grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900/40">
              <div className="text-xs font-medium uppercase tracking-wide text-slate-400">
                Live endpoint
              </div>
              <div className="mt-1 font-mono text-sm font-semibold text-slate-900 dark:text-white">
                POST /predict
              </div>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Receives a single JSON flow and returns the prediction result.
              </p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900/40">
              <div className="text-xs font-medium uppercase tracking-wide text-slate-400">
                Flow source
              </div>
              <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-white">
                Raspberry Pi / nProbe
              </div>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Connect the Pi to the same endpoint and monitor incoming flows.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => navigate("/live")}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-200 px-5 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-700/60"
            >
              <Radio className="h-4 w-4" />
              Open Live Stream
            </button>
          </div>

        </div>
      )}
    </div>
  );
}

function ModeTab({
  active,
  icon: Icon,
  label,
  desc,
  onClick,
}: {
  active: boolean;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  desc: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={[
        "flex flex-1 items-center gap-3 rounded-xl px-5 py-3.5 text-left transition-all duration-200",
        active
          ? "bg-blue-600 text-white shadow-sm"
          : "text-slate-600 hover:bg-slate-50 dark:text-slate-400 dark:hover:bg-slate-700/60",
      ].join(" ")}
    >
      <Icon className="h-5 w-5 shrink-0" />
      <div>
        <div className="text-sm font-semibold">{label}</div>
        <div className={`text-xs ${active ? "text-blue-100" : "text-slate-400 dark:text-slate-500"}`}>
          {desc}
        </div>
      </div>
    </button>
  );
}
