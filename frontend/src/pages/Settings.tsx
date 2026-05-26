import { useState } from "react";
import {
  DEFAULT_STREAM_GAP_SECONDS,
  MAX_STREAM_GAP_SECONDS,
  MIN_STREAM_GAP_SECONDS,
  getStreamGapSeconds,
  setStreamGapSeconds,
  DEFAULT_HISTORY_LIMIT,
  MAX_HISTORY_LIMIT,
  MIN_HISTORY_LIMIT,
  getHistoryLimit,
  setHistoryLimit,
} from "../lib/settings";

export default function Settings() {
  const [gapSeconds, setGapSecondsState] = useState(() =>
    getStreamGapSeconds()
  );
  const [historyLimit, setHistoryLimitState] = useState(() =>
    getHistoryLimit()
  );

  function updateGap(value: number) {
    setGapSecondsState(setStreamGapSeconds(value));
  }

  function updateHistoryLimit(value: number) {
    setHistoryLimitState(setHistoryLimit(value));
  }

  return (
    <div className="mx-auto max-w-7xl">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-slate-600">
          Stream behavior and dashboard preferences.
        </p>
      </header>

      <div className="max-w-2xl rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-col gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              CSV stream timing
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Controls the delay between rows when a CSV is replayed as a stream.
            </p>
          </div>

          <label className="block">
            <span className="text-sm font-medium text-slate-700">
              Gap between flows
            </span>

            <div className="mt-2 flex items-center gap-3">
              <input
                type="range"
                min={MIN_STREAM_GAP_SECONDS}
                max={MAX_STREAM_GAP_SECONDS}
                step="0.25"
                value={gapSeconds}
                onChange={(e) => updateGap(Number(e.target.value))}
                className="w-full"
              />

              <input
                type="number"
                min={MIN_STREAM_GAP_SECONDS}
                max={MAX_STREAM_GAP_SECONDS}
                step="0.25"
                value={gapSeconds}
                onChange={(e) => updateGap(Number(e.target.value))}
                className="w-24 rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200"
              />

              <span className="text-sm text-slate-600">sec</span>
            </div>
          </label>

          <div className="flex items-center justify-between border-t border-slate-100 pt-3">
            <span className="text-xs text-slate-500">
              Current value: {gapSeconds.toFixed(2)} seconds
            </span>

            <button
              type="button"
              onClick={() => updateGap(DEFAULT_STREAM_GAP_SECONDS)}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              Reset
            </button>
          </div>
        </div>
      </div>

      <div className="mt-4 max-w-2xl rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-col gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              Chat flow history
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Number of recent flows the chatbot will use as context when a
              conversation starts (1–30).
            </p>
          </div>

          <label className="block">
            <span className="text-sm font-medium text-slate-700">
              Flows to include
            </span>

            <div className="mt-2 flex items-center gap-3">
              <input
                type="range"
                min={MIN_HISTORY_LIMIT}
                max={MAX_HISTORY_LIMIT}
                step="1"
                value={historyLimit}
                onChange={(e) => updateHistoryLimit(Number(e.target.value))}
                className="w-full"
              />

              <input
                type="number"
                min={MIN_HISTORY_LIMIT}
                max={MAX_HISTORY_LIMIT}
                step="1"
                value={historyLimit}
                onChange={(e) => updateHistoryLimit(Number(e.target.value))}
                className="w-24 rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200"
              />

              <span className="text-sm text-slate-600">flows</span>
            </div>
          </label>

          <div className="flex items-center justify-between border-t border-slate-100 pt-3">
            <span className="text-xs text-slate-500">
              Current value: {historyLimit} flows
            </span>

            <button
              type="button"
              onClick={() => updateHistoryLimit(DEFAULT_HISTORY_LIMIT)}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              Reset
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}