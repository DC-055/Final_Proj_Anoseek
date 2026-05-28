import {
  DEFAULT_STREAM_GAP_SECONDS, MAX_STREAM_GAP_SECONDS, MIN_STREAM_GAP_SECONDS,
  DEFAULT_HISTORY_LIMIT,      MAX_HISTORY_LIMIT,      MIN_HISTORY_LIMIT,
  DEFAULT_STREAM_BUCKET_MS,   DEFAULT_STREAM_POLL_SECONDS,
  MIN_STREAM_POLL_SECONDS,    MAX_STREAM_POLL_SECONDS,
  BUCKET_OPTIONS,
} from "../lib/settings";
import { useSettings } from "../context/SettingsContext";

export default function Settings() {
  const {
    streamGapSeconds, updateStreamGap,
    historyLimit,     updateHistoryLimit,
    streamBucketMs,   updateStreamBucket,
    streamPollSeconds,updateStreamPoll,
  } = useSettings();

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Stream behavior and dashboard preferences. Changes apply immediately.
        </p>
      </header>

      <div className="flex flex-col gap-4 max-w-2xl">

        {/* CSV stream gap */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">CSV stream timing</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Delay between rows when a CSV is replayed as a stream.
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Gap between flows</span>
              <div className="mt-2 flex items-center gap-3">
                <input
                  type="range"
                  min={MIN_STREAM_GAP_SECONDS} max={MAX_STREAM_GAP_SECONDS} step="0.25"
                  value={streamGapSeconds}
                  onChange={(e) => updateStreamGap(Number(e.target.value))}
                  className="w-full accent-blue-500"
                />
                <input
                  type="number"
                  min={MIN_STREAM_GAP_SECONDS} max={MAX_STREAM_GAP_SECONDS} step="0.25"
                  value={streamGapSeconds}
                  onChange={(e) => updateStreamGap(Number(e.target.value))}
                  className="w-24 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                />
                <span className="text-sm text-slate-600 dark:text-slate-400">sec</span>
              </div>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">{streamGapSeconds.toFixed(2)}s</span>
              <button type="button" onClick={() => updateStreamGap(DEFAULT_STREAM_GAP_SECONDS)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

        {/* Live stream poll interval */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Live stream poll interval</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                How often the Live stream page fetches new events from the agent.
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Poll every</span>
              <div className="mt-2 flex items-center gap-3">
                <input
                  type="range"
                  min={MIN_STREAM_POLL_SECONDS} max={MAX_STREAM_POLL_SECONDS} step="1"
                  value={streamPollSeconds}
                  onChange={(e) => updateStreamPoll(Number(e.target.value))}
                  className="w-full accent-blue-500"
                />
                <input
                  type="number"
                  min={MIN_STREAM_POLL_SECONDS} max={MAX_STREAM_POLL_SECONDS} step="1"
                  value={streamPollSeconds}
                  onChange={(e) => updateStreamPoll(Number(e.target.value))}
                  className="w-24 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                />
                <span className="text-sm text-slate-600 dark:text-slate-400">sec</span>
              </div>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">{streamPollSeconds}s</span>
              <button type="button" onClick={() => updateStreamPoll(DEFAULT_STREAM_POLL_SECONDS)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

        {/* Live stream time frame bucket */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Live stream time frame</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Bucket size for the flows-per-time-frame chart. "Auto" picks a size based on the event range.
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Bucket size </span>
              <select
                value={streamBucketMs}
                onChange={(e) => updateStreamBucket(Number(e.target.value))}
                className="mt-2 w-48 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
              >
                {BUCKET_OPTIONS.map((o) => (
                  <option key={o.ms} value={o.ms}>{o.label}</option>
                ))}
              </select>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">
                Current: {BUCKET_OPTIONS.find((o) => o.ms === streamBucketMs)?.label ?? "Auto"}
              </span>
              <button type="button" onClick={() => updateStreamBucket(DEFAULT_STREAM_BUCKET_MS)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

        {/* Chat history */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Chat flow history</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Number of recent flows the chatbot will use as context (1–{MAX_HISTORY_LIMIT}).
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Flows to include</span>
              <div className="mt-2 flex items-center gap-3">
                <input
                  type="range"
                  min={MIN_HISTORY_LIMIT} max={MAX_HISTORY_LIMIT} step="1"
                  value={historyLimit}
                  onChange={(e) => updateHistoryLimit(Number(e.target.value))}
                  className="w-full accent-blue-500"
                />
                <input
                  type="number"
                  min={MIN_HISTORY_LIMIT} max={MAX_HISTORY_LIMIT} step="1"
                  value={historyLimit}
                  onChange={(e) => updateHistoryLimit(Number(e.target.value))}
                  className="w-24 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                />
                <span className="text-sm text-slate-600 dark:text-slate-400">flows</span>
              </div>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">{historyLimit} flows</span>
              <button type="button" onClick={() => updateHistoryLimit(DEFAULT_HISTORY_LIMIT)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
