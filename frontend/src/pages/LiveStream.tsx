import { useEffect, useMemo, useRef, useState } from "react";
import { getAgentEvents, type EventRecord } from "../api/client";
import { badgeForSeverity, badgeForAction } from "../lib/severity";
import { getStreamBucketMs } from "../lib/settings";

const POLL_MS = 5000;

export default function LiveStream() {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  async function fetchEvents() {
    try {
      const data = await getAgentEvents("all", 200);
      setEvents(data);
      setError(null);
    } catch (e: any) {
      setError(e?.message ?? "Failed to fetch events");
    }
  }

  useEffect(() => {
    fetchEvents();
    intervalRef.current = setInterval(fetchEvents, POLL_MS);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  const timeStats = useMemo(() => {
    if (events.length < 2) return null;

    const timestamps = events
      .map((e) => new Date(e.timestamp).getTime())
      .filter((t) => !isNaN(t));
    if (timestamps.length < 2) return null;

    const minT = Math.min(...timestamps);
    const maxT = Math.max(...timestamps);
    const range = maxT - minT;

    const savedBucket = getStreamBucketMs();
    const niceSteps = [
      60_000, 5 * 60_000, 15 * 60_000, 30 * 60_000,
      60 * 60_000, 3 * 60 * 60_000, 6 * 60 * 60_000, 24 * 60 * 60_000,
    ];
    const bucketMs = savedBucket > 0
      ? savedBucket
      : niceSteps.find((s) => s >= range / 24) ?? niceSteps[niceSteps.length - 1];

    const fmt = (ms: number): string => {
      const d = new Date(ms);
      if (bucketMs < 60 * 60_000)
        return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`;
      if (bucketMs < 24 * 60 * 60_000)
        return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:00`;
      return `${d.getMonth() + 1}/${d.getDate()}`;
    };

    const counts = new Map<number, number>();
    for (const t of timestamps) {
      const bucket = Math.floor(t / bucketMs) * bucketMs;
      counts.set(bucket, (counts.get(bucket) ?? 0) + 1);
    }

    const sorted = [...counts.entries()].sort((a, b) => a[0] - b[0]);
    const maxCount = Math.max(...sorted.map(([, c]) => c));
    return { buckets: sorted.map(([ts, count]) => ({ label: fmt(ts), count })), maxCount };
  }, [events]);

  const recent = useMemo(() => [...events].reverse().slice(0, 100), [events]);

  return (
    <div className="mx-auto max-w-7xl">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Live stream</h1>
        <p className="mt-1 text-sm text-slate-600">
          Agent event feed — polls every {POLL_MS / 1000}s.
        </p>
      </header>

      {error && (
        <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {error}
        </div>
      )}

      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">

        {/* Stats pills */}
        <div className="flex flex-wrap gap-2 text-sm text-slate-700">
          <span className="rounded-full bg-slate-100 px-3 py-1">
            Events: <b>{events.length}</b>
          </span>
          <span className="rounded-full bg-red-100 px-3 py-1 text-red-700">
            Flagged: <b>{events.filter((e) => e.severity > 0).length}</b>
          </span>
          <span className="rounded-full bg-orange-100 px-3 py-1 text-orange-700">
            Blocked: <b>{events.filter((e) => e.action === "block").length}</b>
          </span>
          <span className="animate-pulse rounded-full bg-green-100 px-3 py-1 text-green-700">
            Live
          </span>
        </div>

        {/* Time chart */}
        {timeStats ? (
          <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">
              Flows per time frame
              <span className="ml-2 font-normal normal-case">
                ({timeStats.buckets.length} buckets)
              </span>
            </p>
            <div className="flex items-end gap-[3px] overflow-x-auto pb-8">
              {timeStats.buckets.map(({ label, count }, i) => (
                <div
                  key={i}
                  className="group relative flex flex-col items-center"
                  style={{ minWidth: "34px" }}
                >
                  <span className="mb-0.5 text-[10px] text-slate-500">{count}</span>
                  <div
                    className="w-full rounded-t bg-blue-500 transition-colors group-hover:bg-blue-400"
                    style={{ height: `${Math.max(3, Math.round((count / timeStats.maxCount) * 72))}px` }}
                  />
                  <span
                    className="absolute bottom-0 left-1/2 whitespace-nowrap text-[9px] text-slate-400"
                    style={{ transform: "translateX(-50%) rotate(-40deg) translateY(100%)" }}
                  >
                    {label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          events.length === 0 && (
            <div className="mt-6 rounded-xl border border-dashed border-slate-300 p-10 text-center text-sm text-slate-400">
              No events yet — run a prediction to generate flow data.
            </div>
          )
        )}

        {/* Event feed */}
        {recent.length > 0 && (
          <div className="mt-4 overflow-x-auto rounded-xl border border-slate-200">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-50 text-slate-700">
                <tr>
                  {["Time", "Src IP", "Dst IP", "Severity", "Confidence", "Action"].map((h) => (
                    <th key={h} className="whitespace-nowrap px-3 py-2 font-semibold">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {recent.map((e) => (
                  <tr key={e.event_id} className={e.severity > 0 ? "bg-red-50/40" : ""}>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-500">
                      {e.timestamp.replace("T", " ").slice(0, 19)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{e.src_ip ?? "-"}</td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{e.dst_ip ?? "-"}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-semibold ${badgeForSeverity(e.severity_label)}`}>
                        {e.severity_label}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {e.confidence !== undefined ? e.confidence.toFixed(3) : "-"}
                    </td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-medium ${badgeForAction(e.action)}`}>
                        {e.action ?? "-"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
