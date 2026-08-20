import { useEffect, useMemo, useRef, useState } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import { getAgentEvents, type EventRecord } from "../api/client";
import { BUCKET_OPTIONS } from "../lib/settings";
import { useDarkModeContext } from "../context/DarkModeContext";
import { useSettings } from "../context/SettingsContext";
import { badgeForAction } from "../lib/severity";
import SeverityBadge from "../components/SeverityBadge";

function colorForLabel(label: string): string {
  const s = label.toLowerCase();
  if (!label || s === "benign" || s === "none") return "#22c55e"; // green
  if (s.includes("recon") || s.includes("scan")) return "#eab308"; // yellow
  if (s.includes("brute") || s.includes("fuzz")) return "#f97316"; // orange
  if (s.includes("dos") || s.includes("ddos"))   return "#ef4444"; // red
  return "#a855f7";                                                 // purple
}

export default function LiveStream() {
  const { dark } = useDarkModeContext();
  const { streamBucketMs, streamPollSeconds, updateStreamBucket } = useSettings();
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
    intervalRef.current = setInterval(fetchEvents, streamPollSeconds * 1000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [streamPollSeconds]);

  const labels = useMemo(
    () => [...new Set(events.map((e) => e.severity_label).filter(Boolean))],
    [events],
  );

  const { chartData, lastUpdate } = useMemo(() => {
    if (events.length < 2) return { chartData: [], lastUpdate: null };

    const timestamps = events
      .map((e) => new Date(e.timestamp).getTime())
      .filter((t) => !isNaN(t));
    if (timestamps.length < 2) return { chartData: [], lastUpdate: null };

    const minT = Math.min(...timestamps);
    const maxT = Math.max(...timestamps);
    const range = maxT - minT;

    const niceSteps = [
      30_000, 60_000, 5 * 60_000, 15 * 60_000, 30 * 60_000,
      60 * 60_000, 3 * 60 * 60_000, 6 * 60 * 60_000, 24 * 60 * 60_000,
    ];
    const bucketMs =
      streamBucketMs > 0
        ? streamBucketMs
        : niceSteps.find((s) => s >= range / 24) ?? niceSteps[niceSteps.length - 1];

    const fmt = (ms: number): string => {
      const d = new Date(ms);
      if (bucketMs < 60 * 60_000)
        return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`;
      if (bucketMs < 24 * 60 * 60_000)
        return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:00`;
      return `${d.getMonth() + 1}/${d.getDate()}`;
    };

    const buckets = new Map<number, Record<string, number>>();
    for (const e of events) {
      const t = new Date(e.timestamp).getTime();
      if (isNaN(t)) continue;
      const bucket = Math.floor(t / bucketMs) * bucketMs;
      if (!buckets.has(bucket)) buckets.set(bucket, {});
      const b = buckets.get(bucket)!;
      b[e.severity_label] = (b[e.severity_label] ?? 0) + 1;
    }

    const allLabels = [...new Set(events.map((e) => e.severity_label).filter(Boolean))];
    const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
    const chartData = sorted.map(([ts, counts]) => {
      const row: Record<string, number | string> = { time: fmt(ts) };
      for (const lbl of allLabels) row[lbl] = counts[lbl] ?? 0;
      return row;
    });
    return { chartData, lastUpdate: new Date(maxT) };
  }, [events, streamBucketMs]);

  const peakCount = useMemo(() => {
    if (!chartData.length) return 0;
    return Math.max(
      ...chartData.map((d) =>
        labels.reduce((sum, l) => sum + (((d as any)[l]) ?? 0), 0),
      ),
    );
  }, [chartData, labels]);

  const activeIPs = useMemo(
    () => new Set(events.map((e) => e.src_ip).filter(Boolean)).size,
    [events],
  );

  const recentLog = useMemo(() => [...events].reverse().slice(0, 50), [events]);

  const grid  = dark ? "#334155" : "#e2e8f0";
  const tick  = dark ? "#94a3b8" : "#64748b";
  const ttBg  = dark ? "#1e293b" : "#ffffff";
  const ttBdr = dark ? "#475569" : "#e2e8f0";
  const ttLbl = dark ? "#94a3b8" : "#475569";

  const cardCls = "rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800";

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8 space-y-4">

      {/* Header */}
      <header className="flex flex-wrap items-center gap-3">
        <span className="flex items-center gap-2 rounded-md bg-red-600 px-3 py-1 text-xs font-bold uppercase tracking-widest text-white">
          <span className="h-2 w-2 animate-pulse rounded-full bg-white" />
          Live
        </span>
        <h1 className="text-xl font-bold uppercase tracking-wide">
          Live Flow Transmission Analytics
        </h1>
        <span className="ml-auto text-xs text-slate-400 dark:text-slate-500">
          Last update: {lastUpdate ? lastUpdate.toLocaleTimeString() : "waiting…"}
        </span>
      </header>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-500 dark:bg-red-900/30 dark:text-red-300">
          {error}
        </div>
      )}

      {/* Chart + stat cards row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_200px]">

        {/* Chart panel */}
        <div className={cardCls}>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500">
                Time-series flow analysis
              </p>
              <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                Polling every {streamPollSeconds}s
              </p>
            </div>
            <div className="flex flex-wrap gap-1">
              {BUCKET_OPTIONS.map((o) => (
                <button
                  key={o.ms}
                  onClick={() => updateStreamBucket(o.ms)}
                  className={[
                    "rounded-lg px-2.5 py-1 text-[11px] font-medium transition-all duration-150 focus:outline-none",
                    streamBucketMs === o.ms
                      ? "bg-blue-600 text-white shadow-sm"
                      : "border border-slate-200 bg-white text-slate-600 hover:border-blue-300 hover:text-blue-600 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-300 dark:hover:border-blue-400 dark:hover:text-blue-400",
                  ].join(" ")}
                >
                  {o.label}
                </button>
              ))}
            </div>
          </div>

          {chartData.length > 1 ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={grid} />
                <XAxis dataKey="time" tick={{ fill: tick, fontSize: 11 }} />
                <YAxis tick={{ fill: tick, fontSize: 11 }} allowDecimals={false} domain={[0, "auto"]} />
                <Tooltip
                  contentStyle={{ background: ttBg, border: `1px solid ${ttBdr}`, borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: ttLbl }}
                />
                <Legend wrapperStyle={{ color: tick, fontSize: 12 }} />
                {labels.map((label) => (
                  <Line
                    key={label}
                    type="monotone"
                    dataKey={label}
                    stroke={colorForLabel(label)}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4 }}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[300px] items-center justify-center rounded-xl border border-dashed border-slate-300 text-sm text-slate-400 dark:border-slate-600 dark:text-slate-500">
              No event data yet — run a prediction to generate flows.
            </div>
          )}
        </div>

        {/* Stat cards */}
        <div className="flex flex-col gap-3">
          <div className={cardCls}>
            <p className="text-xs uppercase tracking-widest text-slate-400 dark:text-slate-500">Total events</p>
            <p className="mt-1 text-3xl font-bold text-slate-900 dark:text-slate-100">{events.length}</p>
          </div>
          <div className={cardCls}>
            <p className="text-xs uppercase tracking-widest text-slate-400 dark:text-slate-500">Active IPs</p>
            <p className="mt-1 text-3xl font-bold text-slate-900 dark:text-slate-100">{activeIPs}</p>
          </div>
          <div className={cardCls}>
            <p className="text-xs uppercase tracking-widest text-slate-400 dark:text-slate-500">Peak (bucket)</p>
            <p className="mt-1 text-3xl font-bold text-slate-900 dark:text-slate-100">{peakCount}</p>
          </div>
        </div>
      </div>

      {/* Live log — full width below chart */}
      <div className={cardCls}>
        <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500">
          Live event log
        </p>

        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700">
                <th className="pb-2 pr-4 font-semibold text-slate-500 dark:text-slate-400">Time</th>
                <th className="pb-2 pr-4 font-semibold text-slate-500 dark:text-slate-400">Severity</th>
                <th className="pb-2 pr-4 font-semibold text-slate-500 dark:text-slate-400">Source IP</th>
                <th className="pb-2 pr-4 font-semibold text-slate-500 dark:text-slate-400">Dest IP</th>
                <th className="pb-2 pr-4 font-semibold text-slate-500 dark:text-slate-400">Action</th>
                <th className="pb-2 pr-4 font-semibold text-slate-500 dark:text-slate-400">Confidence</th>
                <th className="pb-2 font-semibold text-slate-500 dark:text-slate-400">Note</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50 dark:divide-slate-700/60">
              {recentLog.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-400 dark:text-slate-500">
                    Waiting for events…
                  </td>
                </tr>
              )}
              {recentLog.map((e) => (
                <tr
                  key={e.event_id}
                  className={
                    e.severity > 0
                      ? "bg-orange-50/50 dark:bg-orange-900/10"
                      : ""
                  }
                >
                  <td className="py-1.5 pr-4 font-mono text-slate-500 dark:text-slate-400">
                    {e.timestamp.slice(11, 19)}
                  </td>
                  <td className="py-1.5 pr-4">
                    <SeverityBadge label={e.severity_label} />
                  </td>
                  <td className="py-1.5 pr-4 font-mono text-slate-700 dark:text-slate-300">
                    {e.src_ip ?? "—"}
                  </td>
                  <td className="py-1.5 pr-4 font-mono text-slate-700 dark:text-slate-300">
                    {e.dst_ip ?? "—"}
                  </td>
                  <td className="py-1.5 pr-4">
                    {e.action ? (
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${badgeForAction(e.action)}`}>
                        {e.action}
                      </span>
                    ) : "—"}
                  </td>
                  <td className="py-1.5 pr-4 font-mono text-slate-600 dark:text-slate-400">
                    {typeof e.confidence === "number" ? e.confidence.toFixed(3) : "—"}
                  </td>
                  <td className="py-1.5 text-slate-500 dark:text-slate-400">
                    {e.note ?? ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
