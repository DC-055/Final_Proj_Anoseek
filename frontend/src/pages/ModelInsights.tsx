import { useMemo } from "react";
import {
  BarChart, Bar, Cell, LabelList, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from "recharts";
import { useAgentState } from "../hooks/useAgentState";
import { useEvents } from "../hooks/useEvents";
import { useDarkModeContext } from "../context/DarkModeContext";
import KpiCard from "../components/KpiCard";
import SeverityBadge from "../components/SeverityBadge";

const CLASSES = [
  "Benign",
  "Recon / scanning",
  "Brute force attacks",
  "DoS / DDoS attacks",
  "Exploitation attacks",
];

// Same identity mapping used on Overview/Live stream — kept consistent across the app.
const CLASS_COLORS = ["#22c55e", "#eab308", "#f97316", "#ef4444", "#a855f7"];

const ACTIONS = ["pass", "flag", "alert", "block", "rate_limit", "error"] as const;
const ACTION_COLORS: Record<string, string> = {
  pass: "#94a3b8",
  flag: "#eab308",
  alert: "#f97316",
  block: "#ef4444",
  rate_limit: "#3b82f6",
  error: "#a855f7",
};

const CONFIDENCE_BUCKETS = [
  { key: "0-50%", min: 0, max: 0.5 },
  { key: "50-60%", min: 0.5, max: 0.6 },
  { key: "60-70%", min: 0.6, max: 0.7 },
  { key: "70-80%", min: 0.7, max: 0.8 },
  { key: "80-90%", min: 0.8, max: 0.9 },
  { key: "90-100%", min: 0.9, max: 1.0001 },
];

export default function ModelInsights() {
  const { dark } = useDarkModeContext();
  const { snapshot } = useAgentState(1000);
  const { events, error } = useEvents("all", 1000, 3000);

  const severityCounts = useMemo(() => {
    const counts = [0, 0, 0, 0, 0];
    for (const e of events) {
      if (typeof e.severity === "number" && e.severity >= 0 && e.severity < 5) counts[e.severity]++;
    }
    return counts;
  }, [events]);

  const totalEvents = events.length;
  const anomalyCount = totalEvents - severityCounts[0];
  const anomalyRate = totalEvents > 0 ? `${((anomalyCount / totalEvents) * 100).toFixed(1)}%` : "—";

  const confidences = useMemo(
    () => events.map((e) => e.confidence).filter((c): c is number => typeof c === "number"),
    [events],
  );
  const avgConfidence =
    confidences.length > 0
      ? `${((confidences.reduce((a, b) => a + b, 0) / confidences.length) * 100).toFixed(1)}%`
      : "—";

  const uniqueSrcIps = useMemo(
    () => new Set(events.map((e) => e.src_ip).filter(Boolean)).size,
    [events],
  );

  const severityBarData = useMemo(
    () =>
      CLASSES.map((label, i) => ({ label, count: severityCounts[i] })).filter(
        (d) => d.count > 0,
      ),
    [severityCounts],
  );

  const actionBarData = useMemo(
    () =>
      ACTIONS.map((action) => ({
        action,
        count: events.filter((e) => e.action === action).length,
      })).filter((d) => d.count > 0),
    [events],
  );

  const confidenceHistData = useMemo(
    () =>
      CONFIDENCE_BUCKETS.map((b) => ({
        bucket: b.key,
        count: confidences.filter((c) => c >= b.min && c < b.max).length,
      })),
    [confidences],
  );

  const avgConfidenceBySeverity = useMemo(
    () =>
      CLASSES.map((label, i) => {
        const inClass = events.filter((e) => e.severity === i && typeof e.confidence === "number");
        const avg =
          inClass.length > 0
            ? inClass.reduce((a, e) => a + (e.confidence as number), 0) / inClass.length
            : 0;
        return { label, avgConfidence: Number((avg * 100).toFixed(1)), count: inClass.length };
      }).filter((d) => d.count > 0),
    [events],
  );

  const topSourceIps = useMemo(() => {
    const byIp = new Map<string, { total: number; anomalies: number; maxSeverity: number; confSum: number; confN: number }>();
    for (const e of events) {
      if (!e.src_ip) continue;
      const cur = byIp.get(e.src_ip) ?? { total: 0, anomalies: 0, maxSeverity: 0, confSum: 0, confN: 0 };
      cur.total++;
      if (e.severity > 0) cur.anomalies++;
      cur.maxSeverity = Math.max(cur.maxSeverity, e.severity);
      if (typeof e.confidence === "number") {
        cur.confSum += e.confidence;
        cur.confN++;
      }
      byIp.set(e.src_ip, cur);
    }
    return [...byIp.entries()]
      .map(([src_ip, s]) => ({
        src_ip,
        total: s.total,
        anomalies: s.anomalies,
        maxSeverityLabel: CLASSES[s.maxSeverity] ?? "—",
        avgConfidence: s.confN > 0 ? s.confSum / s.confN : null,
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 8);
  }, [events]);

  const grid = dark ? "#334155" : "#e2e8f0";
  const tick = dark ? "#94a3b8" : "#64748b";
  const ttBg = dark ? "#1e293b" : "#ffffff";
  const ttBdr = dark ? "#475569" : "#e2e8f0";
  const ttLbl = dark ? "#94a3b8" : "#475569";

  const cardCls = "rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800";

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8 space-y-4">
      <header className="mb-2">
        <h1 className="text-2xl font-semibold tracking-tight">System Insights</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Statistical analysis of the network traffic the agent has analyzed
        </p>
      </header>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-500 dark:bg-red-900/30 dark:text-red-300">
          {error}
        </div>
      )}

      {/* KPI cards */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard label="Flows analyzed" value={snapshot ? snapshot.totals.flows_seen : "—"} />
        <KpiCard label="Anomaly rate" value={anomalyRate} tone="danger" />
        <KpiCard label="Avg. confidence" value={avgConfidence} />
        <KpiCard label="Unique source IPs" value={uniqueSrcIps} />
      </div>

      {totalEvents === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-12 text-center text-sm text-slate-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-400">
          No traffic analyzed yet — upload a CSV in the Modes page to see statistics here.
        </div>
      ) : (
        <>
          {/* Severity distribution + action breakdown */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className={cardCls}>
              <h2 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                Severity distribution
              </h2>
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={severityBarData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={grid} horizontal={false} />
                  <XAxis type="number" tick={{ fill: tick, fontSize: 11 }} allowDecimals={false} />
                  <YAxis type="category" dataKey="label" width={120} tick={{ fill: tick, fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: ttBg, border: `1px solid ${ttBdr}`, borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: ttLbl }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {severityBarData.map((d) => (
                      <Cell key={d.label} fill={CLASS_COLORS[CLASSES.indexOf(d.label)]} />
                    ))}
                    <LabelList dataKey="count" position="right" fill={tick} fontSize={11} />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className={cardCls}>
              <h2 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                Agent actions
              </h2>
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={actionBarData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={grid} />
                  <XAxis dataKey="action" tick={{ fill: tick, fontSize: 11 }} />
                  <YAxis tick={{ fill: tick, fontSize: 11 }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: ttBg, border: `1px solid ${ttBdr}`, borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: ttLbl }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {actionBarData.map((d) => (
                      <Cell key={d.action} fill={ACTION_COLORS[d.action]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Confidence histogram + avg confidence by severity */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className={cardCls}>
              <h2 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                Classification confidence distribution
              </h2>
              {confidences.length === 0 ? (
                <div className="flex h-[260px] items-center justify-center text-sm text-slate-500 dark:text-slate-400">
                  No classification confidence data available.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={confidenceHistData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={grid} />
                    <XAxis dataKey="bucket" tick={{ fill: tick, fontSize: 11 }} />
                    <YAxis tick={{ fill: tick, fontSize: 11 }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ background: ttBg, border: `1px solid ${ttBdr}`, borderRadius: 8, fontSize: 12 }}
                      labelStyle={{ color: ttLbl }}
                    />
                    <Bar dataKey="count" fill="#2563eb" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className={cardCls}>
              <h2 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">
                Avg. classification confidence by class
              </h2>
              {avgConfidenceBySeverity.length === 0 ? (
                <div className="flex h-[260px] items-center justify-center text-sm text-slate-500 dark:text-slate-400">
                  No classification confidence data available.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={avgConfidenceBySeverity} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={grid} />
                    <XAxis dataKey="label" tick={{ fill: tick, fontSize: 10 }} interval={0} angle={-15} textAnchor="end" height={50} />
                    <YAxis tick={{ fill: tick, fontSize: 11 }} domain={[0, 100]} unit="%" />
                    <Tooltip
                      contentStyle={{ background: ttBg, border: `1px solid ${ttBdr}`, borderRadius: 8, fontSize: 12 }}
                      labelStyle={{ color: ttLbl }}
                      formatter={(v: any) => [`${v}%`, "Avg. confidence"]}
                    />
                    <Bar dataKey="avgConfidence" radius={[4, 4, 0, 0]}>
                      {avgConfidenceBySeverity.map((d) => (
                        <Cell key={d.label} fill={CLASS_COLORS[CLASSES.indexOf(d.label)]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Top source IPs */}
          <div className={cardCls}>
            <div className="mb-3 flex items-baseline justify-between">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Top source IPs
              </h2>
              <span className="text-xs text-slate-500 dark:text-slate-400">by flow count</span>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  <tr>
                    <th className="px-3 py-2 font-medium">Source IP</th>
                    <th className="px-3 py-2 font-medium">Flows</th>
                    <th className="px-3 py-2 font-medium">Anomalies</th>
                    <th className="px-3 py-2 font-medium">Highest severity</th>
                    <th className="px-3 py-2 font-medium">Avg. confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                  {topSourceIps.map((row) => (
                    <tr key={row.src_ip} className="hover:bg-slate-50 dark:hover:bg-slate-700/40">
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-700 dark:text-slate-300">
                        {row.src_ip}
                      </td>
                      <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{row.total}</td>
                      <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{row.anomalies}</td>
                      <td className="px-3 py-2">
                        <SeverityBadge label={row.maxSeverityLabel} />
                      </td>
                      <td className="px-3 py-2 text-slate-700 dark:text-slate-300">
                        {row.avgConfidence != null ? `${(row.avgConfidence * 100).toFixed(1)}%` : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
