import { useMemo } from "react";
import { useAgentState } from "../hooks/useAgentState";
import { useEvents } from "../hooks/useEvents";
import KpiCard from "../components/KpiCard";
import SeverityBadge from "../components/SeverityBadge";
import { badgeForAction } from "../lib/severity";

const CLASSES = [
  "Benign",
  "Recon / scanning",
  "Brute force attacks",
  "DoS / DDoS attacks",
  "Exploitation attacks",
];

const BAR_COLORS = [
  "bg-green-500",
  "bg-yellow-500",
  "bg-orange-500",
  "bg-red-500",
  "bg-purple-500",
];

export default function Overview() {
  const { snapshot } = useAgentState(3000);
  const { events }   = useEvents("all", 200, 4000);

  const severityCounts = useMemo(() => {
    const counts = [0, 0, 0, 0, 0];
    for (const e of events) {
      const s = e.severity;
      if (typeof s === "number" && s >= 0 && s < 5) counts[s]++;
    }
    return counts;
  }, [events]);

  const totalEvents = severityCounts.reduce((a, b) => a + b, 0);
  const maxCount    = Math.max(1, ...severityCounts);

  const totals = snapshot?.totals;
  const flowsAnalyzed = totals ? totals.events      : "—";
  const blockedIps    = totals ? totals.blocked_ips : "—";
  const openAlerts    = totals ? totals.flagged      : "—";
  const anomalyCount = totalEvents - severityCounts[0];
  const anomalyRate =
  totalEvents > 0
    ? `${((anomalyCount / totalEvents) * 100).toFixed(1)}%`
    : "—";

  const criticalEvents = useMemo(
    () =>
      events
        .filter((e) => e.action === "flag" || e.action === "alert" || e.action === "block")
        .slice(-10)
        .reverse(),
    [events],
  );

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8">
      <header className="mb-6 flex items-baseline justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            Real-time SOC dashboard · refreshes every 3–4 seconds
          </p>
        </div>
        <div className="hidden text-xs text-slate-500 dark:text-slate-400 md:block">
          {totalEvents > 0 && `Showing data from last ${totalEvents} events`}
        </div>
      </header>

      {/* KPI cards */}
      <div className="mb-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard label="Flows analyzed" value={flowsAnalyzed} />
        <KpiCard label="Anomaly rate"   value={anomalyRate}   tone="danger" />
        <KpiCard label="Blocked IPs"    value={blockedIps} />
        <KpiCard label="Open alerts"    value={openAlerts}    tone="warning" />
      </div>

      {/* Severity mix + action breakdown */}
      <div className="mb-6 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800 lg:col-span-2">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Severity mix</h2>
            <span className="text-xs text-slate-500 dark:text-slate-400">{totalEvents} events</span>
          </div>

          {totalEvents === 0 ? (
            <div className="py-8 text-center text-sm text-slate-500 dark:text-slate-400">
              No events yet — upload a CSV in the Modes page to see data here.
            </div>
          ) : (
            <div className="space-y-2.5">
              {CLASSES.map((label, i) => {
                const count = severityCounts[i];
                const pct   = totalEvents ? (count / totalEvents) * 100 : 0;
                const width = (count / maxCount) * 100;
                return (
                  <div key={label}>
                    <div className="mb-1 flex justify-between text-xs">
                      <span className="font-medium text-slate-700 dark:text-slate-300">{label}</span>
                      <span className="text-slate-500 dark:text-slate-400">
                        {count.toLocaleString()} · {pct.toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-700">
                      <div
                        className={`h-full rounded-full ${BAR_COLORS[i]}`}
                        style={{ width: `${width}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <h2 className="mb-3 text-sm font-semibold text-slate-900 dark:text-slate-100">Agent actions</h2>
          {totalEvents === 0 ? (
            <div className="py-8 text-center text-sm text-slate-500 dark:text-slate-400">
              No actions yet.
            </div>
          ) : (
            <div className="space-y-2">
              {(["pass", "flag", "alert", "block"] as const).map((act) => {
                const n = events.filter((e) => e.action === act).length;
                return (
                  <div key={act} className="flex items-center justify-between">
                    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${badgeForAction(act)}`}>
                      {act}
                    </span>
                    <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{n}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Recent critical events */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Recent critical events</h2>
          <span className="text-xs text-slate-500 dark:text-slate-400">flag / alert / block</span>
        </div>

        {criticalEvents.length === 0 ? (
          <div className="py-8 text-center text-sm text-slate-500 dark:text-slate-400">
            No critical events yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                <tr>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Source</th>
                  <th className="px-3 py-2 font-medium">Destination</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                  <th className="px-3 py-2 font-medium">Note</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                {criticalEvents.map((e) => (
                  <tr key={e.event_id} className="hover:bg-slate-50 dark:hover:bg-slate-700/40">
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-600 dark:text-slate-400">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-700 dark:text-slate-300">
                      {e.src_ip ?? "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-700 dark:text-slate-300">
                      {e.dst_ip ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge label={e.severity_label} />
                    </td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${badgeForAction(e.action)}`}>
                        {e.action}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
                      {e.note ?? "—"}
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
