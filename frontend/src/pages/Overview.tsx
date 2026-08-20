import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAgentState } from "../hooks/useAgentState";
import { useEvents } from "../hooks/useEvents";
import KpiCard from "../components/KpiCard";
import SeverityBadge from "../components/SeverityBadge";
import { badgeForAction, badgeForAgentState, labelForAgentState } from "../lib/severity";
import { getAgentConfig, type AgentConfig } from "../api/client";

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
  const navigate = useNavigate();
  const { snapshot } = useAgentState(1000);
  const { events }   = useEvents("all", 200, 2000);

  // Static agent constants (decay thresholds) — fetched once, same source as Topbar/AgentState.
  const [config, setConfig] = useState<AgentConfig | null>(null);
  useEffect(() => {
    getAgentConfig().then(setConfig).catch(() => {});
  }, []);

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
  const flowsAnalyzed = totals ? totals.flows_seen  : "—";
  const blockedIps    = totals ? totals.blocked_ips : "—";
  const openAlerts    = totals ? totals.flagged      : "—";
  const anomalyCount = totalEvents - severityCounts[0];
  const anomalyRate =
  totalEvents > 0
    ? `${((anomalyCount / totalEvents) * 100).toFixed(1)}%`
    : "—";

  const elapsedInState = snapshot
    ? Math.max(0, Math.floor((Date.now() - new Date(snapshot.entered_state_at).getTime()) / 1000))
    : 0;

  const lastTransition = snapshot?.transitions.length
    ? snapshot.transitions[snapshot.transitions.length - 1]
    : null;

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
            Real-time SOC dashboard · refreshes every 2 seconds
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
                const width = pct;
                return (
                  <div key={label}>
                    <div className="mb-1 flex justify-between text-xs">
                      <span className="font-medium text-slate-700 dark:text-slate-300">{label}</span>
                      <span className="text-slate-500 dark:text-slate-400">
                        {pct.toFixed(1)}%
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

        <div className="flex h-full flex-col rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Agent state</h2>
            <button
              type="button"
              onClick={() => navigate("/agent")}
              className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400"
            >
              Details
            </button>
          </div>
          {!snapshot ? (
            <div className="flex flex-1 items-center justify-center text-sm text-slate-500 dark:text-slate-400">
              Loading…
            </div>
          ) : (
            <div className="flex flex-1 flex-col gap-6">
              <div>
                <span
                  className={`inline-flex w-fit items-center gap-1.5 rounded-full border px-3 py-1.5 text-sm font-semibold ${badgeForAgentState(snapshot.status)}`}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  {labelForAgentState(snapshot.status)}
                </span>
                <div className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                  since {new Date(snapshot.entered_state_at).toLocaleTimeString()} · {formatElapsed(elapsedInState)}
                </div>
                {lastTransition && (
                  <div className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                    <span className="font-medium text-slate-600 dark:text-slate-300">Last transition:</span>{" "}
                    {lastTransition.from} → {lastTransition.to} — {lastTransition.reason}
                  </div>
                )}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                    Benign score
                  </div>
                  <div className="mt-0.5 text-lg font-semibold text-slate-900 dark:text-slate-100">
                    {snapshot.benign_sequence}
                  </div>
                  {snapshot.status !== "idle" && (
                    <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                      {snapshot.status === "alerted"
                        ? `need >${config?.decay_thresholds.alerted ?? "?"} + SOC confirm to decay`
                        : `need >${config?.decay_thresholds.under_attack ?? "?"} + SOC confirm to decay`}
                    </div>
                  )}
                </div>
                <div className="text-right">
                  <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
                    Last event IP
                  </div>
                  <div className="mt-0.5 truncate font-mono text-sm text-slate-900 dark:text-slate-100">
                    {snapshot.last_event_ip ?? "—"}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 10 Recent critical events */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
        <div className="mb-3 flex items-baseline justify-between">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">10 Recent critical events</h2>
            <button
              type="button"
              onClick={() => navigate("/alerts", { state: { tab: "all" } })}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
            >
              More Info and Actions
            </button>
          </div>
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

function formatElapsed(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return `${h}h ${mm}m`;
}
