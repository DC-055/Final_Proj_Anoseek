/**
 * Alerts page.
 *
 * Wide screens (>=1024px): events table left, drill-down panel right (column).
 * Narrow screens (<1024px): drill-down becomes an overlay drawer from the right.
 */
import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import {
  blockIp,
  unblockIp,
  rateLimitIp,
  unRateLimitIp,
  getAgentByIp,
  type ByIpResult,
  type EventRecord,
} from "../api/client";
import { useEvents } from "../hooks/useEvents";
import { badgeForAction } from "../lib/severity";
import SeverityBadge from "../components/SeverityBadge";

type TabKind = "all" | "flagged" | "blocked";

export default function Alerts() {
  const location = useLocation();
  const [tab, setTab] = useState<TabKind>((location.state as any)?.tab ?? "flagged");
  const [selectedIp, setSelectedIp] = useState<string | null>((location.state as any)?.selectedIp ?? null);
  const [query, setQuery] = useState("");
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);

  // Re-apply navigation state when navigating to this page while it's already mounted
  useEffect(() => {
    const state = location.state as any;
    if (state?.tab) setTab(state.tab);
    if (state?.selectedIp !== undefined) setSelectedIp(state.selectedIp);
  }, [location.state]);

  const { events } = useEvents(tab, 200, 4000);
  const allCounts  = useTabCounts();

  const sortedEvents = useMemo(() => {
    const reversed = [...events].reverse();
    const q = query.trim().toLowerCase();
    return reversed.filter((e) => {
      if (onlyAnomalies && e.severity === 0) return false;
      if (!q) return true;
      const hay = [
        e.src_ip ?? "",
        e.dst_ip ?? "",
        e.severity_label,
        e.action ?? "",
        e.note ?? "",
        new Date(e.timestamp).toLocaleTimeString(),
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [events, query, onlyAnomalies]);

  // Lock body scroll while drawer is open on narrow screens
  useEffect(() => {
    if (selectedIp && window.innerWidth < 1024) {
      document.body.style.overflow = "hidden";
      return () => { document.body.style.overflow = ""; };
    }
  }, [selectedIp]);

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Flagged and blocked events. Click a row to drill into that IP.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_22rem]">
        {/* ───── Events table (always visible) ───── */}
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 pt-3 pb-2 dark:border-slate-700">
            <div className="flex gap-1">
              <Tab label="All"     count={allCounts.all}     active={tab === "all"}     onClick={() => setTab("all")} />
              <Tab label="Flagged" count={allCounts.flagged} active={tab === "flagged"} onClick={() => setTab("flagged")} />
              <Tab label="Blocked" count={allCounts.blocked} active={tab === "blocked"} onClick={() => setTab("blocked")} />
            </div>
            <div className="flex items-center gap-3 pb-1">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="IP, severity, action…"
                className="w-52 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
              />
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-slate-600 dark:text-slate-400">
                <input
                  type="checkbox"
                  checked={onlyAnomalies}
                  onChange={(e) => setOnlyAnomalies(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-slate-300"
                />
                Anomalies only
              </label>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-700/50">
                <tr>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Source IP</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                  <th className="px-3 py-2 font-medium">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                {sortedEvents.length === 0 && (
                  <tr>
                    <td className="px-3 py-8 text-center text-sm text-slate-500" colSpan={5}>
                      No {tab === "all" ? "" : tab + " "}events yet. Upload a CSV in the Modes page.
                    </td>
                  </tr>
                )}
                {sortedEvents.map((e) => {
                  const isSelected = e.src_ip === selectedIp;
                  return (
                    <tr
                      key={e.event_id}
                      onClick={() => e.src_ip && setSelectedIp(e.src_ip)}
                      className={`cursor-pointer ${isSelected ? "bg-blue-50/60 dark:bg-blue-900/20" : "hover:bg-slate-50 dark:hover:bg-slate-700/40"}`}
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-600 dark:text-slate-400">
                        {new Date(e.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-700 dark:text-slate-300">
                        {e.src_ip ?? "—"}
                      </td>
                      <td className="px-3 py-2">
                        <SeverityBadge label={e.severity_label} />
                      </td>
                      <td className="px-3 py-2">
                        <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${badgeForAction(e.action)}`}>
                          {e.action}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-slate-600 dark:text-slate-400">
                        {typeof e.confidence === "number" ? e.confidence.toFixed(3) : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* ───── Drill-down: WIDE — column, NARROW — drawer ───── */}

        {/* On wide screens this column sits next to the table */}
        <div className="hidden lg:block">
          <DrillDownPanel srcIp={selectedIp} onClose={() => setSelectedIp(null)} />
        </div>

        {/* On narrow screens, drawer that slides over content */}
        {selectedIp && (
          <div className="lg:hidden">
            {/* dim backdrop */}
            <div
              onClick={() => setSelectedIp(null)}
              className="fixed inset-0 z-40 bg-slate-900/40 backdrop-blur-sm"
            />
            {/* sliding panel */}
            <div className="fixed inset-y-0 right-0 z-50 w-full max-w-sm overflow-y-auto bg-white shadow-2xl dark:bg-slate-800">
              <div className="p-4">
                <DrillDownPanel srcIp={selectedIp} onClose={() => setSelectedIp(null)} bare />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────── helpers */

function Tab({
  label, count, active, onClick,
}: { label: string; count: number; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-sm transition-colors ${
        active
          ? "border-b-2 border-slate-900 font-medium text-slate-900 dark:border-slate-100 dark:text-slate-100"
          : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
      }`}
      style={{ marginBottom: "-1px" }}
    >
      {label}{" "}
      <span className={active ? "text-slate-500 dark:text-slate-400" : "text-slate-400 dark:text-slate-500"}>({count})</span>
    </button>
  );
}

function useTabCounts() {
  const all     = useEvents("all", 1000, 5000).events;
  const flagged = useEvents("flagged", 1000, 5000).events;
  const blocked = useEvents("blocked", 1000, 5000).events;
  return {
    all: all.length,
    flagged: flagged.length,
    blocked: blocked.length,
  };
}

/**
 * `bare`: skip the outer card border (used when wrapped in a drawer that
 *         already has its own white background).
 */
function DrillDownPanel({
  srcIp,
  onClose,
  bare = false,
}: {
  srcIp: string | null;
  onClose: () => void;
  bare?: boolean;
}) {
  const [data, setData] = useState<ByIpResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!srcIp) {
      setData(null);
      return;
    }

    let cancelled = false;
    async function tick() {
      try {
        const d = await getAgentByIp(srcIp!);
        if (!cancelled) {
          setData(d);
          setError(null);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message ?? "fetch failed");
      }
    }

    tick();
    const id = setInterval(tick, 4000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [srcIp]);

  // Empty state — only relevant for the wide-screen column variant
  if (!srcIp) {
    if (bare) return null;  // drawer just closes, never shows empty state
    return (
      <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500 dark:border-slate-600 dark:bg-slate-800/50 dark:text-slate-400">
        Click a row to drill into that source IP.
      </div>
    );
  }

  async function onBlock() {
    if (!srcIp) return;
    setBusy(true);
    try {
      await blockIp(srcIp);
      const d = await getAgentByIp(srcIp);
      setData(d);
    } catch (e: any) {
      setError(e?.message ?? "block failed");
    } finally {
      setBusy(false);
    }
  }

  async function onUnblock() {
    if (!srcIp) return;
    setBusy(true);
    try {
      await unblockIp(srcIp);
      const d = await getAgentByIp(srcIp);
      setData(d);
    } catch (e: any) {
      setError(e?.message ?? "unblock failed");
    } finally {
      setBusy(false);
    }
  }

  async function onRateLimit() {
    if (!srcIp) return;
    setBusy(true);
    try {
      await rateLimitIp(srcIp);
      const d = await getAgentByIp(srcIp);
      setData(d);
    } catch (e: any) {
      setError(e?.message ?? "rate limit failed");
    } finally {
      setBusy(false);
    }
  }

  async function onUnRateLimit() {
    if (!srcIp) return;
    setBusy(true);
    try {
      await unRateLimitIp(srcIp);
      const d = await getAgentByIp(srcIp);
      setData(d);
    } catch (e: any) {
      setError(e?.message ?? "un-rate-limit failed");
    } finally {
      setBusy(false);
    }
  }

  const events: EventRecord[] = data?.events ?? [];
  const reversed = [...events].reverse();
  // These names match GET /agent/by-ip/{src_ip} from the backend.
  const isBlocked = data?.blocked ?? false;
  const isRateLimited = data?.rate_limited ?? false;

  const wrapperCls = bare
    ? ""
    : "rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800";

  return (
    <div className={wrapperCls}>
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">Source IP</div>
          <div className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">{srcIp}</div>
        </div>
        <button
          onClick={onClose}
          aria-label="Close"
          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-700 dark:hover:text-slate-200"
        >
          ✕
        </button>
      </div>

      <div className="mb-4 flex gap-2">
        {isBlocked ? (
          <button
            onClick={onUnblock}
            disabled={busy}
            className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
          >
            Unblock
          </button>
        ) : (
          <button
            onClick={onBlock}
            disabled={busy}
            className="flex-1 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-50"
          >
            Block IP
          </button>
        )}
        {isRateLimited ? (
          <button
            onClick={onUnRateLimit}
            disabled={busy}
            className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
          >
            Un-rate-limit
          </button>
        ) : (
          <button
            onClick={onRateLimit}
            disabled={busy}
            className="flex-1 rounded-lg bg-amber-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-400 disabled:opacity-50"
          >
            Rate Limit
          </button>
        )}
        <button
          onClick={onClose}
          className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
        >
          Dismiss
        </button>
      </div>

      {error && (
        <div className="mb-3 rounded-lg border border-red-200 bg-red-50 px-2 py-1.5 text-xs text-red-800 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300">
          {error}
        </div>
      )}

      {data && (
        <div className="mb-4 grid grid-cols-3 gap-1.5">
          <CounterTile label="Events"  value={data.counts.events} />
          <CounterTile label="Flagged" value={data.counts.flagged} tone="warning" />
          <CounterTile label="Blocked" value={data.counts.blocked} tone="danger" />
        </div>
      )}

      {isBlocked && (
        <div className="mb-3 rounded-lg bg-red-50 px-2 py-1.5 text-xs font-medium text-red-800 dark:bg-red-900/30 dark:text-red-300">
          On manual blocklist. New flows from this IP will be dropped.
        </div>
      )}
      {isRateLimited && (
        <div className="mb-3 rounded-lg bg-amber-50 px-2 py-1.5 text-xs font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-300">
          On manual rate-limit list. New flows from this IP will be throttled.
        </div>
      )}

      <div className="mb-2 text-xs font-semibold text-slate-700 dark:text-slate-300">Timeline</div>
      {!data ? (
        <div className="text-xs text-slate-500 dark:text-slate-400">Loading…</div>
      ) : reversed.length === 0 ? (
        <div className="text-xs text-slate-500 dark:text-slate-400">No events recorded.</div>
      ) : (
        <div className="max-h-96 space-y-1 overflow-y-auto">
          {reversed.map((e) => {
            const isCritical = e.action === "block";
            return (
              <div
                key={e.event_id}
                className={`flex flex-col gap-0.5 rounded-md p-2 text-xs ${
                  isCritical ? "bg-red-50 dark:bg-red-900/30" : "bg-slate-50 dark:bg-slate-700/50"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-slate-600 dark:text-slate-400">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </span>
                  <span className={`inline-flex items-center rounded-full border px-1.5 py-0 text-[10px] font-medium ${badgeForAction(e.action)}`}>
                    {e.action}
                  </span>
                </div>
                <div className="text-slate-700 dark:text-slate-300">{e.severity_label}</div>
                {e.note && <div className="text-slate-500 dark:text-slate-400">{e.note}</div>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function CounterTile({
  label, value, tone = "default",
}: { label: string; value: number; tone?: "default" | "warning" | "danger" }) {
  const toneCls = {
    default: "bg-slate-100 text-slate-900 dark:bg-slate-700 dark:text-slate-100",
    warning: "bg-yellow-50 text-yellow-900 dark:bg-yellow-900/20 dark:text-yellow-300",
    danger:  "bg-red-50 text-red-900 dark:bg-red-900/20 dark:text-red-300",
  }[tone];
  return (
    <div className={`rounded-lg p-2 ${toneCls}`}>
      <div className="text-[10px] uppercase tracking-wide opacity-70">{label}</div>
      <div className="text-sm font-semibold">{value}</div>
    </div>
  );
}
