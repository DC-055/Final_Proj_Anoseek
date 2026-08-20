/**
 * AgentState page.
 *
 * Top:    state machine diagram (3 nodes, current state highlighted)
 * Middle: counter tiles (benign score, SOC confirm, time in state)
 * Bottom: recent transitions timeline
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAgentState } from "../hooks/useAgentState";
import { badgeForAgentState, labelForAgentState } from "../lib/severity";
import { getAgentConfig, type AgentConfig } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";

type StateKey = "idle" | "alerted" | "under_attack";

export default function AgentState() {
  const { snapshot, error } = useAgentState(1000);
  const navigate = useNavigate();

  // Static agent constants (decay thresholds) — fetched once, same source as Topbar.
  const [config, setConfig] = useState<AgentConfig | null>(null);
  useEffect(() => {
    getAgentConfig().then(setConfig).catch(() => {});
  }, []);

  // Live "time in current state" ticker — updates every second
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  if (error) {
    return (
      <div className="mx-auto max-w-7xl">
        <header className="mb-6">
          <h1 className="text-2xl font-semibold tracking-tight">Agent state</h1>
        </header>
        <div className="rounded-2xl border border-red-200 bg-red-50 p-6 text-sm text-red-800 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300">
          Backend offline — {error}
        </div>
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="mx-auto max-w-7xl">
        <header className="mb-6">
          <h1 className="text-2xl font-semibold tracking-tight">Agent state</h1>
        </header>
        <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center text-sm text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
          Loading…
        </div>
      </div>
    );
  }

  const status = snapshot.status as StateKey;
  const enteredAt = new Date(snapshot.entered_state_at).getTime();
  const elapsedSeconds = Math.max(0, Math.floor((now - enteredAt) / 1000));

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Agent state</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Current state, counters, and recent transitions. Refreshes every 2 seconds.
        </p>
      </header>

      {/* ─── Diagram + Counters ─── */}
      <div className="mb-3 flex flex-col gap-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm md:flex-row dark:border-slate-700 dark:bg-slate-800">
        {/* Diagram */}
        <div className="min-w-0 flex-1 flex items-center justify-center">
          <StateMachineDiagram status={status} />
        </div>

        {/* Counters sidebar */}
        <div className="flex shrink-0 flex-col gap-3 md:w-56">
          <div className="flex flex-col gap-1">
            <span
              className={`inline-flex w-fit items-center gap-1.5 rounded-full border px-3 py-1.5 text-sm font-semibold ${badgeForAgentState(status)}`}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-current" />
              {labelForAgentState(status)}
            </span>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              since {new Date(snapshot.entered_state_at).toLocaleString()}
            </span>
          </div>

          <CounterTile
            label="Benign score"
            value={snapshot.benign_sequence}
            hint={
              status === "alerted"
                ? `need >${config?.decay_thresholds.alerted ?? "?"} + SOC confirm to decay`
                : status === "under_attack"
                ? `need >${config?.decay_thresholds.under_attack ?? "?"} + SOC confirm to decay`
                : "—"
            }
          />
          <CounterTile
            label="In current state"
            value={formatElapsed(elapsedSeconds)}
            hint={`since ${new Date(snapshot.entered_state_at).toLocaleTimeString()}`}
          />
        </div>
      </div>

      {/* ─── Transitions timeline ─── */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Recent transitions</h2>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {snapshot.transitions.length} recent
          </span>
        </div>

        {snapshot.transitions.length === 0 ? (
          <div className="py-8 text-center text-sm text-slate-500 dark:text-slate-400">
            No transitions yet. Upload an attack-heavy CSV to see state changes.
          </div>
        ) : (
          <div className="space-y-2">
            {[...snapshot.transitions].reverse().map((t, idx) => {
              const clickable = Boolean(t.src_ip);
              const Wrapper = clickable ? "button" : "div";
              return (
                <Wrapper
                  key={idx}
                  onClick={
                    clickable
                      ? () => navigate("/alerts", { state: { tab: "all", selectedIp: t.src_ip } })
                      : undefined
                  }
                  className={`flex w-full flex-wrap items-center gap-2 rounded-lg bg-slate-50 px-3 py-2 text-left text-sm dark:bg-slate-700/50 ${
                    clickable ? "cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-700" : ""
                  }`}
                >
                  <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                    {new Date(t.at).toLocaleTimeString()}
                  </span>
                  <StatePill state={t.from} />
                  <span className="text-slate-400 dark:text-slate-500">→</span>
                  <StatePill state={t.to} />
                  <span className="text-xs text-slate-600 dark:text-slate-300">{t.reason}</span>
                  {t.src_ip && (
                    <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                      {t.src_ip}
                    </span>
                  )}
                  {t.severity_label && <SeverityBadge label={t.severity_label} />}
                </Wrapper>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────── helpers */

function formatElapsed(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return `${h}h ${mm}m`;
}

function StatePill({ state }: { state: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${badgeForAgentState(
        state,
      )}`}
    >
      {labelForAgentState(state)}
    </span>
  );
}

function CounterTile({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "success" | "warning" | "danger";
}) {
  const toneCls = {
    default: "text-slate-900 dark:text-slate-100",
    success: "text-green-700 dark:text-green-400",
    warning: "text-amber-700 dark:text-amber-400",
    danger:  "text-red-700 dark:text-red-400",
  }[tone];
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold ${toneCls}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{hint}</div>}
    </div>
  );
}

/* ─────────────────────────────────────────────── state machine SVG */

function StateMachineDiagram({ status }: { status: StateKey }) {
  // Node colors: light fill + darker stroke when active
  const nodeStyle = (key: StateKey) => {
    const active = key === status;
    const baseStroke = active ? 2 : 0.5;
    switch (key) {
      case "idle":
        return {
          fill: "#EAF3DE",
          stroke: "#3B6D11",
          strokeWidth: baseStroke,
          textFill: "#173404",
          subFill: "#3B6D11",
        };
      case "alerted":
        return {
          fill: "#FAEEDA",
          stroke: "#BA7517",
          strokeWidth: baseStroke,
          textFill: "#412402",
          subFill: "#854F0B",
        };
      case "under_attack":
        return {
          fill: "#FCEBEB",
          stroke: "#A32D2D",
          strokeWidth: baseStroke,
          textFill: "#501313",
          subFill: "#A32D2D",
        };
    }
  };

  const idle = nodeStyle("idle");
  const alerted = nodeStyle("alerted");
  const ua = nodeStyle("under_attack");

  return (
    <svg
      viewBox="0 0 600 200"
      style={{ width: "100%", maxWidth: "1100px", height: "auto", display: "block" }}
    >
      <defs>
        <marker
          id="arr"
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerWidth="6"
          markerHeight="6"
          orient="auto"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
        </marker>
      </defs>

      {/* Forward arrows: IDLE -> ALERTED -> UNDER_ATTACK */}
      <line x1="155" y1="100" x2="245" y2="100" stroke="#94a3b8" strokeWidth="1" markerEnd="url(#arr)" />
      <text x="200" y="92" fontSize="10" textAnchor="middle" fill="#64748b">repeated flags</text>
      <text x="200" y="115" fontSize="10" textAnchor="middle" fill="#64748b">/ severity 3-4</text>

      <line x1="355" y1="100" x2="455" y2="100" stroke="#94a3b8" strokeWidth="1" markerEnd="url(#arr)" />
      <text x="405" y="92" fontSize="10" textAnchor="middle" fill="#64748b">3+ flags during alert</text>

      {/* Backward arc: ALERTED -> IDLE */}
      <path d="M 245 130 Q 200 165 155 130" stroke="#94a3b8" strokeWidth="1" fill="none" markerEnd="url(#arr)" />
      <text x="200" y="180" fontSize="10" textAnchor="middle" fill="#64748b">benign + SOC confirm</text>

      {/* Backward arc: UNDER_ATTACK -> ALERTED */}
      <path d="M 455 130 Q 400 165 355 130" stroke="#94a3b8" strokeWidth="1" fill="none" markerEnd="url(#arr)" />
      <text x="400" y="180" fontSize="10" textAnchor="middle" fill="#64748b">benign + SOC confirm</text>

      {/* IDLE node */}
      <g>
        <rect
          x="55" y="75" width="100" height="50" rx="8"
          fill={idle.fill} stroke={idle.stroke} strokeWidth={idle.strokeWidth}
        />
        <text x="105" y="100" fontSize="14" fontWeight="500" textAnchor="middle" fill={idle.textFill}>
          IDLE
        </text>
        <text x="105" y="115" fontSize="10" textAnchor="middle" fill={idle.subFill}>
          normal traffic
        </text>
      </g>

      {/* ALERTED node */}
      <g>
        <rect
          x="245" y="75" width="110" height="50" rx="8"
          fill={alerted.fill} stroke={alerted.stroke} strokeWidth={alerted.strokeWidth}
        />
        <text x="300" y="100" fontSize="14" fontWeight="500" textAnchor="middle" fill={alerted.textFill}>
          ALERTED
        </text>
        <text x="300" y="115" fontSize="10" textAnchor="middle" fill={alerted.subFill}>
          SOC notified
        </text>
      </g>

      {/* UNDER_ATTACK node */}
      <g>
        <rect
          x="455" y="75" width="110" height="50" rx="8"
          fill={ua.fill} stroke={ua.stroke} strokeWidth={ua.strokeWidth}
        />
        <text x="510" y="100" fontSize="14" fontWeight="500" textAnchor="middle" fill={ua.textFill}>
          UNDER ATTACK
        </text>
        <text x="510" y="115" fontSize="10" textAnchor="middle" fill={ua.subFill}>
          active blocking
        </text>
      </g>

      {/* "Current" pill below the active node */}
      {status === "idle" && (
        <text x="105" y="148" fontSize="10" fontWeight="500" textAnchor="middle" fill="#3B6D11">
          ← current
        </text>
      )}
      {status === "alerted" && (
        <text x="300" y="148" fontSize="10" fontWeight="500" textAnchor="middle" fill="#BA7517">
          ← current
        </text>
      )}
      {status === "under_attack" && (
        <text x="500" y="148" fontSize="10" fontWeight="500" textAnchor="middle" fill="#A32D2D">
          ← current
        </text>
      )}
    </svg>
  );
}