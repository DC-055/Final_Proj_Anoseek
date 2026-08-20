
import { useEffect, useRef, useState } from "react";
import { Sun, Moon, Bell } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAgentState } from "../hooks/useAgentState";
import { badgeForAgentState, labelForAgentState } from "../lib/severity";
import { confirmFromSoc, resetAgent, getAgentConfig, type AgentConfig, type AlertRecord } from "../api/client";
import { useChatContext } from "../context/ChatContext";
import { useDarkModeContext } from "../context/DarkModeContext";
import { useAlerts } from "../hooks/useAlerts";

type AlertToast = AlertRecord & { toastId: number };

const SEVERITY_BAR: Record<number, string> = {
  0: "bg-emerald-500",
  1: "bg-blue-500",
  2: "bg-yellow-500",
  3: "bg-orange-500",
  4: "bg-red-600",
};

const SEVERITY_TITLE: Record<number, string> = {
  0: "text-emerald-700 dark:text-emerald-300",
  1: "text-blue-700 dark:text-blue-300",
  2: "text-yellow-700 dark:text-yellow-300",
  3: "text-orange-700 dark:text-orange-300",
  4: "text-red-700 dark:text-red-300",
};

let _id = 0;
let _confirmId = 0;

type ConfirmRequest = {
  id: number;
  status: string;
  timestamp: string;
  ip: string | null;
};

export default function Topbar() {
  const { snapshot, error } = useAgentState(1000);
  const [config, setConfig] = useState<AgentConfig | null>(null);
  const [busy, setBusy] = useState(false);

  // Static agent constants — fetched once on mount, not on the polling
  // cadence of /agent/state, since they never change at runtime.
  useEffect(() => {
    getAgentConfig().then(setConfig).catch(() => {});
  }, []);
  const { clear: clearChat } = useChatContext();
  const { dark, toggle } = useDarkModeContext();
  const navigate = useNavigate();

  // ── Notification bell state ──
  const [history, setHistory] = useState<AlertToast[]>([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const [activeToast, setActiveToast] = useState<AlertToast | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lastEventIpRef = useRef<string | null>(null);

  const { resetCursor } = useAlerts((alert) => {
    if (alert.src_ip) lastEventIpRef.current = alert.src_ip;
    const t: AlertToast = { ...alert, toastId: _id++ };
    setHistory((prev) => [...prev.slice(-4), t]);
    setUnread((prev) => prev + 1);
    setActiveToast(t);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setActiveToast(null), 6000);
  });

  // ── SOC confirmation popup — fires once the benign streak crosses the decay
  // threshold for the current state (alerted/under_attack) and SOC hasn't
  // confirmed yet. That's the only moment a confirmation is actually needed;
  // escalating up is automatic and doesn't need SOC sign-off. ──
  const [confirmPopup, setConfirmPopup] = useState(false);
  const [confirmHistory, setConfirmHistory] = useState<ConfirmRequest[]>([]);
  const [confirmUnread, setConfirmUnread] = useState(0);
  const [confirmOpen, setConfirmOpen] = useState(false);
  // The backend only tracks one global soc_confirm flag, so at most one queued
  // request can actually be acted on — this is the id of that one. Any earlier
  // requests become read-only history once a newer one supersedes them, so
  // confirming/denying can never apply to the "wrong" entry.
  const [pendingConfirmId, setPendingConfirmId] = useState<number | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const prevReadyRef = useRef(false);
  const confirmTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function pushConfirmRequest(status: string) {
    setConfirmPopup(true);
    if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
    confirmTimerRef.current = setTimeout(() => setConfirmPopup(false), 6000);
    const req: ConfirmRequest = {
      id: _confirmId++,
      status,
      timestamp: new Date().toISOString(),
      ip: snapshot?.last_event_ip ?? lastEventIpRef.current,
    };
    setConfirmHistory((prev) => [...prev.slice(-4), req]);
    setConfirmUnread((prev) => prev + 1);
    setPendingConfirmId(req.id);
  }

  // Fires once the benign streak crosses the decay threshold for the current
  // state but nothing can happen yet because SOC hasn't confirmed — without
  // this, the streak can sit well past the threshold forever with no prompt.
  useEffect(() => {
    const s = snapshot?.status;
    const bs = snapshot?.benign_sequence ?? 0;
    const threshold = s && s !== "idle" ? config?.decay_thresholds[s] : undefined;
    const ready = threshold !== undefined && bs > threshold && snapshot?.soc_confirm !== 1;
    if (ready && !prevReadyRef.current && s) pushConfirmRequest(s);
    prevReadyRef.current = ready;
  }, [snapshot?.status, snapshot?.benign_sequence, snapshot?.soc_confirm]);

  async function onConfirm(confirmed: boolean) {
    if (pendingConfirmId === null) return;
    const id = pendingConfirmId;
    setBusy(true);
    setConfirmError(null);
    try {
      await confirmFromSoc(confirmed);
      setConfirmHistory((prev) => prev.filter((r) => r.id !== id));
      setPendingConfirmId(null);
      setConfirmPopup(false);
      setConfirmUnread(0);
      if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
    } catch (e: any) {
      // Without this, a failed request left the popup silently stuck open —
      // the exception skipped every cleanup line above with no visible cause.
      setConfirmError(e?.message ?? "Failed to send confirmation");
    } finally {
      setBusy(false);
    }
  }

  async function onReset() {
    if (!confirm("Reset agent? This wipes all event history.")) return;
    setBusy(true);
    try {
      await resetAgent();
      clearChat();
      // Clear all frontend notification + SOC confirmation state
      setHistory([]);
      setUnread(0);
      setActiveToast(null);
      setConfirmHistory([]);
      setConfirmUnread(0);
      setConfirmPopup(false);
      setPendingConfirmId(null);
      setConfirmError(null);
      prevReadyRef.current = false;
      resetCursor();
    } finally {
      setBusy(false);
    }
  }

  const status = snapshot?.status;

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-slate-200 bg-white px-6 dark:border-slate-700 dark:bg-slate-800">
      <div className="flex items-center gap-3 text-sm text-slate-500">
        <span className="hidden md:inline">SOC dashboard</span>
        {error && <span className="text-red-600 dark:text-red-400">backend offline</span>}

        {/* ── SOC confirmation button + popup + dropdown ── */}
        <div className="relative">
          {confirmPopup && (
            <div className="absolute top-full left-0 z-50 mt-2 flex w-52 overflow-hidden rounded-xl border border-amber-300 bg-amber-50 shadow-lg dark:border-amber-700 dark:bg-amber-900/30">
              <div className="w-1 shrink-0 bg-amber-500" />
              <div className="flex flex-1 flex-col gap-1 px-2.5 py-2">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-300">
                  SOC Action Required
                </div>
                <div className="text-[10px] text-slate-600 dark:text-slate-400">
                  Benign streak ready to decay from{" "}
                  <span className="font-medium">{snapshot?.status?.replace("_", " ")}</span> — confirm to allow it.
                </div>
                {(snapshot?.last_event_ip ?? lastEventIpRef.current) && (
                  <div className="text-[10px] text-slate-500 dark:text-slate-500">
                    Last flagged IP before the benign streak:{" "}
                    <span className="font-mono text-slate-700 dark:text-slate-300">
                      {snapshot?.last_event_ip ?? lastEventIpRef.current}
                    </span>
                  </div>
                )}
                {confirmError && (
                  <div className="rounded-md bg-red-100 px-1.5 py-1 text-[10px] font-medium text-red-700 dark:bg-red-900/40 dark:text-red-300">
                    {confirmError} — try again.
                  </div>
                )}
                <div className="mt-0.5 flex gap-1.5">
                  <button
                    disabled={busy}
                    onClick={() => onConfirm(true)}
                    className="flex-1 rounded-md bg-amber-500 px-2 py-1 text-[10px] font-semibold text-white hover:bg-amber-400 disabled:opacity-50"
                  >
                    Confirm
                  </button>
                  <button
                    disabled={busy}
                    onClick={() => onConfirm(false)}
                    className="flex-1 rounded-md border border-amber-300 bg-white px-2 py-1 text-[10px] font-semibold text-amber-700 hover:bg-amber-50 disabled:opacity-50 dark:border-amber-700 dark:bg-transparent dark:text-amber-300 dark:hover:bg-amber-900/20"
                  >
                    Deny
                  </button>
                </div>
                <button
                  onClick={() => { setConfirmPopup(false); navigate("/alerts", { state: { tab: "all", selectedIp: snapshot?.last_event_ip ?? lastEventIpRef.current } }); }}
                  className="self-start text-[10px] font-medium text-amber-700 underline hover:text-amber-600 dark:text-amber-300"
                >
                  Review →
                </button>
              </div>
              <button
                onClick={() => setConfirmPopup(false)}
                className="self-start px-1.5 pt-1.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 text-xs"
                aria-label="Dismiss"
              >✕</button>
            </div>
          )}

          <button
            onClick={() => { setConfirmOpen((o) => !o); setConfirmUnread(0); setOpen(false); }}
            disabled={!snapshot}
            className="relative rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition-all duration-150 hover:-translate-y-0.5 hover:shadow-md hover:bg-slate-50 active:translate-y-0 active:scale-95 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
          >
            SOC confirmation
            {confirmUnread > 0 && (
              <span className="absolute -top-2 right-0 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-amber-500 px-1 text-[10px] font-bold text-white">
                {confirmUnread}
              </span>
            )}
          </button>

          {confirmOpen && (
            <div className="absolute left-0 top-full z-50 mt-2 w-80 rounded-xl border border-slate-200 bg-white shadow-xl dark:border-slate-700 dark:bg-slate-800">
              <div className="flex items-center justify-between border-b border-slate-100 px-4 py-2.5 dark:border-slate-700">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Confirmation Requests</span>
                {confirmHistory.length > 0 && (
                  <button
                    onClick={() => { setConfirmHistory([]); setConfirmUnread(0); }}
                    className="text-[10px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                  >
                    Clear
                  </button>
                )}
              </div>
              {confirmHistory.length === 0 ? (
                <div className="px-4 py-6 text-center text-xs text-slate-400">No requests yet</div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-700">
                  {[...confirmHistory].reverse().map((req) => {
                    const isPending = req.id === pendingConfirmId;
                    return (
                    <div key={req.id} className={`flex flex-col gap-2 px-3 py-2.5 ${isPending ? "" : "opacity-60"}`}>
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-amber-700 dark:text-amber-300">
                          Ready to decay →{" "}
                          {req.status === "under_attack" ? "Under Attack" : req.status === "alerted" ? "Alerted" : "Idle"}
                          {!isPending && (
                            <span className="ml-1.5 text-[10px] font-normal text-slate-400 dark:text-slate-500">
                              (superseded)
                            </span>
                          )}
                        </div>
                        {req.ip && (
                          <div className="truncate text-xs text-slate-600 dark:text-slate-400">
                            <span className="text-[10px] text-slate-400 dark:text-slate-500">
                              Last flagged IP before the benign streak:
                            </span>{" "}
                            <span className="font-mono">{req.ip}</span>
                          </div>
                        )}
                        <div className="font-mono text-[10px] text-slate-400">
                          {new Date(req.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                      <div className="flex gap-1.5">
                        {isPending && (
                          <>
                            <button
                              disabled={busy}
                              className="flex-1 rounded-md bg-amber-500 px-2 py-1 text-xs font-semibold text-white hover:bg-amber-400 disabled:opacity-50"
                              onClick={() => onConfirm(true)}
                            >
                              Confirm
                            </button>
                            <button
                              disabled={busy}
                              className="flex-1 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
                              onClick={() => onConfirm(false)}
                            >
                              Deny
                            </button>
                          </>
                        )}
                        <button
                          className="rounded-md bg-slate-100 px-2 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
                          onClick={() => { setConfirmOpen(false); navigate("/alerts", { state: { tab: "all", selectedIp: req.ip } }); }}
                        >
                          Review →
                        </button>
                      </div>
                    </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={toggle}
          aria-label="Toggle dark mode"
          className="group flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 transition-all duration-150 hover:-translate-y-0.5 hover:shadow-md active:scale-95 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
        >
          {dark
            ? <Sun className="h-3.5 w-3.5 transition-transform duration-300 group-hover:rotate-90" />
            : <Moon className="h-3.5 w-3.5 transition-transform duration-300 group-hover:-rotate-12" />}
          {dark ? "Light" : "Dark"}
        </button>

        {snapshot && (
          <div className="hidden gap-3 text-xs text-slate-500 dark:text-slate-400 md:flex">
            <span>events <b className="text-slate-900 dark:text-slate-100">{snapshot.totals.events}</b></span>
            <span>flagged <b className="text-slate-900 dark:text-slate-100">{snapshot.totals.flagged}</b></span>
            <span>blocked <b className="text-slate-900 dark:text-slate-100">{snapshot.totals.blocked}</b></span>
          </div>
        )}

        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${badgeForAgentState(status)}`}>
          <span className="h-1.5 w-1.5 rounded-full bg-current" />
          {labelForAgentState(status)}
        </span>

        {/* ── Notifications ── */}
        <div className="relative">

          {/* Notification toast popup */}
          {activeToast && (
            <div className="absolute top-full right-0 mt-2 flex w-72 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-800">
              <div className={`w-1.5 shrink-0 ${SEVERITY_BAR[activeToast.severity] ?? "bg-slate-400"}`} />
              <button
                className="flex flex-1 flex-col gap-0.5 px-3 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-700/50"
                onClick={() => {
                  setActiveToast(null);
                  navigate("/alerts", { state: { tab: "all", selectedIp: activeToast.src_ip } });
                }}
              >
                <div className={`text-xs font-semibold uppercase tracking-wide ${SEVERITY_TITLE[activeToast.severity] ?? ""}`}>
                  {activeToast.severity_label}
                </div>
                {activeToast.src_ip && (
                  <div className="font-mono text-xs text-slate-700 dark:text-slate-300">
                    {activeToast.src_ip}{activeToast.dst_ip ? ` → ${activeToast.dst_ip}` : ""}
                  </div>
                )}
                <div className="text-xs text-slate-500 dark:text-slate-400">{activeToast.text}</div>
              </button>
              <button
                onClick={() => setActiveToast(null)}
                className="self-start px-2 pt-2 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
                aria-label="Dismiss"
              >✕</button>
            </div>
          )}

          {/* Notifications button */}
          <button
            onClick={() => { setOpen((o) => !o); setUnread(0); setConfirmOpen(false); }}
            className="relative flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition-all duration-150 hover:-translate-y-0.5 hover:shadow-md active:scale-95 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200"
          >
            <Bell className="h-3.5 w-3.5" />
            Notifications
            {unread > 0 && (
              <span className="absolute -top-2 right-0 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-bold text-white">
                {unread > 99 ? "99+" : unread}
              </span>
            )}
          </button>

          {/* Dropdown */}
          {open && (
            <div className="absolute right-0 top-full z-50 mt-2 w-80 rounded-xl border border-slate-200 bg-white shadow-xl dark:border-slate-700 dark:bg-slate-800">
              <div className="border-b border-slate-100 px-4 py-2.5 dark:border-slate-700">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Recent Alerts</span>
              </div>
              {history.length === 0 ? (
                <div className="px-4 py-6 text-center text-xs text-slate-400">No alerts yet</div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-700">
                  {[...history].reverse().map((a) => (
                    <button
                      key={a.toastId}
                      className="flex w-full items-start gap-2 px-3 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-700/50"
                      onClick={() => {
                        setOpen(false);
                        navigate("/alerts", { state: { tab: "all", selectedIp: a.src_ip } });
                      }}
                    >
                      <div className={`mt-1 h-2 w-2 shrink-0 rounded-full ${SEVERITY_BAR[a.severity] ?? "bg-slate-400"}`} />
                      <div className="min-w-0 flex-1">
                        <div className={`text-xs font-semibold ${SEVERITY_TITLE[a.severity] ?? ""}`}>{a.severity_label}</div>
                        {a.src_ip && <div className="truncate font-mono text-xs text-slate-600 dark:text-slate-400">{a.src_ip}</div>}
                        <div className="line-clamp-2 text-xs text-slate-500 dark:text-slate-400">{a.text}</div>
                      </div>
                      <div className="shrink-0 font-mono text-[10px] text-slate-400">
                        {new Date(a.timestamp).toLocaleTimeString()}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        <button
          onClick={onReset}
          disabled={busy || !snapshot}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition-all duration-150 hover:-translate-y-0.5 hover:shadow-md hover:bg-slate-50 active:translate-y-0 active:scale-95 disabled:opacity-50 disabled:hover:translate-y-0 disabled:hover:shadow-none dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
        >
          Reset
        </button>
      </div>
    </header>
  );
}
