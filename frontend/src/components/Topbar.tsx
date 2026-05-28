
import { useState } from "react";
import { Sun, Moon } from "lucide-react";
import { useAgentState } from "../hooks/useAgentState";
import { badgeForAgentState, labelForAgentState } from "../lib/severity";
import { confirmFromSoc, resetAgent } from "../api/client";
import { useChatContext } from "../context/ChatContext";
import { useDarkModeContext } from "../context/DarkModeContext";

export default function Topbar() {
  const { snapshot, error } = useAgentState(3000);
  const [busy, setBusy] = useState(false);
  const { clear: clearChat } = useChatContext();
  const { dark, toggle } = useDarkModeContext();

  async function onConfirm() {
    setBusy(true);
    try { await confirmFromSoc(); } finally { setBusy(false); }
  }

  async function onReset() {
    if (!confirm("Reset agent? This wipes all event history.")) return;
    setBusy(true);
    try {
      await resetAgent();
      clearChat();
    } finally { setBusy(false); }
  }

  const status = snapshot?.status;

  return (
    <header className="flex h-14 items-center justify-between border-b border-slate-200 bg-white px-6 dark:border-slate-700 dark:bg-slate-800">
      <div className="flex items-center gap-3 text-sm text-slate-500">
        <span className="hidden md:inline">SOC dashboard</span>
        {error && <span className="text-red-600 dark:text-red-400">backend offline</span>}
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

        <span
          className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${badgeForAgentState(status)}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-current" />
          {labelForAgentState(status)}
        </span>

        <button
          onClick={onConfirm}
          disabled={busy || !snapshot}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition-all duration-150 hover:-translate-y-0.5 hover:shadow-md hover:bg-slate-50 active:translate-y-0 active:scale-95 disabled:opacity-50 disabled:hover:translate-y-0 disabled:hover:shadow-none dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
        >
          SOC confirm
        </button>
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