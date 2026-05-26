
import { useState } from "react";
import { useAgentState } from "../hooks/useAgentState";
import { badgeForAgentState, labelForAgentState } from "../lib/severity";
import { confirmFromSoc, resetAgent } from "../api/client";
import { useChatContext } from "../context/ChatContext";

export default function Topbar() {
  const { snapshot, error } = useAgentState(3000);
  const [busy, setBusy] = useState(false);
  const { clear: clearChat } = useChatContext();

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
    <header className="flex h-14 items-center justify-between border-b border-slate-200 bg-white px-6">
      <div className="flex items-center gap-3 text-sm text-slate-500">
        <span className="hidden md:inline">SOC dashboard</span>
        {error && <span className="text-red-600">backend offline</span>}
      </div>

      <div className="flex items-center gap-3">
        {snapshot && (
          <div className="hidden gap-3 text-xs text-slate-500 md:flex">
            <span>events <b className="text-slate-900">{snapshot.totals.events}</b></span>
            <span>flagged <b className="text-slate-900">{snapshot.totals.flagged}</b></span>
            <span>blocked <b className="text-slate-900">{snapshot.totals.blocked}</b></span>
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
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
        >
          SOC confirm
        </button>
        <button
          onClick={onReset}
          disabled={busy || !snapshot}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
        >
          Reset
        </button>
      </div>
    </header>
  );
}