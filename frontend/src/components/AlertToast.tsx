import { useEffect, useState } from "react";
import type { AlertRecord } from "../api/client";

export type Toast = AlertRecord & { toastId: number };

const SEVERITY_STYLES: Record<number, { bar: string; bg: string; title: string }> = {
  0: { bar: "bg-emerald-500", bg: "bg-emerald-50 dark:bg-emerald-900/30", title: "text-emerald-800 dark:text-emerald-200" },
  1: { bar: "bg-blue-500",    bg: "bg-blue-50 dark:bg-blue-900/30",       title: "text-blue-800 dark:text-blue-200" },
  2: { bar: "bg-yellow-500",  bg: "bg-yellow-50 dark:bg-yellow-900/30",   title: "text-yellow-800 dark:text-yellow-200" },
  3: { bar: "bg-orange-500",  bg: "bg-orange-50 dark:bg-orange-900/30",   title: "text-orange-800 dark:text-orange-200" },
  4: { bar: "bg-red-600",     bg: "bg-red-50 dark:bg-red-900/30",         title: "text-red-800 dark:text-red-200" },
};

function SingleToast({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const [visible, setVisible] = useState(false);
  const style = SEVERITY_STYLES[toast.severity] ?? SEVERITY_STYLES[1];

  useEffect(() => {
    // mount → fade in
    const t1 = setTimeout(() => setVisible(true), 10);
    // auto-dismiss after 6 s
    const t2 = setTimeout(() => {
      setVisible(false);
      setTimeout(onDismiss, 300);
    }, 6000);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, [onDismiss]);

  return (
    <div
      className={`pointer-events-auto flex w-80 overflow-hidden rounded-xl shadow-lg border border-slate-200 dark:border-slate-700 transition-all duration-300 ${style.bg} ${visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"}`}
    >
      <div className={`w-1.5 shrink-0 ${style.bar}`} />
      <div className="flex flex-1 flex-col gap-0.5 px-3 py-2.5">
        <div className={`text-xs font-semibold uppercase tracking-wide ${style.title}`}>
          {toast.severity_label}
        </div>
        {toast.src_ip && (
          <div className="font-mono text-xs text-slate-700 dark:text-slate-300">
            {toast.src_ip}
            {toast.dst_ip ? ` → ${toast.dst_ip}` : ""}
          </div>
        )}
        <div className="text-xs text-slate-600 dark:text-slate-400">{toast.text}</div>
      </div>
      <button
        onClick={() => { setVisible(false); setTimeout(onDismiss, 300); }}
        className="self-start px-2 pt-2 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
        aria-label="Dismiss"
      >
        ✕
      </button>
    </div>
  );
}

export function AlertToastContainer({ toasts, onDismiss }: {
  toasts: Toast[];
  onDismiss: (id: number) => void;
}) {
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col gap-2 items-end">
      {toasts.map((t) => (
        <SingleToast key={t.toastId} toast={t} onDismiss={() => onDismiss(t.toastId)} />
      ))}
    </div>
  );
}
