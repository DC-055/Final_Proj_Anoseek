/**
 * KpiCard — a small tile showing one headline number with a label.
 * Used for the row of cards at the top of the Overview page.
 *
 *   <KpiCard label="Flows analyzed" value={12_487} />
 *   <KpiCard label="Anomaly rate"   value="3.4%" tone="danger" />
 */
type Tone = "default" | "warning" | "danger" | "success";

const TONE_CLASSES: Record<Tone, string> = {
  default: "text-slate-900 dark:text-white",
  success: "text-green-700 dark:text-green-400",
  warning: "text-amber-700 dark:text-amber-400",
  danger:  "text-red-700 dark:text-red-400",
};

export default function KpiCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: Tone;
}) {
  return (
    <div className="animate-pop-in rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition-all duration-200 hover:-translate-y-1 hover:shadow-lg dark:border-slate-700 dark:bg-slate-800">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold ${TONE_CLASSES[tone]}`}>
        {value}
      </div>
      {hint && <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{hint}</div>}
    </div>
  );
}