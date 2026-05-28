export default function ModelInsights() {
  return (
    <div className="mx-auto max-w-7xl">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Model insights</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Confusion matrix, ROC/PR curves, embedding projection.
        </p>
      </header>
      <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-12 text-center text-sm text-slate-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-400">
        Phase 3 — reads /metrics endpoint and renders saved training metrics.
      </div>
    </div>
  );
}