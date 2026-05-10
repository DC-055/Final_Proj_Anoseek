export default function LiveStream() {
  return (
    <div className="mx-auto max-w-7xl">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Live stream</h1>
        <p className="mt-1 text-sm text-slate-600">
          Simulated real-time flow stream. Requires backend WebSocket support.
        </p>
      </header>
      <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-12 text-center text-sm text-slate-500">
        Coming later — needs backend stream implemented first.
      </div>
    </div>
  );
}