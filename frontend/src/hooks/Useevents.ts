import { useEffect, useState } from "react";
import { getAgentEvents, type EventRecord } from "../api/client";

/**
 * Polls the backend's /agent/events?kind=... every `intervalMs`.
 * Used by the Overview "Recent events" table and (later) the Alerts page.
 */
export function useEvents(
  kind: "all" | "flagged" | "blocked" = "all",
  limit = 100,
  intervalMs = 2000,
) {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      try {
        const e = await getAgentEvents(kind, limit);
        if (!cancelled) {
          setEvents(e);
          setError(null);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message ?? "fetch failed");
      }
    }

    tick();
    const id = setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [kind, limit, intervalMs]);

  return { events, error };
}