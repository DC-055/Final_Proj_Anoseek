import { useEffect, useState } from "react";
import { getAgentState, type AgentSnapshot } from "../api/client";

/**
 * Polls the backend's /agent/state every `intervalMs` and returns the latest snapshot.
 * Used by the topbar (live state pill) and any page that wants live totals.
 */
export function useAgentState(intervalMs = 3000) {
  const [snapshot, setSnapshot] = useState<AgentSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      try {
        const s = await getAgentState();
        if (!cancelled) {
          setSnapshot(s);
          setError(null);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message ?? "fetch failed");
      }
    }

    tick();                                       // first call immediately
    const id = setInterval(tick, intervalMs);     // then every intervalMs
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [intervalMs]);

  return { snapshot, error };
}