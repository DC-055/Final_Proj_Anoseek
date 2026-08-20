import { useEffect, useRef } from "react";
import { getAlerts, type AlertRecord } from "../api/client";

export function useAlerts(
  onAlert: (alert: AlertRecord) => void,
  intervalMs = 2000,
) {
  const cursorRef = useRef<number>(0);
  const onAlertRef = useRef(onAlert);
  onAlertRef.current = onAlert;

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      try {
        const alerts = await getAlerts(cursorRef.current);
        if (cancelled || alerts.length === 0) return;
        cursorRef.current = alerts[alerts.length - 1].alert_id + 1;
        for (const a of alerts) onAlertRef.current(a);
      } catch {
        // backend may not be up yet — ignore
      }
    }

    tick();
    const id = setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [intervalMs]);

  function resetCursor() {
    cursorRef.current = 0;
  }

  return { resetCursor };
}
