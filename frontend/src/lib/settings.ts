const STREAM_GAP_KEY = "anoseek.streamGapSeconds";
const HISTORY_LIMIT_KEY = "anoseek.chatHistoryLimit";

export const DEFAULT_HISTORY_LIMIT = 30;
export const MIN_HISTORY_LIMIT = 1;
export const MAX_HISTORY_LIMIT = 30;

export function getHistoryLimit(): number {
  const raw = window.localStorage.getItem(HISTORY_LIMIT_KEY);
  if (raw === null) return DEFAULT_HISTORY_LIMIT;
  const n = Number(raw);
  if (!Number.isFinite(n)) return DEFAULT_HISTORY_LIMIT;
  return Math.min(MAX_HISTORY_LIMIT, Math.max(MIN_HISTORY_LIMIT, Math.round(n)));
}

export function setHistoryLimit(value: number): number {
  const next = Math.min(MAX_HISTORY_LIMIT, Math.max(MIN_HISTORY_LIMIT, Math.round(value)));
  window.localStorage.setItem(HISTORY_LIMIT_KEY, String(next));
  return next;
}

export const DEFAULT_STREAM_GAP_SECONDS = 1;
export const MIN_STREAM_GAP_SECONDS = 0;
export const MAX_STREAM_GAP_SECONDS = 60;

export function clampStreamGapSeconds(value: number) {
  if (!Number.isFinite(value)) return DEFAULT_STREAM_GAP_SECONDS;

  return Math.min(
    MAX_STREAM_GAP_SECONDS,
    Math.max(MIN_STREAM_GAP_SECONDS, value)
  );
}

export function getStreamGapSeconds() {
  const raw = window.localStorage.getItem(STREAM_GAP_KEY);

  if (raw === null) return DEFAULT_STREAM_GAP_SECONDS;

  return clampStreamGapSeconds(Number(raw));
}

export function setStreamGapSeconds(value: number) {
  const next = clampStreamGapSeconds(value);

  window.localStorage.setItem(STREAM_GAP_KEY, String(next));

  return next;
}