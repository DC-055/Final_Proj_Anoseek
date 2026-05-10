const STREAM_GAP_KEY = "anoseek.streamGapSeconds";

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