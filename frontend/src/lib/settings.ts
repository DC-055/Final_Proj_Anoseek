const STREAM_GAP_KEY    = "anoseek.streamGapSeconds";
const HISTORY_LIMIT_KEY = "anoseek.chatHistoryLimit";
const STREAM_BUCKET_KEY = "anoseek.streamBucketMs";
const STREAM_POLL_KEY   = "anoseek.streamPollSeconds";

export const DEFAULT_STREAM_POLL_SECONDS = 2;
export const MIN_STREAM_POLL_SECONDS     = 2;
export const MAX_STREAM_POLL_SECONDS     = 60;

export function getStreamPollSeconds(): number {
  const raw = window.localStorage.getItem(STREAM_POLL_KEY);
  if (raw === null) return DEFAULT_STREAM_POLL_SECONDS;
  const n = Number(raw);
  if (!Number.isFinite(n)) return DEFAULT_STREAM_POLL_SECONDS;
  return Math.min(MAX_STREAM_POLL_SECONDS, Math.max(MIN_STREAM_POLL_SECONDS, Math.round(n)));
}

export function setStreamPollSeconds(value: number): number {
  const next = Math.min(MAX_STREAM_POLL_SECONDS, Math.max(MIN_STREAM_POLL_SECONDS, Math.round(value)));
  window.localStorage.setItem(STREAM_POLL_KEY, String(next));
  return next;
}

export const BUCKET_OPTIONS: { label: string; ms: number }[] = [
  { label: "Auto",    ms: 0 },
  { label: "10 sec",  ms: 10_000 },
  { label: "30 sec",  ms: 30_000 },
  { label: "1 min",   ms: 60_000 },
  { label: "5 min",   ms: 5 * 60_000 },
  { label: "15 min",  ms: 15 * 60_000 },
  { label: "30 min",  ms: 30 * 60_000 },
  { label: "1 hour",  ms: 60 * 60_000 },
  { label: "3 hours", ms: 3 * 60 * 60_000 },
];

export const DEFAULT_STREAM_BUCKET_MS = 0;

export function getStreamBucketMs(): number {
  const raw = window.localStorage.getItem(STREAM_BUCKET_KEY);
  if (raw === null) return DEFAULT_STREAM_BUCKET_MS;
  const n = Number(raw);
  return Number.isFinite(n) ? n : DEFAULT_STREAM_BUCKET_MS;
}

export function setStreamBucketMs(value: number): number {
  window.localStorage.setItem(STREAM_BUCKET_KEY, String(value));
  return value;
}

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