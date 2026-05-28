import { createContext, useContext, useState } from "react";
import {
  getStreamGapSeconds,   setStreamGapSeconds,   clampStreamGapSeconds,
  getHistoryLimit,       setHistoryLimit,
  getStreamBucketMs,     setStreamBucketMs,
  getStreamPollSeconds,  setStreamPollSeconds,
  DEFAULT_STREAM_GAP_SECONDS, DEFAULT_HISTORY_LIMIT,
  DEFAULT_STREAM_BUCKET_MS,   DEFAULT_STREAM_POLL_SECONDS,
} from "../lib/settings";

interface SettingsCtx {
  streamGapSeconds: number;
  historyLimit: number;
  streamBucketMs: number;
  streamPollSeconds: number;
  updateStreamGap:    (v: number) => void;
  updateHistoryLimit: (v: number) => void;
  updateStreamBucket: (v: number) => void;
  updateStreamPoll:   (v: number) => void;
  resetAll: () => void;
}

const SettingsContext = createContext<SettingsCtx>({
  streamGapSeconds:  DEFAULT_STREAM_GAP_SECONDS,
  historyLimit:      DEFAULT_HISTORY_LIMIT,
  streamBucketMs:    DEFAULT_STREAM_BUCKET_MS,
  streamPollSeconds: DEFAULT_STREAM_POLL_SECONDS,
  updateStreamGap:    () => {},
  updateHistoryLimit: () => {},
  updateStreamBucket: () => {},
  updateStreamPoll:   () => {},
  resetAll: () => {},
});

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [streamGapSeconds,  setGap]   = useState(getStreamGapSeconds);
  const [historyLimit,      setLimit] = useState(getHistoryLimit);
  const [streamBucketMs,    setBucket]= useState(getStreamBucketMs);
  const [streamPollSeconds, setPoll]  = useState(getStreamPollSeconds);

  function updateStreamGap(v: number) {
    setGap(setStreamGapSeconds(clampStreamGapSeconds(v)));
  }
  function updateHistoryLimit(v: number) {
    setLimit(setHistoryLimit(v));
  }
  function updateStreamBucket(v: number) {
    setBucket(setStreamBucketMs(v));
  }
  function updateStreamPoll(v: number) {
    setPoll(setStreamPollSeconds(v));
  }
  function resetAll() {
    updateStreamGap(DEFAULT_STREAM_GAP_SECONDS);
    updateHistoryLimit(DEFAULT_HISTORY_LIMIT);
    updateStreamBucket(DEFAULT_STREAM_BUCKET_MS);
    updateStreamPoll(DEFAULT_STREAM_POLL_SECONDS);
  }

  return (
    <SettingsContext.Provider value={{
      streamGapSeconds, historyLimit, streamBucketMs, streamPollSeconds,
      updateStreamGap, updateHistoryLimit, updateStreamBucket, updateStreamPoll,
      resetAll,
    }}>
      {children}
    </SettingsContext.Provider>
  );
}

export function useSettings() {
  return useContext(SettingsContext);
}
