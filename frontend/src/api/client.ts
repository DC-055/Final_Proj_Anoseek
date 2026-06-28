/**
 * Central API client — every fetch goes through here.
 * Change API_URL once and everything follows.
 */

export const API_URL = "http://localhost:8001";

// ---------------- types

export type AgentSnapshot = {
  status: "idle" | "alerted" | "under_attack";
  entered_state_at: string;
  benign_sequence: number;
  soc_confirm: number;
  last_event_ip: string | null;
  totals: {
    events: number;
    flagged: number;
    blocked: number;
    blocked_ips: number;
  };
  transitions: Array<{
    from: string;
    to: string;
    reason: string;
    at: string;
  }>;
};

export type EventRecord = {
  event_id: number;
  timestamp: string;
  flow_id: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  severity: number;
  severity_label: string;
  confidence?: number;
  state_before: string;
  state_after?: string;
  action?: string;
  note?: string;
};

export type FlowResult = Record<string, any> & {
  predicted_class?: number;
  severity?: string;
  confidence?: number;
  is_anomaly?: boolean;
  action?: string;
  agent_state?: string;
  event_id?: number;
  note?: string;
};

export type ByIpResult = {
  src_ip: string;
  blocked: boolean;
  rate_limited: boolean;
  counts: { events: number; flagged: number; blocked: number };
  events: EventRecord[];
};

// ---------------- helpers

async function jsonOrThrow(res: Response) {
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const j = await res.json();
      msg = j?.detail ?? msg;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

// ---------------- endpoints

export async function ping() {
  return jsonOrThrow(await fetch(`${API_URL}/ping`));
}

export async function getAgentState(): Promise<AgentSnapshot> {
  return jsonOrThrow(await fetch(`${API_URL}/agent/state`));
}

export async function getAgentEvents(
  kind: "all" | "flagged" | "blocked" = "all",
  limit = 200,
): Promise<EventRecord[]> {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/events?kind=${kind}&limit=${limit}`),
  );
}

export async function getAgentByIp(srcIp: string): Promise<ByIpResult> {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/by-ip/${encodeURIComponent(srcIp)}`),
  );
}

export async function confirmFromSoc(confirmed: boolean) {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirmed }),
    }),
  );
}

export async function resetAgent() {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/reset`, { method: "POST" }),
  );
}

export async function getMetrics() {
  return jsonOrThrow(await fetch(`${API_URL}/metrics`));
}

export async function predictCsv(
  file: File,
  delaySeconds = 1,
  onResult?: (row: FlowResult) => void
): Promise<FlowResult[]> {
  const fd = new FormData();
  fd.append("file", file);

  const params = new URLSearchParams({
    delay_seconds: String(delaySeconds),
  });

  const res = await fetch(`${API_URL}/predict-csv?${params}`, {
    method: "POST",
    body: fd,
  });

  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  if (!res.body) throw new Error("No response body");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const collected: FlowResult[] = [];
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";   // keep incomplete last line

    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const payload = line.slice(6).trim();
      if (!payload) continue;
      try {
        const obj = JSON.parse(payload);
        if (obj.done || obj.aborted) break;
        collected.push(obj as FlowResult);
        onResult?.(obj as FlowResult);
      } catch {
        // ignore malformed lines
      }
    }
  }

  return collected;
}

export async function predictLive(flow: Record<string, unknown>) {
  const res = await fetch("http://localhost:8001/predict", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(flow),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Live prediction failed");
  }

  return res.json();
}

export async function blockIp(srcIp: string) {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/block-ip/${encodeURIComponent(srcIp)}`, {
      method: "POST",
    }),
  );
}

export async function unblockIp(srcIp: string) {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/unblock-ip/${encodeURIComponent(srcIp)}`, {
      method: "POST",
    }),
  );
}

export async function rateLimitIp(srcIp: string) {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/rate-limit-ip/${encodeURIComponent(srcIp)}`, {
      method: "POST",
    }),
  );
}

export async function unRateLimitIp(srcIp: string) {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/unrate-limit-ip/${encodeURIComponent(srcIp)}`, {
      method: "POST",
    }),
  );
}

export type AlertRecord = {
  alert_id: number;
  type?: "alert" | "confirm_request";
  event_id: number | null;
  src_ip: string | null;
  dst_ip: string | null;
  severity: number;
  severity_label: string;
  text: string;
  timestamp: string;
};

export type PolicyStatement = {
  State: string;
  Action_Required: string;
  Allowed: boolean;
};

export type Policy = {
  Version: string;
  Statement: PolicyStatement[];
};

export async function getPolicy(): Promise<Policy> {
  return jsonOrThrow(await fetch(`${API_URL}/agent/policy`));
}

export async function updatePolicy(policy: Policy): Promise<{ ok: boolean }> {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/policy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(policy),
    }),
  );
}

export async function getAlerts(since = 0): Promise<AlertRecord[]> {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/alerts?since=${since}`, { cache: "no-store" }),
  );
}
