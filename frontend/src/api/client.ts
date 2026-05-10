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
  manually_blocked?: boolean;
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

export async function confirmFromSoc() {
  return jsonOrThrow(
    await fetch(`${API_URL}/agent/confirm`, { method: "POST" }),
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
  delaySeconds = 1
): Promise<FlowResult[]> {
  const fd = new FormData();
  fd.append("file", file);

  const params = new URLSearchParams({
    delay_seconds: String(delaySeconds),
  });

  return jsonOrThrow(
    await fetch(`${API_URL}/predict-csv?${params}`, {
      method: "POST",
      body: fd,
    })
  );
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