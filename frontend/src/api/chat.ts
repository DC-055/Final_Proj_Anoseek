import { API_URL } from "./client";

export type ChatResponse = {
  ok: boolean;
  answer?: string;
  error?: string;
  debug?: { ip_detected?: string | null; events_included?: number };
};

export async function askChat(question: string): Promise<ChatResponse> {
  const res = await fetch(`${API_URL}/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  // We don't use jsonOrThrow here: even on 200 OK the backend
  // may return { ok: false, error: "..." } and we want that text.
  try {
    return await res.json();
  } catch {
    return { ok: false, error: `Request failed (${res.status})` };
  }
}