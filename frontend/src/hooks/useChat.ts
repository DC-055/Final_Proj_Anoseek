import { useState } from "react";
import { askChat } from "../api/chat";
import { getHistoryLimit } from "../lib/settings";

export type ChatMessage = {
  role: "user" | "assistant" | "error";
  text: string;
  timestamp: string;
};

/**
 * Simple chat state hook — keeps a local message history client-side
 * and calls the backend per question (no conversation history sent yet).
 */
export function useChat() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [sessionStartedAt, setSessionStartedAt] = useState<string | null>(null);
  const [sessionHistoryLimit, setSessionHistoryLimit] = useState<number>(30);

  function append(msg: ChatMessage) {
    setMessages((prev) => [...prev, msg]);
  }

  async function send(question: string) {
    const q = question.trim();
    if (!q || loading) return;

    const historyLimit = getHistoryLimit();

    if (messages.length === 0) {
      setSessionStartedAt(new Date().toISOString());
      setSessionHistoryLimit(historyLimit);
    }

    append({ role: "user", text: q, timestamp: new Date().toISOString() });
    setLoading(true);

    try {
      const res = await askChat(q, historyLimit);
      if (res.ok) {
        append({
          role: "assistant",
          text: res.answer ?? "(empty answer)",
          timestamp: new Date().toISOString(),
        });
      } else {
        append({
          role: "error",
          text: res.error ?? "Unknown error",
          timestamp: new Date().toISOString(),
        });
      }
    } catch (e: any) {
      append({
        role: "error",
        text: e?.message ?? "Network error",
        timestamp: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  }

  function clear() {
    setMessages([]);
    setSessionStartedAt(null);
  }

  return { messages, loading, send, clear, sessionStartedAt, sessionHistoryLimit };
}