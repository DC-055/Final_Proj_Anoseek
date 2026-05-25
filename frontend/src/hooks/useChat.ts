import { useState } from "react";
import { askChat } from "../api/chat";

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

  function append(msg: ChatMessage) {
    setMessages((prev) => [...prev, msg]);
  }

  async function send(question: string) {
    const q = question.trim();
    if (!q || loading) return;

    append({ role: "user", text: q, timestamp: new Date().toISOString() });
    setLoading(true);

    try {
      const res = await askChat(q);
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
  }

  return { messages, loading, send, clear };
}