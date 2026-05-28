import { useEffect, useRef, useState } from "react";
import { useChatContext } from "../context/ChatContext";
import ChatMessageBubble from "../components/ChatMessage";

const SUGGESTIONS = [
  "Summarize the recent activity.",
  "Why is the agent in its current state?",
  "Which IPs look most suspicious?",
  "What happened in the last 5 minutes?",
];

export default function Chat() {
  const { messages, loading, send, clear, sessionStartedAt, sessionHistoryLimit } = useChatContext();
  const [input, setInput] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Autoscroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages.length, loading]);

  // Auto-grow textarea up to 4 lines
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    const lineHeight = parseInt(getComputedStyle(el).lineHeight, 10) || 20;
    el.style.height = `${Math.min(el.scrollHeight, lineHeight * 4 + 20)}px`;
  }, [input]);

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const q = input.trim();
    if (!q || loading) return;
    setInput("");
    send(q);
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      const q = input.trim();
      if (!q || loading) return;
      setInput("");
      send(q);
    }
  }

  return (
    <div className="mx-auto flex h-full min-h-[50vh] max-h-[calc(100vh-10rem)] w-full max-w-none flex-col p-4 md:p-8">
      <header className="mb-4 flex items-baseline justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Chat</h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            Ask about recent events, agent state, or a specific IP. The chatbot
            sees real agent data — mention an IP to focus the answer.
          </p>
        </div>
        <button
          onClick={clear}
          disabled={messages.length === 0 && !loading}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
        >
          New Chat
        </button>
      </header>

      {/* ─── Messages ─── */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800"
      >
        {messages.length === 0 && !loading && (
          <div className="flex h-full flex-col items-center justify-center gap-4 py-8">
            <div className="text-sm text-slate-500 dark:text-slate-400">
              Try one of these to get started:
            </div>
            <div className="flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="space-y-4">
          {sessionStartedAt && (
            <div className="flex justify-center">
              <div className="rounded-full border border-slate-200 bg-slate-50 px-4 py-1.5 text-xs text-slate-500 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-400">
                Conversation started at{" "}
                <span className="font-medium text-slate-700 dark:text-slate-200">
                  {new Date(sessionStartedAt).toLocaleTimeString()}
                </span>
                {" — "}context includes the last{" "}
                <span className="font-medium text-slate-700 dark:text-slate-200">
                  {sessionHistoryLimit}
                </span>{" "}
                flows from that moment
              </div>
            </div>
          )}

          {messages.map((m, idx) => (
            <ChatMessageBubble key={idx} message={m} />
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="rounded-2xl rounded-tl-sm bg-slate-100 px-4 py-2 text-sm text-slate-500 dark:bg-slate-700 dark:text-slate-400">
                <span className="inline-flex gap-1">
                  <Dot delay={0} />
                  <Dot delay={150} />
                  <Dot delay={300} />
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ─── Input ─── */}
      <form onSubmit={onSubmit} className="mt-3 flex items-end gap-2">
        <textarea
          ref={textareaRef}
          rows={1}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Ask about an IP, event, or agent state…  Shift+Enter for new line"
          disabled={loading}
          className="flex-1 resize-none overflow-y-auto rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm outline-none focus:ring-2 focus:ring-blue-200 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Send
        </button>
      </form>
    </div>
  );
}

function Dot({ delay }: { delay: number }) {
  return (
    <span
      className="inline-block h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400 dark:bg-slate-500"
      style={{ animationDelay: `${delay}ms` }}
    />
  );
}