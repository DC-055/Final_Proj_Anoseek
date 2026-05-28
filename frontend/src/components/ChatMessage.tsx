import type { ChatMessage } from "../hooks/useChat";

/* ── Inline renderer: **bold**, *italic*, `code` ── */
function renderInline(text: string): React.ReactNode {
  const segments: React.ReactNode[] = [];
  const re = /(\*\*[^*\n]+\*\*|\*[^*\n]+\*|`[^`\n]+`)/g;
  let last = 0;
  for (const match of text.matchAll(re)) {
    if (match.index! > last) segments.push(text.slice(last, match.index));
    const m = match[0];
    const key = match.index!;
    if (m.startsWith("**")) {
      segments.push(<strong key={key} className="font-semibold">{m.slice(2, -2)}</strong>);
    } else if (m.startsWith("`")) {
      segments.push(
        <code key={key} className="rounded bg-slate-200 px-1 py-0.5 font-mono text-[11px] dark:bg-slate-600">
          {m.slice(1, -1)}
        </code>
      );
    } else {
      segments.push(<em key={key} className="italic">{m.slice(1, -1)}</em>);
    }
    last = match.index! + m.length;
  }
  if (last < text.length) segments.push(text.slice(last));
  return segments.length === 0 ? text : segments;
}

/* ── Block renderer ── */
function MarkdownBody({ text }: { text: string }) {
  const nodes: React.ReactNode[] = [];
  const lines = text.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      nodes.push(
        <pre key={i} className="my-2 overflow-x-auto rounded-lg bg-slate-800 p-3 text-[12px] text-slate-100 dark:bg-slate-900">
          {lang && <span className="mb-1 block text-[10px] uppercase tracking-widest text-slate-400">{lang}</span>}
          <code className="font-mono">{codeLines.join("\n")}</code>
        </pre>
      );
      i++;
      continue;
    }

    // Headings
    const h3 = line.match(/^### (.+)/);
    const h2 = line.match(/^## (.+)/);
    const h1 = line.match(/^# (.+)/);
    if (h3) { nodes.push(<h3 key={i} className="mt-3 mb-1 text-sm font-bold">{renderInline(h3[1])}</h3>); i++; continue; }
    if (h2) { nodes.push(<h2 key={i} className="mt-3 mb-1 text-base font-bold">{renderInline(h2[1])}</h2>); i++; continue; }
    if (h1) { nodes.push(<h1 key={i} className="mt-3 mb-1 text-lg font-bold">{renderInline(h1[1])}</h1>); i++; continue; }

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      nodes.push(<hr key={i} className="my-2 border-slate-300 dark:border-slate-600" />);
      i++;
      continue;
    }

    // Unordered list — collect consecutive list items
    if (/^[-*+] /.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^[-*+] /.test(lines[i])) {
        items.push(lines[i].slice(2));
        i++;
      }
      nodes.push(
        <ul key={i} className="my-1 ml-4 list-disc space-y-0.5">
          {items.map((item, j) => <li key={j}>{renderInline(item)}</li>)}
        </ul>
      );
      continue;
    }

    // Ordered list
    if (/^\d+\. /.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\d+\. /.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\. /, ""));
        i++;
      }
      nodes.push(
        <ol key={i} className="my-1 ml-4 list-decimal space-y-0.5">
          {items.map((item, j) => <li key={j}>{renderInline(item)}</li>)}
        </ol>
      );
      continue;
    }

    // Empty line — skip (paragraph spacing is handled by parent spacing)
    if (line.trim() === "") { i++; continue; }

    // Paragraph / regular line
    nodes.push(<p key={i}>{renderInline(line)}</p>);
    i++;
  }

  return <div className="space-y-1 leading-relaxed">{nodes}</div>;
}

/* ── Exported bubble component ── */
export default function ChatMessageBubble({ message }: { message: ChatMessage }) {
  if (message.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[80%] rounded-2xl rounded-tr-sm bg-blue-600 px-4 py-2 text-sm text-white">
          {message.text}
        </div>
      </div>
    );
  }

  if (message.role === "error") {
    return (
      <div className="flex justify-start">
        <div className="max-w-[80%] rounded-2xl rounded-tl-sm border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300">
          ⚠ {message.text}
        </div>
      </div>
    );
  }

  // assistant
  return (
    <div className="flex justify-start">
      <div className="max-w-[80%] rounded-2xl rounded-tl-sm bg-slate-100 px-4 py-2 text-sm text-slate-800 dark:bg-slate-700 dark:text-slate-100">
        <MarkdownBody text={message.text} />
      </div>
    </div>
  );
}
