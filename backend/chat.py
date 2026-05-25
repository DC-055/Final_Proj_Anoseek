"""
Chat layer — single-turn LLM Q&A grounded in agent state.

Flow:
  1. Look for an IP in the user's question (regex).
  2. If found, pull that IP's events via agent.by_ip().
     If not, pull the last N events generally.
  3. Format a system prompt + agent state + events + question.
  4. Call Gemini, return the answer.

Environment:
  GEMINI_API_KEY — required, lives in backend/.env (never commit!)
"""
from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from dotenv import load_dotenv
import google.generativeai as genai

if TYPE_CHECKING:
    from agent import PolicyAnoseekAgent

# Load .env from backend/ — the file holds GEMINI_API_KEY
load_dotenv()

_API_KEY = os.environ.get("GEMINI_API_KEY")
if _API_KEY:
    genai.configure(api_key=_API_KEY)
else:
    print("[chat] WARNING: GEMINI_API_KEY not set; chat endpoint will fail")

# Cheap and fast — good enough for grounded Q&A on a few hundred tokens of context
MODEL_NAME = "gemini-2.5-flash"
MAX_EVENTS_GENERAL = 30   # if no IP detected, send the last N events
MAX_EVENTS_BY_IP   = 50   # if IP detected, send up to N events for that IP


SYSTEM_PROMPT = """You are Anoseek, a SOC (Security Operations Center) assistant.
You help analysts understand network anomaly events and the actions an automated
policy agent has taken.

Rules:
- Answer ONLY based on the data shown to you below. Do not invent events, IPs, or numbers.
- If the data doesn't answer the question, say "I don't have that information."
- Keep answers concise (2-4 sentences unless asked for detail).
- Use the same terminology as the data: "flagged", "blocked", "alerted", "under_attack".
- When referring to events, prefer their timestamps or event_ids over generic phrases.
"""


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ip(text: str) -> str | None:
    """Find the first IPv4-looking token in the question, or None."""
    m = _IPV4_RE.search(text or "")
    return m.group(0) if m else None


def _format_event(e: dict) -> str:
    """One-line summary of an event for prompt injection."""
    ts = e.get("timestamp", "?")[:19]   # trim ISO microseconds
    sev = e.get("severity_label", "?")
    action = e.get("action", "?")
    src = e.get("src_ip") or "?"
    note = e.get("note", "")
    conf = e.get("confidence")
    conf_s = f" conf={conf:.2f}" if isinstance(conf, (int, float)) else ""
    return f"[{ts}] src={src} severity={sev} action={action}{conf_s} note={note}"


def build_context(agent: "PolicyAnoseekAgent", question: str) -> tuple[str, dict]:
    """
    Pull relevant agent data based on the question. Returns:
      (context_text, debug_info_dict)
    """
    snapshot = agent.snapshot()
    ip = _extract_ip(question)

    if ip:
        info = agent.by_ip(ip)
        events = info["events"][-MAX_EVENTS_BY_IP:]
        scope = f"IP {ip}"
        ip_summary = (
            f"Source IP focus: {ip}\n"
            f"  total events: {info['counts']['events']}\n"
            f"  flagged: {info['counts']['flagged']}\n"
            f"  blocked: {info['counts']['blocked']}\n"
            f"  manually blocked: {info.get('manually_blocked', False)}\n"
        )
    else:
        events = agent.list_events(kind="all", limit=MAX_EVENTS_GENERAL)
        scope = "recent activity (no specific IP)"
        ip_summary = ""

    lines = []
    lines.append(f"=== Agent state ===")
    lines.append(f"status: {snapshot['status']}")
    lines.append(f"in state since: {snapshot['entered_state_at']}")
    lines.append(f"totals: events={snapshot['totals']['events']} "
                 f"flagged={snapshot['totals']['flagged']} "
                 f"blocked={snapshot['totals']['blocked']}")
    if ip_summary:
        lines.append("")
        lines.append(ip_summary.rstrip())

    lines.append("")
    lines.append(f"=== Events ({scope}, most recent first) ===")
    if not events:
        lines.append("(no events)")
    else:
        for e in reversed(events):
            lines.append(_format_event(e))

    return "\n".join(lines), {"ip_detected": ip, "events_included": len(events)}


def ask(agent: "PolicyAnoseekAgent", question: str) -> dict:
    """Main entry point — called by the /chat endpoint."""
    if not _API_KEY:
        return {
            "ok": False,
            "error": "GEMINI_API_KEY not configured on the server",
        }

    if not question or not question.strip():
        return {"ok": False, "error": "empty question"}

    context, debug = build_context(agent, question)

    full_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Data available to you:\n"
        f"{context}\n\n"
        f"Question from analyst:\n"
        f"{question}"
    )

    try:
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(full_prompt)
        answer = response.text or "(empty response)"
    except Exception as e:
        return {"ok": False, "error": f"LLM call failed: {e}"}

    return {
        "ok": True,
        "answer": answer,
        "debug": debug,
    }