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
from google import genai

# Load .env from backend/ — the file holds GEMINI_API_KEY
load_dotenv()

from llm_rag import build_context_with_rag
from ips_agent_rag import build_ips_agent_context_with_rag

if TYPE_CHECKING:
    from agent import PolicyAnoseekAgent


_API_KEY = os.environ.get("GEMINI_API_KEY")
if _API_KEY:
    _client = genai.Client(api_key=_API_KEY)
else:
    _client = None
    print("[chat] WARNING: GEMINI_API_KEY not set; chat endpoint will fail")


MODEL_NAME = "gemini-2.5-flash"
SYSTEM_PROMPT = """
    You are Anoseek's cybersecurity assistant.

    Your role:
    - Explain Anoseek anomaly detections using the retrieved Anoseek/MITRE context.
    - Connect Anoseek labels to MITRE ATT&CK techniques and mitigations.
    - Explain why a flow may have been flagged based on Anoseek indicators.
    - Help analysts understand the actions an automated policy agent has taken.
    - Recommend safe response actions from Anoseek's response list.
  
    Rules:
    - Use the retrieved context as your main source. Do not invent events, IPs, or numbers.
    - If attack type found MITRE ATTACK RAG please refer to it
    - If the data doesn't answer the question, say "I don't have that information."
    - Do not claim an attack succeeded unless the context confirms it.
    - Do not claim credentials were stolen, data was leaked, or a service went down unless evidence is provided.
    - If the retrieved context is insufficient, say what is missing.
    - Distinguish between MITRE mitigations and Anoseek response actions.
    - Use the same terminology as the data: "flagged", "blocked", "alerted", "under_attack".
    - When referring to events, prefer their timestamps or event_ids over generic phrases.
    - Keep the answer practical and understandable.
"""


#question= "can you pleae tell me more about the source ip '172.31.64.8'?"

def ask(agent: "PolicyAnoseekAgent", question: str) -> dict:
    """Main entry point — called by the /chat endpoint."""
    if not _client:
        return {
            "ok": False,
            "error": "GEMINI_API_KEY not configured on the server",
        }

    if not question or not question.strip():
        return {"ok": False, "error": "empty question"}

    context_ips_and_agent = build_ips_agent_context_with_rag(question)
    context_mitre_attack = build_context_with_rag(question)

    print(
        f"ips and agent context:\n"
        f"{context_ips_and_agent}\n\n"
        f"MITRE ATTACK context:\n"
        f"{context_mitre_attack}\n\n"
        )
    

    full_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Data available to you:\n"
        f"ips and agent context:\n"
        f"{context_ips_and_agent}\n\n"
        f"MITRE ATTACK context:\n"
        f"{context_mitre_attack}\n\n"
        f"Question from analyst:\n"
        f"{question}"
    )

    try:
        response = _client.models.generate_content(
            model=MODEL_NAME,
            contents=full_prompt,
        )
        answer = response.text or "(empty response)"
    except Exception as e:
        return {"ok": False, "error": f"LLM call failed: {e}"}

    return {
        "ok": True,
        "answer": answer,
    }