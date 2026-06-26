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
from typing import TYPE_CHECKING

from dotenv import load_dotenv
from google import genai
import json
import logging
logging.basicConfig(level=logging.INFO)

# Load .env from backend/ — the file holds GEMINI_API_KEY
load_dotenv()

from llm_rag import build_context_with_rag
from ips_agent_rag import build_ips_agent_context_with_rag
from ips_agent_embed import write_event_embeddings_file
import re

if TYPE_CHECKING:
    from agent import PolicyAnoseekAgent


_API_KEY = os.environ.get("GEMINI_API_KEY")
if _API_KEY:
    _client = genai.Client(api_key=_API_KEY)
else:
    _client = None
    print("[chat] WARNING: GEMINI_API_KEY not set; chat endpoint will fail")


MODEL_NAME = "gemini-3.1-flash-lite"
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
    - If the query isn't related to a certain flow or packet, stick to reliable information from MITRE only.
    - Distinguish between MITRE mitigations and Anoseek response actions.
    - Use the same terminology as the data: "flagged", "blocked", "alerted", "under_attack".
    - When referring to events, prefer their timestamps or event_ids over generic phrases.
    - Keep the answer practical and understandable.
"""


#question= "can you pleae tell me more about the source ip '172.31.64.8'?"

IP_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
EVENT_KEYWORDS = {"this flow", "this alert", "this event", "this detection",
                  "why was", "why did", "what happened", "source ip", "dst ip",
                  "src ip", "destination ip", "flagged", "blocked", "alerted",
                  "lately", "recently", "latest activity", "recent activity"}
INFO_PREFIXES = ("what is", "what are", "explain", "how does", "define",
                 "what does mitre", "what mitigation", "in general")

def build_full_context_with_rag(mitre_top, event_top=None):
    full_docs = []
    full_docs.extend(mitre_top)
    if event_top:
        full_docs.extend(event_top)

    full_docs.sort(key=lambda item: item["score"], reverse=True)
    full_docs = full_docs[:3]
    retrieved_context = "\n\n---\n\n".join(
        item["doc"]["text"] for item in full_docs
    )
    return retrieved_context

def ask(agent: "PolicyAnoseekAgent", question: str) -> dict:
    """Main entry point — called by the /chat endpoint."""
    if not _client:
        return {
            "ok": False,
            "error": "GEMINI_API_KEY not configured on the server",
        }

    if not question or not question.strip():
        return {"ok": False, "error": "empty question"}

    if os.path.exists("../ips_agent_events.json"):
        write_event_embeddings_file(rewrite=True)
    else:
        logging.info("json file for embedding not found!\n")
        
    query_type = is_event_query(question)
    print(query_type)

    if query_type:
        context_ips_and_agent = build_ips_agent_context_with_rag(question)
        event_enrichment = []
        for item in context_ips_and_agent:
            label = item["doc"]["metadata"].get("severity_label")
            if label:
                event_enrichment.append(label)

        enriched_question = f"{question}\n \
            the following event was flagged as {event_enrichment}"
        
        print(f"enriched = {enriched_question}")

        context_mitre_attack = build_context_with_rag(enriched_question)
        full_context = build_full_context_with_rag(context_mitre_attack, context_ips_and_agent)
    else:
        context_mitre_attack = build_context_with_rag(question)
        full_context = build_full_context_with_rag(context_mitre_attack)

    print(
        f"{full_context}"
        )
    

    full_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Data available to you:\n"
        f"{full_context}\n\n"
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

"""
Classifying the user's query to better understand if it's
an informational question [general knowledge]
or a specific event related 
"""
def is_event_query(question: str) -> bool:
    q = question.lower()
    if IP_RE.search(question):
        return True
    if any(q.startswith(p) for p in INFO_PREFIXES):
        return False
    return any(kw in q for kw in EVENT_KEYWORDS)
