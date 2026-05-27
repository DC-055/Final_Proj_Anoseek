from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING

from google import genai
from llm_rag import cosine_similarity

if TYPE_CHECKING:
    from agent import PolicyAnoseekAgent

_API_KEY = os.environ.get("GEMINI_API_KEY")
if _API_KEY:
    client = genai.Client(api_key=_API_KEY)
else:
    print("[ips_agent_rag] WARNING: GEMINI_API_KEY not set; embeddings will fail")

_IPS_EMBEDDINGS_FILE = "../ips_agent_embeddings.json"
if os.path.exists(_IPS_EMBEDDINGS_FILE):
    with open(_IPS_EMBEDDINGS_FILE, "r", encoding="utf-8") as f:
        embedded_docs = json.load(f)
else:
    print("[ips_agent_rag] WARNING: ips_agent_embeddings.json not found — run ips_agent_embedded.py first")
    embedded_docs = []


def retrieve_relevant_ips_and_agent(user_query, top_k=5):
    query_result = client.models.embed_content(
        model="gemini-embedding-2",
        contents=user_query,
        config=types.EmbedContentConfig(output_dimensionality=768)
    )

    query_embedding = query_result.embeddings[0].values

    scored_docs = []

    for doc in embedded_docs:
        score = cosine_similarity(query_embedding, doc["embedding"])
        scored_docs.append({
            "score": score,
            "doc": doc
        })

    scored_docs.sort(key=lambda item: item["score"], reverse=True)

    return scored_docs[:top_k]

def build_ips_agent_context_with_rag(user_query):
    top_docs = retrieve_relevant_ips_and_agent(user_query)

    retrieved_context = "\n\n---\n\n".join(
        item["doc"]["text"] for item in top_docs
    )

    return retrieved_context