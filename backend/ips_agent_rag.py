from __future__ import annotations

import json
import os

from google import genai
from google.genai import types
from llm_rag import cosine_similarity

_API_KEY = os.environ.get("GEMINI_API_KEY")
if _API_KEY:
    client = genai.Client(api_key=_API_KEY)
else:
    client = None
    print("[ips_agent_rag] WARNING: GEMINI_API_KEY not set")

_IPS_EMBEDDINGS_FILE = "../ips_agent_embeddings.json"


def load_embedded_docs():
    if os.path.exists(_IPS_EMBEDDINGS_FILE) and os.path.getsize(_IPS_EMBEDDINGS_FILE) > 0:
        try:
            with open(_IPS_EMBEDDINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("[ips_agent_rag] WARNING: ips_agent_embeddings.json is not valid JSON - run ips_agent_embed.py again")
            return []

    print("[ips_agent_rag] WARNING: ips_agent_embeddings.json not found or empty - run ips_agent_embed.py first")
    return []


def retrieve_relevant_ips_and_agent(user_query, top_k=2):
    if not client:
        return []

    query_result = client.models.embed_content(
        model="gemini-embedding-2",
        contents=user_query,
        config=types.EmbedContentConfig(output_dimensionality=768)
    )

    query_embedding = query_result.embeddings[0].values

    scored_docs = []

    for doc in load_embedded_docs():
        score = cosine_similarity(query_embedding, doc["embedding"])
        scored_docs.append({
            "score": score,
            "doc": doc
        })

    scored_docs.sort(key=lambda item: item["score"], reverse=True)

    return scored_docs[:top_k]


def build_ips_agent_context_with_rag(user_query):
    return retrieve_relevant_ips_and_agent(user_query)
