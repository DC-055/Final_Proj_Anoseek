import json
import time
import os
from google import genai
from google.genai import types


import math


_API_KEY = os.environ.get("GEMINI_API_KEY")
if _API_KEY:
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
else:
    print("[chat] WARNING: GEMINI_API_KEY not set; chat endpoint will fail")

with open("../anoseek_embeddings.json", "r", encoding="utf-8") as f:
    embedded_docs = json.load(f)

def cosine_similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a == 0 or norm_b == 0:
        return 0

    return dot / (norm_a * norm_b)

def retrieve_relevant_docs(user_query, top_k=2):
    
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

def format_rag(retrieved_context):
    return f"""
    Retrieved Anoseek/MITRE context:
    {retrieved_context}
    """

def build_context_with_rag(user_query):
    top_docs = retrieve_relevant_docs(user_query)
    return top_docs

