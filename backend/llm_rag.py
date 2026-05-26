import json
import time
import os
from google import genai
from google.genai import types
import math

### TO-DO: Store API KEY 
client = genai.Client(api_key="AIzaSyBQKLFkXS_XxFOBpshl1g8IJUMsyl5DQOA")

with open("anoseek_embeddings.json", "r", encoding="utf-8") as f:
    embedded_docs = json.load(f)

def cosine_similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a == 0 or norm_b == 0:
        return 0

    return dot / (norm_a * norm_b)

def retrieve_relevant_docs(user_query, top_k=3):
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

def answer_with_rag(user_query):
    top_docs = retrieve_relevant_docs(user_query, top_k=3)

    retrieved_context = "\n\n---\n\n".join(
        item["doc"]["text"] for item in top_docs
    )

    system_prompt = """
    You are Anoseek's cybersecurity assistant.

    Your role:
    - Explain Anoseek anomaly detections using the retrieved Anoseek/MITRE context.
    - Connect Anoseek labels to MITRE ATT&CK techniques and mitigations.
    - Explain why a flow may have been flagged based on Anoseek indicators.
    - Recommend safe response actions from Anoseek's response list.

    Rules:
    - Use the retrieved context as your main source.
    - Do not claim an attack succeeded unless the context confirms it.
    - Do not claim credentials were stolen, data was leaked, or a service went down unless evidence is provided.
    - If the retrieved context is insufficient, say what is missing.
    - Distinguish between MITRE mitigations and Anoseek response actions.
    -  Keep the answer practical and understandable.
    """

    contents = f"""
    User question:
    {user_query}

    Retrieved Anoseek/MITRE context:
    {retrieved_context}
    """

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(
            system_instruction=system_prompt
        ),
        contents=contents
    )

    return response.text, top_docs

question = "I have seen numerous calls from the same IP to several services in a short time-span. What does it mean and what should we do?"

answer, docs = answer_with_rag(question)

print(f"query = {question}")
print(answer)