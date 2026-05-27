import json
import os
from google import genai
from google.genai import types
import time

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

#### Creation of ips_agent_embeddings.json ####

INPUT_FILE = "../ips_agent_events.json"
OUTPUT_FILE = "../ips_agent_embeddings.json"

def shorten(text, max_chars=800):
    if not text:
        return ""
    return str(text)[:max_chars]

def write_event_embeddings_file():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        rag_objects = json.load(f)

    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            embedded_docs = json.load(f)
    else:
        embedded_docs = []

    already_embedded_ids = {doc["id"] for doc in embedded_docs}

    for i, obj in enumerate(rag_objects):
        if i in already_embedded_ids:
            print(f"Skipping {i}, already embedded")
            continue


        text_to_embed = f"""
        Timestamp: {obj.get("timestamp")}
        Source IP: {obj.get("src_ip")}
        Destination IP: {obj.get("dst_ip")}
        Severity: {obj.get("severity_label")} ({obj.get("severity")})
        Action taken: {obj.get("action")}
        Agent state: {obj.get("agent_state")}
        Confidence: {obj.get("confidence")}
        Note: {shorten(obj.get("note", ""), 800)}
        """

        try:
            result = client.models.embed_content(
                model="gemini-embedding-2",
                contents=text_to_embed,
                config=types.EmbedContentConfig(output_dimensionality=768)
            )

            embedding = result.embeddings[0].values

            embedded_docs.append({
                "id": i,
                "text": text_to_embed,
                "embedding": embedding,
                "metadata": {
                    "timestamp": obj.get("timestamp"),
                    "src_ip": obj.get("src_ip"),
                    "dst_ip": obj.get("dst_ip"),
                    "severity": obj.get("severity"),
                    "severity_label": obj.get("severity_label"),
                    "action": obj.get("action"),
                    "agent_state": obj.get("agent_state"),
                    "confidence": obj.get("confidence"),
                    "note": obj.get("note"),
                }
            })

            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(embedded_docs, f, indent=2, ensure_ascii=False)

            print(f"Embedded and saved {i + 1}/{len(rag_objects)}")

            # manual delay to avoid Gemini TPM rate limit
            time.sleep(4)

        except Exception as e:
            print(f"Stopped at object {i}")
            print(e)
            break
