import json
import os
from google import genai
from google.genai import types
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

#### Creation of ips_agent_embeddings.json ####

INPUT_FILE = "../ips_agent_events.json"
OUTPUT_FILE = "../ips_agent_embeddings.json"

def shorten(text, max_chars=800):
    if not text:
        return ""
    return str(text)[:max_chars]

def load_existing_embeddings():
    if not os.path.exists(OUTPUT_FILE) or os.path.getsize(OUTPUT_FILE) == 0:
        return []

    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Warning: {OUTPUT_FILE} is not valid JSON; rebuilding embeddings from scratch")
        return []

def write_event_embeddings_file(rewrite=True):
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        rag_objects = json.load(f)

    if rewrite:
        embedded_docs = []
    else:
        embedded_docs = load_existing_embeddings()

    already_embedded_ids = {doc["id"] for doc in embedded_docs}
    
    total = len(rag_objects)

    with ThreadPoolExecutor(max_workers=10) as executor:
         futures = [ executor.submit(embed_single_element, obj, i, total)
                    for i, obj in enumerate(rag_objects)
                    if i not in already_embedded_ids]
         
         for future in as_completed(futures):
              result_data = future.result()

              if result_data is not None:
                   embedded_docs.append(result_data)

    embedded_docs.sort(key=lambda doc: doc["id"])

    # write all elements at once, then atomically replace the previous context
    tmp_file = f"{OUTPUT_FILE}.tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(embedded_docs, f, indent=2, ensure_ascii=False)
    os.replace(tmp_file, OUTPUT_FILE)


"""
MULTI-THREAD EMBEDDING WORKFLOW:
* Each thread receives an elements to embed, awaits
 response and returns the text only(!)
 * Only main thread is writing to OUTPUT file to avoid race conditions.
 * as_completed is used as a non-blocking method to 
 have API items written upon arrival.
"""

def embed_single_element(obj, i, total):
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

            print(f"Embedded and saved {i + 1}/{total}")

            return { 
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
            }

    except Exception as e:
            print(f"Stopped at object {i}")
            print(e)
            return None # embedding failed
