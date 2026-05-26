<<<<<<< HEAD
import json
import os
from google import genai
from google.genai import types 
import time

### TODO -> STORE API-KEY AS ENV VARIABLE
client = genai.Client(api_key="GEMINI_API_KEY")

#### Creation of anoseek_embeddings.json ####

INPUT_FILE = "../anoseek_rag_mitre_enriched.json"
OUTPUT_FILE = "../anoseek_embeddings.json"

def shorten(text, max_chars=800):
    if not text:
        return ""
    return text[:max_chars]

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
    Anoseek label: {obj.get("anoseek label")}
    Severity: {obj.get("severity text")} ({obj.get("anoseek severity")})

    MITRE ID: {obj.get("mitre id")}
    Attack name: {obj.get("attack name")}
    Attack description: {shorten(obj.get("attack description"), 800)}

    Mitigation: {obj.get("mitigation")}
    Mitigation description: {shorten(obj.get("mitigation description"), 800)}

    Anoseek indicators: {", ".join(obj.get("anoseek indicators", []))}
    Anoseek responses: {", ".join(obj.get("anoseek responses", []))}
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
                "anoseek_label": obj.get("anoseek label"),
                "severity": obj.get("anoseek severity"),
                "severity_text": obj.get("severity text"),
                "mitre_id": obj.get("mitre id"),
                "attack_name": obj.get("attack name"),
                "mitigation": obj.get("mitigation")
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
=======
import json
import os
from google import genai
from google.genai import types
import time

### TODO -> STORE API-KEY AS ENV VARIABLE
client = genai.Client(api_key="GEMINI_API_KEY")

#### Creation of anoseek_embeddings.json ####

INPUT_FILE = "anoseek_rag_mitre_enriched.json"
OUTPUT_FILE = "anoseek_embeddings.json"

def shorten(text, max_chars=800):
    if not text:
        return ""
    return text[:max_chars]

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
    Anoseek label: {obj.get("anoseek label")}
    Severity: {obj.get("severity text")} ({obj.get("anoseek severity")})

    MITRE ID: {obj.get("mitre id")}
    Attack name: {obj.get("attack name")}
    Attack description: {shorten(obj.get("attack description"), 800)}

    Mitigation: {obj.get("mitigation")}
    Mitigation description: {shorten(obj.get("mitigation description"), 800)}

    Anoseek indicators: {", ".join(obj.get("anoseek indicators", []))}
    Anoseek responses: {", ".join(obj.get("anoseek responses", []))}
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
                "anoseek_label": obj.get("anoseek label"),
                "severity": obj.get("anoseek severity"),
                "severity_text": obj.get("severity text"),
                "mitre_id": obj.get("mitre id"),
                "attack_name": obj.get("attack name"),
                "mitigation": obj.get("mitigation")
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
>>>>>>> cff3077 (added llm_embed.py with minor tweaks)
