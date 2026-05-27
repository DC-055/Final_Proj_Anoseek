"""
FastAPI entrypoint for ANOSEEK.

On startup, loads:
  AnoseekInference     (model + bundle)
  PolicyAnoseekAgent   (singleton, persistent across requests)

Endpoints:
  GET  /ping                          health check
  POST /predict-csv                   run inference + agent on uploaded CSV
  GET  /agent/state                   current agent snapshot
  GET  /agent/events?kind=...&limit   event histories
  GET  /agent/by-ip/{src_ip}          per-IP drill-down
  POST /agent/confirm                 SOC confirms current alert
  POST /agent/reset                   reset agent to IDLE (demo helper)
  GET  /metrics                       saved training metrics
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware

from agent import PolicyAnoseekAgent
from inference import AnoseekInference
from pipeline import predict_df
from chat import ask as chat_ask
from asyncio import sleep
import json as _json

ARTIFACTS = Path("artifacts")

app = FastAPI(title="Anoseek API")

# Incremented on every reset; each predict-csv task captures its value at start
# and checks it on every row — mismatch means reset was called, stop the loop.
_stream_gen: int = 0


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8001", "http://127.0.0.1:8001/docs"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Globals populated at startup
INFERENCE: AnoseekInference | None = None
AGENT:     PolicyAnoseekAgent | None = None


@app.on_event("startup")
def load_artifacts():
    global INFERENCE, AGENT
    print("[startup] loading inference artifacts...")
    INFERENCE = AnoseekInference(
        bundle_path=ARTIFACTS / "bundle.joblib",
        model_path=ARTIFACTS / "embedding_model.pt",
    )
    AGENT = PolicyAnoseekAgent()
    print(f"[startup] ready — input_size={INFERENCE.input_size}, "
          f"classes={INFERENCE.class_names}")


# ---------------------------------------------------------------- health

@app.get("/ping")
def ping():
    return {"ok": True}


# ---------------------------------------------------------------- prediction

@app.post("/predict-csv")
async def predict_csv(
    file: UploadFile = File(...),
    delay_seconds: float = Query(default=1.0, ge=0.0, le=60.0),
):
    global _stream_gen
    if INFERENCE is None or AGENT is None:
        raise HTTPException(503, "Service not ready")

    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file")

    raw = await file.read()

    try:
        df = pd.read_csv(io.BytesIO(raw))
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    my_gen = _stream_gen
    results = []

    for _, row in df.iterrows():
        if _stream_gen != my_gen:
            break  # reset was called — stop feeding old flows into the agent

        row_df = pd.DataFrame([row])

        out = predict_df(row_df, INFERENCE, AGENT)

        results.extend(
            out.where(pd.notnull(out), None).to_dict(orient="records")
        )

        if delay_seconds:
            await sleep(delay_seconds)

    return results


@app.post("/predict")
async def predict(
        file: UploadFile = File(...),
    ):
    if INFERENCE is None or AGENT is None:
        raise HTTPException(503, "Service not ready")

    if not file.filename.lower().endswith(".json"):
        raise HTTPException(400, f"Upload a .json file")

    raw = await file.read()

    try:
        df = pd.read_json(io.BytesIO(raw), typ='series').to_frame().T
    except Exception as e:
        raise HTTPException(403, f"Could not parse JSON: {e}")

    results = []
    out = predict_df(df, INFERENCE, AGENT)

    results.extend(
        out.where(pd.notnull(out), None).to_dict(orient="records")
    )

    return results



# ---------------------------------------------------------------- agent

@app.get("/agent/state")
def agent_state():
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.snapshot()


@app.get("/agent/events")
def agent_events(kind: str = "all", limit: int = 200):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    if kind not in ("all", "flagged", "blocked"):
        raise HTTPException(400, "kind must be all|flagged|blocked")
    return AGENT.list_events(kind=kind, limit=limit)


@app.get("/agent/by-ip/{src_ip}")
def agent_by_ip(src_ip: str):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.by_ip(src_ip)


@app.post("/agent/confirm")
def agent_confirm():
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.confirm_from_soc()


@app.post("/agent/reset")
def agent_reset():
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.reset()


@app.post("/agent/block-ip/{src_ip}")
def agent_block_ip(src_ip: str):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.block_ip_manual(src_ip)


@app.post("/agent/unblock-ip/{src_ip}")
def agent_unblock_ip(src_ip: str):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.unblock_ip_manual(src_ip)

# ---------------------------------------------------------------- metrics

@app.get("/metrics")
def metrics():
    path = ARTIFACTS / "metrics.json"
    if not path.exists():
        raise HTTPException(404, "metrics.json not found — re-run training")
    return json.loads(path.read_text())

# ---------------------------------------------------------------- metrics


def _export_agent_events(limit: int) -> None:
    """Snapshot the last `limit` agent events to ips_agent_events.json."""
    events = AGENT.list_events(kind="all", limit=min(limit, 30))
    Path("ips_agent_events.json").write_text(
        _json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8"
    )


@app.post("/chat")
async def chat_endpoint(payload: dict):
    """
    Body: { "question": "...", "history_limit": 30 }
    Returns: { ok, answer, debug } or { ok: false, error }
    """
    if AGENT is None:
        raise HTTPException(503, "Service not ready")

    question = (payload or {}).get("question", "").strip()
    if not question:
        raise HTTPException(400, "Empty 'question' field")

    history_limit = int((payload or {}).get("history_limit", 30))
    _export_agent_events(history_limit)

    return chat_ask(AGENT, question)

# open connection for stream flow
"""@app.websocket("/ws/stream/csv)"""
