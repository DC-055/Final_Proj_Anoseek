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
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from agent import PolicyAnoseekAgent
from inference import AnoseekInference
from pipeline import predict_df

ARTIFACTS = Path("artifacts")

app = FastAPI(title="Anoseek API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
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
async def predict_csv(file: UploadFile = File(...)):
    if INFERENCE is None or AGENT is None:
        raise HTTPException(503, "Service not ready")
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file")

    raw = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(raw))
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    out = predict_df(df, INFERENCE, AGENT)

    # Replace pandas NaN with None so JSON serialization doesn't blow up
    return out.where(pd.notnull(out), None).to_dict(orient="records")


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


# ---------------------------------------------------------------- metrics

@app.get("/metrics")
def metrics():
    path = ARTIFACTS / "metrics.json"
    if not path.exists():
        raise HTTPException(404, "metrics.json not found — re-run training")
    return json.loads(path.read_text())