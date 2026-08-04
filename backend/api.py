"""
FastAPI entrypoint for ANOSEEK.

On startup, loads:
  AnoseekInference     (model + bundle)
  PolicyAnoseekAgent   (singleton, persistent across requests)

Endpoints:
  GET  /ping                          health check
  POST /login                         username+password -> JWT (role: SOC|ADMIN)
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
import math
from pathlib import Path

import pandas as pd
import inference
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

import auth
from agent import PolicyAnoseekAgent
from inference import AnoseekInference
from threat_intel import ipsun_l3_import
from pipeline import ingest_live_flow
from chat import ask as chat_ask
from asyncio import sleep
import json as _json


def json_safe(obj):
    """Recursively replace non-finite floats (NaN/Infinity) with None.

    JSON has no representation for them: Starlette's encoder raises on NaN,
    and plain json.dumps would emit the non-standard `NaN` token that
    JSON.parse on the frontend can't read either. A NaN prediction shouldn't
    take a whole endpoint down, so we degrade it to null instead.
    """
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    return obj


class SafeJSONResponse(JSONResponse):
    def render(self, content) -> bytes:
        return super().render(json_safe(content))


ARTIFACTS = Path("artifacts")

app = FastAPI(title="Anoseek API", default_response_class=SafeJSONResponse)

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
    auth.init_db()
    print("[startup] loading inference artifacts...")
    INFERENCE = AnoseekInference(
        bundle_path=ARTIFACTS / "bundle.joblib",
        model_path=ARTIFACTS / "embedding_model.pt",
    )

    policy_path = Path(ARTIFACTS / "policy_file.json")
    if not policy_path.exists():
        raise RuntimeError(f"Policy file not found: {policy_path}")
    try:
        policy = json.loads(policy_path.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid policy file: {e}")

    if ipsun_l3_import():
        ipsum_path = Path(ARTIFACTS / "IPsum_L3.txt")
        if not ipsum_path.exists():
            raise RuntimeError(f"IPsum file not found: {ipsum_path}")
        try:
            with open(ipsum_path, "r", encoding="utf-8") as file:
                ipsum = set(line.strip() for line in file if line.strip())
        except (UnicodeDecodeError, OSError) as e:
            raise RuntimeError(f"Invalid IPsum file: {e}")
    else:
        raise RuntimeError(f"Download of IPsum_L3 file failed")


    AGENT = PolicyAnoseekAgent(policy, ipsum)
    print(f"[startup] ready — input_size={INFERENCE.input_size}, "
          f"classes={INFERENCE.class_names}")


# ---------------------------------------------------------------- health

@app.get("/ping")
def ping():
    return {"ok": True}


# ---------------------------------------------------------------- auth

@app.post("/login")
def login(payload: dict = Body(...)):
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if not username or not password:
        raise HTTPException(400, "username and password required")

    role = auth.authenticate(username, password)
    if role is None:
        raise HTTPException(401, "Invalid username or password")

    return {"token": auth.create_token(username, role), "username": username, "role": role}


# ---------------------------------------------------------------- prediction

@app.post("/predict-csv")
async def predict_csv(
    file: UploadFile = File(...),
    delay_seconds: float = Query(default=0.0, ge=0.0, le=60.0),
):
    inference.INFERENCE_STATE = inference.INFERENCE_ENUM[1]

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
    INFERENCE._live_buffers.clear()

    async def event_stream():
        for _, row in df.iterrows():
            if _stream_gen != my_gen:
                yield "data: {\"aborted\": true}\n\n"
                return

            result = None
            try:
                result = ingest_live_flow(row.to_dict(), INFERENCE, AGENT)
            except Exception as e:
                print(f"[predict-csv] row error: {e}")

            if result is not None:
                yield f"data: {json.dumps(json_safe(result))}\n\n"

            if delay_seconds:
                raw_ms = float(row.get("FLOW_DURATION_MILLISECONDS") or 0)
                natural_s = min(raw_ms / 1000.0, 2.0)   # cap at 2 s (was 30 s)
                wait = natural_s * delay_seconds
                if wait > 0:
                    await sleep(wait)

        # Flush IPs with incomplete buffers (appeared only once in the CSV)
        for flow_result in INFERENCE.flush_incomplete_buffers():
            if _stream_gen != my_gen:
                break
            try:
                decision = AGENT.analyze_and_act(flow_result)
                if decision.get("ok"):
                    payload = {**flow_result, 'action': decision.get('action'), 'agent_state': decision.get('agent_state'), 'event_id': decision.get('event_id'), 'note': decision.get('note')}
                    yield f"data: {json.dumps(json_safe(payload))}\n\n"
            except Exception as e:
                print(f"[predict-csv] flush error for {flow_result.get('src_ip')}: {e}")

        yield "data: {\"done\": true}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/predict")
async def predict(
        flow: dict = Body(...),
    ):

    # setting state to "LIVE"
    inference.INFERENCE_STATE = inference.INFERENCE_ENUM[0]

    if INFERENCE is None or AGENT is None:
        raise HTTPException(503, "Service not ready")
    
    try:
        result = ingest_live_flow(flow, INFERENCE, AGENT)
    except Exception as e:
        raise HTTPException(500, f"Prediction failed: {e}")

    if result is None:
        return {"buffering": True, "src_ip": flow.get("IPV4_SRC_ADDR")}

    return result


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


@app.get("/agent/enforcement")
def agent_enforcement():
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return {
        "blocked_ips": list(AGENT.blocked_by_ip.keys()),
        "rate_limited_ips": list(AGENT.rate_limited_by_ip.keys()),
    }


@app.get("/agent/by-ip/{src_ip}")
def agent_by_ip(src_ip: str):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.by_ip(src_ip)


@app.post("/agent/confirm")
def agent_confirm(payload: dict = Body(default={})):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    confirmed = bool(payload.get("confirmed", True))
    return AGENT.confirm_from_soc(confirmed=confirmed)


@app.post("/agent/reset")
def agent_reset():
    global _stream_gen
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    _stream_gen += 1  # signals any running predict-csv loop to stop
    INFERENCE._live_buffers.clear()
    inference.INFERENCE_STATE = inference.INFERENCE_ENUM[0]  # back to LIVE
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


@app.post("/agent/rate-limit-ip/{src_ip}")
def agent_rate_limit_ip(src_ip: str):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.rate_limit_ip_manual(src_ip)


@app.post("/agent/unrate-limit-ip/{src_ip}")
def agent_unrate_limit_ip(src_ip: str):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.rate_unlimit_manual(src_ip)


@app.get("/agent/policy")
def get_policy(_admin: dict = Depends(auth.require_admin)):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.policy


@app.post("/agent/policy")
def update_policy(payload: dict, _admin: dict = Depends(auth.require_admin)):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    if "Statement" not in payload or not isinstance(payload["Statement"], list):
        raise HTTPException(400, "Invalid policy: missing 'Statement' list")
    policy_path = ARTIFACTS / "policy_file.json"
    policy_path.write_text(json.dumps(payload, indent=4))
    AGENT.policy = payload
    return {"ok": True}


@app.get("/agent/alerts")
def agent_alerts(since: int = 0):
    if AGENT is None:
        raise HTTPException(503, "Service not ready")
    return AGENT.get_alerts(since=since)


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
    Path("../ips_agent_events.json").write_text(
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
