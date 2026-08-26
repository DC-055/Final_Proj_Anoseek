"""
Pipeline used by the /predict-csv endpoint.

Runs inference on a DataFrame, then feeds each row through the policy agent
so the upload also updates global agent state. Returns a DataFrame with both
the model outputs and the agent's decision per row.
"""
from __future__ import annotations

import pandas as pd

from agent import PolicyAnoseekAgent
from inference import AnoseekInference


def ingest_live_flow(
        flow: dict,
        inference: AnoseekInference,
        agent: PolicyAnoseekAgent | None = None,
) -> dict | None:
    """
    Feeds one flow dict through the rolling-buffer inference.
    Returns None while the per-IP buffer is still warming up.
    Once the buffer is full, returns the inference result merged with the agent decision.
    """
    if agent is not None:
        agent.record_flow_seen()

    result = inference.ingest_live_flow(flow)
    if result is None:
        return None

    if agent is None:
        return result

    decision = agent.analyze_and_act(result)
    if decision.get("ok"):
        return {
            **result,
            "action":      decision.get("action"),
            "agent_state": decision.get("agent_state"),
            "event_id":    decision.get("event_id"),
            "note":        decision.get("note"),
        }
    return {
        **result,
        "action":      "error",
        "agent_state": decision.get("agent_state"),
        "event_id":    decision.get("event_id"),
        "note":        decision.get("error"),
    }