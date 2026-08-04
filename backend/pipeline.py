"""
Pipeline used by the /predict-csv endpoint.

Runs inference on a DataFrame, then feeds each row through the policy agent
so the upload also updates global agent state. Returns a DataFrame with both
the model outputs and the agent's decision per row.
"""
from __future__ import annotations

import pandas as pd

from agent import PolicyAnoseekAgent
from inference import AnoseekInference, validate_flow_integrity


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
        integrity = validate_flow_integrity(flow)
        if integrity["tier1_missing"]:
            # Skip inference entirely — an incomplete flow doesn't even enter
            # the sequence buffer, it's blocked on sight.
            return agent.force_block_missing_data(flow, integrity["tier1_missing"])
        if integrity["tier2_missing"]:
            agent.flag_data_quality(flow, integrity["tier2_missing"])

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


def predict_df(
        df: pd.DataFrame,
        inference: AnoseekInference,
        agent: PolicyAnoseekAgent | None = None,
) -> pd.DataFrame:
    """
    1) Inference adds: predicted_class, severity, confidence, is_anomaly.
    2) If agent is provided, each row also gets: action, agent_state, event_id, note.
    """
    out = inference.predict_df(df)

    if agent is None:
        return out

    actions, states, event_ids, notes = [], [], [], []
    for _, row in out.iterrows():
        flow_result = {
            "flow_id": row.get("flow_id"),
            "src_ip": row.get("IPV4_SRC_ADDR") or row.get("src_ip"),
            "dst_ip": row.get("IPV4_DST_ADDR") or row.get("dst_ip"),
            "predicted_class": int(row["predicted_class"]),
            "confidence": float(row["confidence"]),
        }
        decision = agent.analyze_and_act(flow_result)
        if decision.get("ok"):
            actions.append(decision.get("action"))
            states.append(decision.get("agent_state"))
            event_ids.append(decision.get("event_id"))
            notes.append(decision.get("note"))
        else:
            actions.append("error")
            states.append(decision.get("agent_state"))
            event_ids.append(decision.get("event_id"))
            notes.append(decision.get("error"))

    out["action"] = actions
    out["agent_state"] = states
    out["event_id"] = event_ids
    out["note"] = notes
    return out