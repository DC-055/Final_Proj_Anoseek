<<<<<<< HEAD
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
=======
import torch
from backend.train_and_save import _build_sequences
import numpy as np
import torch.nn.functional as F
import pandas as pd


TARGET_LIKE_COLUMNS = {"Label", "Attack"}


@torch.no_grad()
def predict_df(df_new: pd.DataFrame, lstm_model, bundle: dict) -> pd.DataFrame:
    # 1) same drops as training
    cols_to_drop = bundle["cols_to_drop"]
    df = df_new.drop(columns=cols_to_drop, errors="ignore").copy()

    # 2) stable feature selection (NO iloc slicing)
    feature_cols = [col for col in bundle["feature_cols"] if col not in TARGET_LIKE_COLUMNS]
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    X_df = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    invalid_columns = X_df.columns[X_df.isna().any()].tolist()
    if invalid_columns:
        raise ValueError(
            "Uploaded CSV contains non-numeric values in required feature columns: "
            f"{invalid_columns}"
        )

    # 3) scale with trained scaler
    scaler = bundle["scaler"]
    X_scaled = scaler.transform(X_df.values)                 # [N, D]
    X_scaled_tensor = torch.from_numpy(X_scaled).float()     # torch [N, D]

    # 4) build sequences
    seq_size = int(bundle["seq_size"])
    X_seq = _build_sequences(X_scaled_tensor, seq_size)      # [M, T, D]

    # 5) LSTM hidden features (your model supports return_hidden=True)
    lstm_model.eval()
    X_svm = lstm_model(X_seq, return_hidden=True).cpu().numpy()  # [M, hidden_dim]

    # 6) SVC severity predictioncls
    svc_model = bundle["svc_model"]
    pred = svc_model.predict(X_svm).astype(int)              # [M] values 0..4

    # 7) optional confidence from decision_function -> softmax
    #    (SVC decision_function returns [M, n_classes] for multiclass)
    scores = svc_model.decision_function(X_svm)
    probs = F.softmax(torch.tensor(scores), dim=1).numpy()
    conf = probs.max(axis=1)

    class_names = bundle["class_names"]

    # 8) align predictions back to original rows:
    #    if seq_size>1, prediction corresponds to the LAST row of each window.
    out = df_new.copy()
    out["pred_class"] = np.nan
    out["severity"] = None
    out["is_anomaly"] = None
    out["confidence"] = np.nan

    start_idx = seq_size - 1
    for i, p in enumerate(pred):
        row_idx = start_idx + i
        out.at[row_idx, "pred_class"] = int(p)
        out.at[row_idx, "severity"] = class_names[int(p)]
        out.at[row_idx, "is_anomaly"] = (int(p) != 0)
        out.at[row_idx, "confidence"] = float(conf[i])

<<<<<<< HEAD
>>>>>>> 9aad3b4 (Bring in Daniel's latest branch contents after force-push)
    return out
=======
    return out
>>>>>>> aa24be6 (updated readme.md file with instructions + minor fixes to train_and_save.py)
