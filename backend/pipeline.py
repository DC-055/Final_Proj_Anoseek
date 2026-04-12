import torch
from backend.train_and_save import _build_sequences
import numpy as np
import torch.nn.functional as F
import pandas as pd
@torch.no_grad()
def predict_df(df_new: pd.DataFrame, lstm_model, bundle: dict) -> pd.DataFrame:
    # 1) same drops as training
    cols_to_drop = bundle["cols_to_drop"]
    df = df_new.drop(columns=cols_to_drop, errors="ignore").copy()

    # 2) stable feature selection (NO iloc slicing)
    feature_cols = bundle["feature_cols"]
    print(feature_cols)
    print(feature_cols.shape)
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    X_df = df[feature_cols]

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

    # 6) SVC severity prediction
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
    out["is_anomaly"] = np.nan
    out["confidence"] = np.nan

    start_idx = seq_size - 1
    for i, p in enumerate(pred):
        row_idx = start_idx + i
        out.at[row_idx, "pred_class"] = int(p)
        out.at[row_idx, "severity"] = class_names[int(p)]
        out.at[row_idx, "is_anomaly"] = (int(p) != 0)
        out.at[row_idx, "confidence"] = float(conf[i])

    return out