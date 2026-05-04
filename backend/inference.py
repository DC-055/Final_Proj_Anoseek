# loads bundle + model, predicts on a DataFrame

"""
Inference layer — bridges trained artifacts to the API.

Loads:
  backend/artifacts/bundle.joblib       (scaler, SVC, feature_cols, medians, clip bounds)
  backend/artifacts/embedding_model.pt  (the embedding network state_dict)

Exposes:
  AnoseekInference.predict_one(flow_dict) -> dict
  AnoseekInference.predict_df(df)         -> DataFrame
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F


# ---------------------------------------------------------------- model definition
# Must match train_and_evaluate.py exactly. Any change here -> retrain required.

class Embeddings(nn.Module):
    def __init__(self, inp_size: int, embedding_dim: int, num_classes: int = 5):
        super().__init__()
        self.feature_extractor = nn.Sequential(
            nn.Linear(inp_size, 15), nn.ReLU(),
            nn.Linear(15, 7),        nn.ReLU(),
            nn.Linear(7, embedding_dim), nn.ReLU(),
        )
        self.classifier = nn.Linear(embedding_dim, num_classes)

    def forward(self, x):
        return self.classifier(self.feature_extractor(x))

    def extract_embeddings(self, x):
        return self.feature_extractor(x)


# ---------------------------------------------------------------- inference class

class AnoseekInference:
    def __init__(
        self,
        bundle_path: str | Path = "artifacts/bundle.joblib",
        model_path:  str | Path = "artifacts/embedding_model.pt",
        device: str | None = None,
    ):
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))

        bundle: dict[str, Any] = joblib.load(bundle_path)
        self.scaler        = bundle["scaler"]
        self.svc           = bundle["svc_model"]
        self.cols_to_drop  = list(bundle["cols_to_drop"])
        self.feature_cols  = list(bundle["feature_cols"])  # ORDER MATTERS
        self.class_names   = list(bundle["class_names"])
        self.input_size    = bundle["input_size"]
        self.embedding_dim = bundle["embedding_dim"]

        # Optional preprocessing stats (added in the training edits).
        # If missing, we fall back to fillna(0) / no clipping.
        self.medians    = bundle.get("medians", {})
        self.clip_lower = bundle.get("clip_lower", {})
        self.clip_upper = bundle.get("clip_upper", {})

        self.model = Embeddings(
            self.input_size, self.embedding_dim, len(self.class_names)
        ).to(self.device)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.eval()

    # -------------------------------------------------- preprocessing

    def _preprocess(self, df: pd.DataFrame) -> np.ndarray:
        """
        Mirrors train-time preprocessing exactly:
          drop unwanted cols -> reorder -> ±inf -> NaN -> fillna(medians) ->
          clip(lower, upper) -> scaler.transform.
        """
        feats = df.drop(columns=self.cols_to_drop, errors="ignore")
        feats = feats.drop(columns=["Attack"], errors="ignore")  # if labelled CSV

        # Enforce training column order. Missing cols become NaN -> median-filled.
        feats = feats.reindex(columns=self.feature_cols)
        feats = feats.replace([np.inf, -np.inf], np.nan)

        if self.medians:
            feats = feats.fillna(pd.Series(self.medians))
        else:
            feats = feats.fillna(0)

        if self.clip_lower and self.clip_upper:
            feats = feats.clip(
                lower=pd.Series(self.clip_lower),
                upper=pd.Series(self.clip_upper),
                axis=1,
            )

        return self.scaler.transform(feats.values.astype(np.float32))

    # -------------------------------------------------- prediction

    @torch.no_grad()
    def _embed_and_classify(self, scaled: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        x = torch.from_numpy(scaled).float().to(self.device)
        emb = self.model.extract_embeddings(x).cpu().numpy()

        preds  = self.svc.predict(emb).astype(int)
        scores = self.svc.decision_function(emb)
        # Softmax over decision scores to get probability-like confidences.
        # Same approach used in train_and_evaluate.py's evaluation block.
        probs  = F.softmax(torch.tensor(scores), dim=1).numpy()
        return preds, probs

    def predict_df(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return df.assign(predicted_class=[], severity=[], confidence=[], is_anomaly=[])

        scaled = self._preprocess(df)
        preds, probs = self._embed_and_classify(scaled)

        confidences = probs[np.arange(len(preds)), preds]
        labels      = [self.class_names[p] for p in preds]

        out = df.copy()
        out["predicted_class"] = preds
        out["severity"]        = labels
        out["confidence"]      = confidences.round(4)
        out["is_anomaly"]      = preds != 0
        return out

    def predict_one(self, flow: dict) -> dict:
        df = pd.DataFrame([flow])
        out = self.predict_df(df).iloc[0].to_dict()
        return {
            "flow_id":         flow.get("flow_id"),
            "src_ip":          flow.get("IPV4_SRC_ADDR") or flow.get("src_ip"),
            "dst_ip":          flow.get("IPV4_DST_ADDR") or flow.get("dst_ip"),
            "predicted_class": int(out["predicted_class"]),
            "severity":        out["severity"],
            "confidence":      float(out["confidence"]),
            "is_anomaly":      bool(out["is_anomaly"]),
        }