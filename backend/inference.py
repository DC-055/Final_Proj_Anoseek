from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any
import time

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

from model_def import NetworkLSTMEmbeddings

SEQ_LENGTH    = 2
HIDDEN_SIZE   = 32
NUM_LAYERS    = 2
BUFFER_TIMEOUT_SECONDS = 30

INFERENCE_ENUM = ["LIVE", "CSV"]
INFERENCE_STATE = INFERENCE_ENUM[0]


def _parse_numeric_value(value: Any) -> Any:
    if not isinstance(value, str) or "," not in value:
        return value
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        return np.nan
    try:
        return sum(float(part) for part in parts)
    except ValueError:
        return value


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
        self.feature_cols  = list(bundle["feature_cols"])
        self.class_names   = list(bundle["class_names"])
        self.input_size    = bundle["input_size"]
        self.embedding_dim = bundle["embedding_dim"]
        self.medians       = bundle.get("medians", {})
        self.clip_lower    = bundle.get("clip_lower", {})
        self.clip_upper    = bundle.get("clip_upper", {})

        self.model = NetworkLSTMEmbeddings(
            inp_size=self.input_size,
            hidden_size=HIDDEN_SIZE,
            num_layers=NUM_LAYERS,
            num_classes=len(self.class_names),
            embedding_dim=self.embedding_dim,
        ).to(self.device)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.eval()

        # per-IP rolling buffer for live inference
        self._live_buffers: dict[str, deque] = {}
        self._buffer_timestamps: dict[str, float] = {}

    # ---------------------------------------------------------------- preprocessing

    def _scale_features(self, df: pd.DataFrame) -> np.ndarray:
        """Drop, reorder, clean, and scale rows. Returns [N, F] float32."""
        feats = df.drop(columns=self.cols_to_drop, errors="ignore")
        feats = feats.drop(columns=["Attack", "IPV4_SRC_ADDR", "IPV4_DST_ADDR"], errors="ignore")
        feats = feats.reindex(columns=self.feature_cols)
        feats = feats.replace([np.inf, -np.inf], np.nan)
        feats = feats.map(_parse_numeric_value)
        feats = feats.apply(pd.to_numeric, errors="coerce")
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

    def _make_sequence(self, rows: np.ndarray) -> np.ndarray:
        """[N, F] → [1, SEQ_LENGTH, F], padding by repeating the last row if N < SEQ_LENGTH."""
        if len(rows) < SEQ_LENGTH:
            pad = np.tile(rows[-1:], (SEQ_LENGTH - len(rows), 1))
            rows = np.vstack([rows, pad])
        else:
            rows = rows[-SEQ_LENGTH:]
        return rows[np.newaxis]  # [1, SEQ_LENGTH, F]

    # ---------------------------------------------------------------- inference

    @torch.no_grad()
    def _embed_and_classify(self, sequences: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """sequences: [N, SEQ_LENGTH, F] → (preds [N], probs [N, C])"""
        x = torch.from_numpy(sequences).float().to(self.device)
        emb = self.model.extract_embeddings(x).cpu().numpy()
        preds = self.svc.predict(emb).astype(int)
        if hasattr(self.svc, "predict_proba"):
            probs = self.svc.predict_proba(emb)

        return preds, probs

    # ---------------------------------------------------------------- public API

    def predict_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Groups flows by source IP, builds one sequence per IP (last SEQ_LENGTH rows,
        padded if needed), and assigns that prediction to every row of that IP.
        """
        if df.empty:
            return df.assign(predicted_class=[], severity=[], confidence=[], is_anomaly=[])

        scaled  = self._scale_features(df)
        src_ips = df["IPV4_SRC_ADDR"].values if "IPV4_SRC_ADDR" in df.columns else np.zeros(len(df), dtype=object)

        pred_classes = np.zeros(len(df), dtype=int)
        confidences  = np.zeros(len(df), dtype=np.float32)

        for ip in pd.unique(src_ips):
            idx  = np.where(src_ips == ip)[0]
            rows = scaled[idx]

            seq = self._make_sequence(rows)
            preds, probs = self._embed_and_classify(seq)
            cls = int(preds[0])
            pred_classes[idx] = cls
            confidences[idx]  = float(probs[0, cls])

        out = df.copy()
        out["predicted_class"] = pred_classes
        out["severity"]        = [self.class_names[p] for p in pred_classes]
        out["confidence"]      = confidences.round(4)
        out["is_anomaly"]      = pred_classes != 0
        return out

    def ingest_live_flow(self, flow: dict) -> dict | None:
        """
        Feed one live flow dict. Returns a classification result once the buffer
        reaches SEQ_LENGTH flows, or immediately if the buffer timed out (padded).
        """
        src_ip = flow.get("IPV4_SRC_ADDR", "unknown")
        now = time.time()

        if src_ip not in self._live_buffers:
            self._live_buffers[src_ip] = deque(maxlen=SEQ_LENGTH)
            self._buffer_timestamps[src_ip] = now

        scaled_row = self._scale_features(pd.DataFrame([flow]))[0]

        buf = self._live_buffers[src_ip]
        timed_out = (len(buf) > 0 and len(buf) < SEQ_LENGTH and
                     now - self._buffer_timestamps[src_ip] >= BUFFER_TIMEOUT_SECONDS)

        if timed_out:
            # Pad the stale buffer with the new flow, classify, then reset
            buf.append(scaled_row)
            seq = self._make_sequence(np.array(buf, dtype=np.float32))
            self._live_buffers[src_ip] = deque(maxlen=SEQ_LENGTH)
            self._buffer_timestamps[src_ip] = now
        else:
            buf.append(scaled_row)
            if len(buf) < SEQ_LENGTH:
                return None
            seq = self._make_sequence(np.array(buf, dtype=np.float32))

        preds, probs = self._embed_and_classify(seq)
        cls = int(preds[0])
        return {
            "src_ip":          src_ip,
            "dst_ip":          flow.get("IPV4_DST_ADDR"),
            "predicted_class": cls,
            "severity":        self.class_names[cls],
            "confidence":      round(float(probs[0, cls]), 4),
            "is_anomaly":      cls != 0,
        }

    def flush_incomplete_buffers(self) -> list[dict]:
        """Classify IPs whose buffer never reached SEQ_LENGTH (e.g. single-flow IPs in a CSV).
        Pads each incomplete buffer to SEQ_LENGTH and returns a classification result per IP.
        """
        results = []
        for src_ip, buf in list(self._live_buffers.items()):
            if len(buf) == 0 or len(buf) >= SEQ_LENGTH:
                continue
            try:
                seq = self._make_sequence(np.array(buf, dtype=np.float32))
                preds, probs = self._embed_and_classify(seq)
                cls = int(preds[0])
                results.append({
                    "src_ip":          src_ip,
                    "dst_ip":          None,
                    "predicted_class": cls,
                    "severity":        self.class_names[cls],
                    "confidence":      round(float(probs[0, cls]), 4),
                    "is_anomaly":      cls != 0,
                })
            except Exception as e:
                print(f"[flush] error for {src_ip}: {e}")
        return results
