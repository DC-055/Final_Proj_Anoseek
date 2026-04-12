from backend.model_def import build_lstm_model
import torch
import joblib
from fastapi import FastAPI, UploadFile, File, HTTPException
import pandas as pd, io
from backend.pipeline import predict_df
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/ping")
def ping():
    return {"ok": True}

@app.on_event("startup")
def load_artifacts():
    global BUNDLE, LSTM
    print("startup-before BUNDLE load\n")
    BUNDLE = joblib.load("backend/artifacts/bundle.joblib")
    print("startup-before LSTM load\n")
    LSTM = build_lstm_model(BUNDLE["input_size"], BUNDLE["hidden_dim"])
    LSTM.load_state_dict(torch.load("backend/artifacts/lstm.pt", map_location="cpu"))
    LSTM.eval()
    print("startup-LSTM.eval() mode\n")

@app.post("/predict-csv")
async def predict_csv(file: UploadFile = File(...)):
    # 1) validate input
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Upload a .csv file")

    # 2) read bytes from request body (multipart/form-data)
    raw = await file.read()

    # 3) parse CSV into DataFrame
    df_new = pd.read_csv(io.BytesIO(raw))

    # 4) run your pipeline inference (uses loaded LSTM + bundle)
    out_df = predict_df(df_new, LSTM, BUNDLE)

    # 5) return JSON
    return out_df.to_dict(orient="records")