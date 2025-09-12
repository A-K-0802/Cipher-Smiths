from fastapi import FastAPI, UploadFile, File, HTTPException
from dotenv import load_dotenv
import os, io, json
import pandas as pd
import numpy as np
from typing import List

from .model_utils import train_models, load_models
from .schemas import TrainResponse, PredictResponse, PredictRow, AlertOut

# Load environment variables (SECRET_KEY etc.)
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")

app = FastAPI(title="AI Threat Detection Backend (No-DB)")

# ---------------------------
# Memory storage for alerts
# ---------------------------
ALERTS_MEMORY: List[dict] = []

# ---------------------------
# Risk Scoring
# ---------------------------
def get_risk_score(anomaly_score, data_row):
    is_anomaly = anomaly_score < 0
    is_critical_port = data_row.get("Destination Port") in [22, 3389, 445]

    if is_anomaly and is_critical_port:
        return "CRITICAL"
    elif anomaly_score < -0.1:
        return "HIGH"
    elif -0.1 <= anomaly_score < 0:
        return "MEDIUM"
    else:
        return "LOW"

# ---------------------------
# Automated SOAR
# ---------------------------
SOAR_HISTORY = []

def automated_response(idx, score, data_row):
    action = "None"
    if score in ["HIGH", "CRITICAL"]:
        src_ip = data_row.get("Source IP", "N/A")
        dst_ip = data_row.get("Destination IP", "N/A")
        dst_port = data_row.get("Destination Port", "N/A")
        action = f"🚨 ACTION: Blocked traffic from {src_ip} to {dst_ip} on port {dst_port}"
        SOAR_HISTORY.append(f"Event {idx}: {action}")
    return action

# ---------------------------
# Train Endpoint
# ---------------------------
@app.post("/train", response_model=TrainResponse)
def train_endpoint():
    try:
        result = train_models()
        return TrainResponse(
            status="success",
            models_saved_to=str(result)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------
# Upload & Predict + Save Alerts (in memory)
# ---------------------------
@app.post("/upload", response_model=PredictResponse)
async def upload_logs(file: UploadFile = File(...)):
    try:
        if_model, clf = load_models()

        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
        df.columns = df.columns.str.strip()
        X_numeric = df.select_dtypes(include=np.number)

        anomaly_scores = if_model.decision_function(X_numeric)
        predictions = if_model.predict(X_numeric)
        predictions = np.where(predictions == -1, 1, 0)  # 1=Anomaly, 0=Normal

        results: List[PredictRow] = []

        for i in X_numeric.index:
            full_row_data = df.loc[i].to_dict()
            anomaly_score = anomaly_scores[i]
            prediction_val = predictions[i]

            risk = get_risk_score(anomaly_score, full_row_data)
            action = automated_response(i, risk, full_row_data)
            prediction_str = "Anomaly" if prediction_val == 1 else "Normal"

            # Save to in-memory alerts
            alert = {
                "id": len(ALERTS_MEMORY) + 1,
                "timestamp": pd.Timestamp.now().isoformat(),
                "source_ip": full_row_data.get("Source IP", "N/A"),
                "destination_ip": full_row_data.get("Destination IP", "N/A"),
                "destination_port": str(full_row_data.get("Destination Port", "N/A")),
                "prediction": prediction_str,
                "anomaly_score": float(anomaly_score),
                "risk_score": risk,
                "automated_action": action,
                "raw_json": json.dumps(full_row_data)
            }
            ALERTS_MEMORY.append(alert)

            results.append(
                PredictRow(
                    index=int(i),
                    prediction=prediction_str,
                    anomaly_score=float(anomaly_score),
                    risk_score=risk,
                    automated_action=action
                )
            )

        return PredictResponse(results=results)

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Models not found. Train first.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------
# Get all alerts (SOC dashboard)
# ---------------------------
@app.get("/alerts", response_model=List[AlertOut])
def get_alerts():
    return ALERTS_MEMORY

@app.get("/")
def root():
    return {"message": "AI Threat Detection Backend is running 🚀"}