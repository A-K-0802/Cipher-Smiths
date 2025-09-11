from pydantic import BaseModel
from typing import Optional

# ---------------------------
# Training
# ---------------------------
class TrainResponse(BaseModel):
    status: str
    models_saved_to: str


# ---------------------------
# Prediction
# ---------------------------
class PredictRow(BaseModel):
    index: int
    prediction: str
    anomaly_score: float
    risk_score: Optional[str] = None
    automated_action: Optional[str] = None


class PredictResponse(BaseModel):
    results: list[PredictRow]


# ---------------------------
# Alerts (MVP, in-memory only)
# ---------------------------
class AlertOut(BaseModel):
    index: int
    prediction: str
    anomaly_score: Optional[float]
    risk_score: Optional[str]
    automated_action: Optional[str]
