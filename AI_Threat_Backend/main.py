from fastapi import FastAPI, UploadFile, File, HTTPException
import pandas as pd
from model_utils import train_models, load_models

app = FastAPI(title="AI Threat Detection Backend")

# ---------------------------
# Train Models
# ---------------------------
@app.post("/train")
def train_endpoint():
    try:
        result = train_models()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------
# Upload CSV Logs & Predict
# ---------------------------
@app.post("/upload")
async def upload_logs(file: UploadFile = File(...)):
    try:
        if_model, clf = load_models()
        contents = await file.read()
        df = pd.read_csv(pd.io.common.BytesIO(contents))
        df.columns = df.columns.str.strip()
        X_numeric = df.select_dtypes(include='number')
        
        # Anomaly detection
        anomaly_scores = if_model.decision_function(X_numeric)
        predictions = if_model.predict(X_numeric)
        predictions = ["Anomaly" if x==-1 else "Normal" for x in predictions]
        
        results = []
        for i, row in df.iterrows():
            results.append({
                "index": i,
                "prediction": predictions[i],
                "anomaly_score": float(anomaly_scores[i])
            })
        
        return {"results": results}
    
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Models not found. Train first.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
