import os
import glob
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import xgboost as xgb

MODEL_DIR = "models_cic"
os.makedirs(MODEL_DIR, exist_ok=True)
DATA_DIR = "data"  # CIC-IDS-2017 CSV files

# -------------------------------
# Load & preprocess dataset
# -------------------------------
def load_and_preprocess_cic(data_path=DATA_DIR):
    all_files = glob.glob(os.path.join(data_path, "*.csv"))
    if not all_files:
        raise FileNotFoundError(f"No CSV files found in {data_path}")
    
    df = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    X = df.drop(columns=['Label'])
    y = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    X_numeric = X.select_dtypes(include=np.number)
    return X_numeric, y

# -------------------------------
# Train models
# -------------------------------
def train_models():
    X, y = load_and_preprocess_cic()
    
    # Use subset for faster training
    X_sample, _, y_sample, _ = train_test_split(
        X, y, train_size=0.2, random_state=42, stratify=y
    )
    
    # Isolation Forest
    if_model = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
    if_model.fit(X_sample)
    if_labels = if_model.predict(X_sample)
    if_labels = np.where(if_labels == -1, 1, 0)
    
    # XGBoost for explainability
    clf = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    )
    clf.fit(X_sample, if_labels)
    
    # Save models
    joblib.dump(if_model, os.path.join(MODEL_DIR, "if_model.joblib"))
    joblib.dump(clf, os.path.join(MODEL_DIR, "xgb_classifier.joblib"))
    
    return {"status": "Models trained and saved successfully."}

# -------------------------------
# Load models
# -------------------------------
def load_models():
    if_model_path = os.path.join(MODEL_DIR, "if_model.joblib")
    xgb_path = os.path.join(MODEL_DIR, "xgb_classifier.joblib")
    
    if not os.path.exists(if_model_path) or not os.path.exists(xgb_path):
        raise FileNotFoundError("Models not found. Please train first.")
    
    if_model = joblib.load(if_model_path)
    clf = joblib.load(xgb_path)
    return if_model, clf
