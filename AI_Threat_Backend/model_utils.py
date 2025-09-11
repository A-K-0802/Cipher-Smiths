import os
import glob
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import xgboost as xgb

# -------------------------------
# Directories for models & data
# -------------------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models_cic")
os.makedirs(MODEL_DIR, exist_ok=True)

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")  # put CIC CSVs here


# -------------------------------
# Data load & preprocess
# -------------------------------
def load_and_preprocess_cic(data_path=DATA_DIR):
    """
    Loads CIC IDS dataset (CSVs in `data_path`), cleans it, 
    and returns numeric features (X) and binary labels (y).
    Label = 0 for BENIGN, 1 for MALICIOUS.
    """
    all_files = glob.glob(os.path.join(data_path, "*.csv"))
    if not all_files:
        raise FileNotFoundError(f"No CSV files found in {data_path}")

    df = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    if 'Label' not in df.columns:
        raise ValueError("Expected 'Label' column in dataset CSVs.")

    X = df.drop(columns=['Label'])
    y = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    X_numeric = X.select_dtypes(include=np.number)
    if X_numeric.shape[1] == 0:
        raise ValueError("No numeric columns found in dataset.")

    return X_numeric, y


# -------------------------------
# Train models (IsolationForest + XGBoost)
# -------------------------------
def train_models(train_fraction=0.2, sample_for_speed=True):
    """
    Trains:
    - IsolationForest (unsupervised anomaly detection)
    - XGBoost classifier (to approximate IF behavior for explainability)
    Saves both models to MODEL_DIR.
    """
    X, y = load_and_preprocess_cic()

    # sample for faster training (MVP mode)
    if sample_for_speed:
        X_sample, _, y_sample, _ = train_test_split(
            X, y, train_size=train_fraction, random_state=42, stratify=y
        )
    else:
        X_sample = X

    # Isolation Forest
    if_model = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
    if_model.fit(X_sample)

    if_labels = if_model.predict(X_sample)
    if_labels = np.where(if_labels == -1, 1, 0)  # 1 = anomaly, 0 = normal

    # XGBoost for approximation
    clf = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    )

    if len(np.unique(if_labels)) < 2:
        # fallback in rare case all labels are same
        clf.fit(X_sample.iloc[:2], if_labels[:2])
    else:
        clf.fit(X_sample, if_labels)

    joblib.dump(if_model, os.path.join(MODEL_DIR, "if_model.joblib"))
    joblib.dump(clf, os.path.join(MODEL_DIR, "xgb_classifier.joblib"))

    return {"status": "trained", "models_saved_to": MODEL_DIR}


# -------------------------------
# Load models
# -------------------------------
def load_models():
    """
    Loads previously trained IsolationForest and XGBoost models.
    """
    if_path = os.path.join(MODEL_DIR, "if_model.joblib")
    xgb_path = os.path.join(MODEL_DIR, "xgb_classifier.joblib")

    if not os.path.exists(if_path) or not os.path.exists(xgb_path):
        raise FileNotFoundError("Models not found in models_cic. Please call /train first.")

    if_model = joblib.load(if_path)
    clf = joblib.load(xgb_path)
    return if_model, clf
