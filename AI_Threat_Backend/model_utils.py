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
    all_files = glob.glob(os.path.join(data_path, "*.csv"))
    if not all_files:
        raise FileNotFoundError(f"No CSV files found in {data_path}")

    df = pd.concat((pd.read_csv(f, encoding='ISO-8859-1') for f in all_files), ignore_index=True)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    if 'label' not in df.columns:
        raise ValueError("Expected 'label' column in dataset CSVs.")

    X = df.drop(columns=['label'])
    y = df['label']

    # Convert categorical columns to numeric using one-hot encoding
    X = pd.get_dummies(X)

    if X.shape[0] == 0 or X.shape[1] == 0:
        raise ValueError("No data available after preprocessing.")

    return X, y



    X_numeric = X.select_dtypes(include=np.number)
    print(f"Numeric features shape: {X_numeric.shape}")  # Debug line

    if X_numeric.shape[0] == 0:
        raise ValueError("No data available after preprocessing.")

    return X_numeric, y



# -------------------------------
# Train models (IsolationForest + XGBoost)
# -------------------------------
def train_models():
    X, y = load_and_preprocess_cic()

    X_numeric = X.select_dtypes(include=np.number)
    if X_numeric.shape[0] == 0 or X_numeric.shape[1] == 0:
        raise ValueError("No numeric data available after preprocessing.")

    if_model = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
    if_model.fit(X_numeric)

    if_labels = if_model.predict(X_numeric)
    if_labels = np.where(if_labels == -1, 1, 0)  # 1 = anomaly

    clf = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    )

    clf.fit(X_numeric, if_labels)

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
