# app.py
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import shap
import os
import glob
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import xgboost as xgb

# ---------------------------
# Paths
# ---------------------------
MODEL_DIR = "models_cic"
DATA_DIR = "MachineLearningCSV/MachineLearningCVE" # <-- IMPORTANT: Point this to the unzipped folder
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------
# Data Loading and Preprocessing for CIC-IDS-2017
# ---------------------------
@st.cache_data
def load_and_preprocess_cic(data_path):
    """Loads, combines, and cleans the CIC-IDS-2017 dataset."""
    all_files = glob.glob(os.path.join(data_path, "*.csv"))
    if not all_files:
        st.error(f"No CSV files found in {data_path}. Please check the path.")
        return None, None
        
    df = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)
    
    # Clean column names (remove leading/trailing spaces)
    df.columns = df.columns.str.strip()
    
    # Drop rows with NaN/Infinity
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Feature and Label separation
    X = df.drop(columns=['Label'])
    y = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1) # 0 for Benign, 1 for Anomaly
    
    return X, y

# ---------------------------
# Train model
# ---------------------------
def train_models():
    """Trains and saves the Isolation Forest and XGBoost models."""
    st.info("Loading and preprocessing data... This may take a while.")
    X, y = load_and_preprocess_cic(DATA_DIR)
    
    if X is None:
        return

    # --- UPDATED: Select only numeric columns for training ---
    X_numeric = X.select_dtypes(include=np.number)

    # Use a subset for faster training during development if needed
    X_sample, _, y_sample, _ = train_test_split(X_numeric, y, train_size=0.2, random_state=42, stratify=y)
    
    st.info(f"Training models on a sample of {len(X_sample)} records...")

    # 1. Isolation Forest for anomaly detection
    if_model = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
    if_model.fit(X_sample)
    
    # Generate labels from Isolation Forest (-1 for anomaly, 1 for normal)
    if_labels = if_model.predict(X_sample)
    if_labels = np.where(if_labels == -1, 1, 0)  # Convert to 1 for anomaly, 0 for normal

    # 2. Train XGBoost classifier to explain IF predictions
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

    st.success("Training complete ✅ Models are saved.")

# ---------------------------
# Rule-Based Risk Scoring
# ---------------------------
def get_risk_score(anomaly_score, data_row):
    """Assigns a risk score based on anomaly score and rules."""
    is_anomaly = anomaly_score < 0
    # Use .get() to safely access the column, which might not exist
    is_critical_port = data_row.get('Destination Port') in [22, 3389, 445]

    if is_anomaly and is_critical_port:
        return "CRITICAL"
    elif anomaly_score < -0.1:
        return "HIGH"
    elif -0.1 <= anomaly_score < 0:
        return "MEDIUM"
    else:
        return "LOW"

# ---------------------------
# Automated SOAR Response
# ---------------------------
SOAR_HISTORY = []

def automated_response(idx, score, data_row):
    """Simulates an automated response for high-risk alerts."""
    action = "None"
    if score in ["HIGH", "CRITICAL"]:
        src_ip = data_row.get('Source IP', 'N/A')
        dst_ip = data_row.get('Destination IP', 'N/A')
        dst_port = data_row.get('Destination Port', 'N/A')
        action = f"🚨 ACTION: Blocked traffic from {src_ip} to {dst_ip} on port {dst_port}"
        SOAR_HISTORY.append(f"Event {idx}: {action}")
    return action

# ---------------------------
# Main App
# ---------------------------
st.set_page_config(layout="wide", page_title="AI-Driven Threat Detection")
st.title("AI-Driven Threat Detection & Prioritization")
st.markdown("This dashboard demonstrates an AI model for detecting suspicious network events, assigning risk scores, and simulating automated responses.")

# --- Training Section ---
with st.expander("Train Models"):
    st.write("Click the button below to train the anomaly detection models on the CIC-IDS-2017 dataset. This needs to be done at least once.")
    if st.button("Train Models"):
        train_models()

# --- Analysis Section ---
st.header("Analyze Network Logs")
uploaded_file = st.file_uploader("Upload a CSV log file for analysis", type=["csv"])

if uploaded_file is not None:
    try:
        # Load models
        if_model = joblib.load(os.path.join(MODEL_DIR, "if_model.joblib"))
        clf = joblib.load(os.path.join(MODEL_DIR, "xgb_classifier.joblib"))

        # --- UPDATED: Process uploaded file ---
        df_live = pd.read_csv(uploaded_file)
        df_live.columns = df_live.columns.str.strip()
        
        st.write("Columns found in uploaded file:", df_live.columns.tolist())
        
        X_numeric = df_live.select_dtypes(include=np.number)

        # Get anomaly scores and predictions using only numeric data
        anomaly_scores = if_model.decision_function(X_numeric)
        predictions = if_model.predict(X_numeric)
        predictions = np.where(predictions == -1, 1, 0)

        # --- UPDATED: Results loop to include IP addresses ---
        results = []
        for i in X_numeric.index:
            full_row_data = df_live.loc[i]
            anomaly_score = anomaly_scores[i]
            prediction_val = predictions[i]
            
            risk = get_risk_score(anomaly_score, full_row_data)
            action = automated_response(i, risk, full_row_data)

            results.append({
                "Event ID": i,
                "Source IP": full_row_data.get('Source IP', 'N/A'),
                "Destination IP": full_row_data.get('Destination IP', 'N/A'),
                "Destination Port": full_row_data.get('Destination Port', 'N/A'),
                "Prediction": "Anomaly" if prediction_val == 1 else "Normal",
                "Risk Score": risk,
                "Automated Response": action
            })

        results_df = pd.DataFrame(results)

        # --- Display Dashboard ---
        st.subheader(" Real-Time Alerts")
        
        def color_risk(val):
            color = 'green' if val == 'LOW' else 'orange' if val == 'MEDIUM' else 'red'
            return f'background-color: {color}'
        
        st.dataframe(results_df.style.applymap(color_risk, subset=['Risk Score']))

        st.subheader(" SOAR Automated Response History")
        if SOAR_HISTORY:
            for item in reversed(SOAR_HISTORY):
                st.info(item)
        else:
            st.write("No automated actions have been taken yet.")
            
        st.subheader("🧠 Anomaly Detection Explanations (SHAP)")
        st.write("This chart shows the top features contributing to an event being classified as an anomaly.")
        
        # --- UPDATED: SHAP plot uses numeric data ---
        explainer = shap.TreeExplainer(clf)
        # Use a smaller sample for SHAP to speed up the app
        shap_sample = X_numeric.sample(min(100, len(X_numeric)), random_state=42)
        shap_values = explainer.shap_values(shap_sample)
        
        fig, ax = plt.subplots()
        shap.summary_plot(shap_values, shap_sample, plot_type="bar", show=False)
        st.pyplot(fig)

    except FileNotFoundError:
        st.error("Models not found. Please train the models first using the 'Train Models' button.")
    except Exception as e:
        st.error(f"An error occurred during analysis: {e}")