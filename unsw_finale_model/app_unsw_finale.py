import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import os

# --- Configuration ---
MODEL_DIR = "models_unsw_reliable"

# --- Load Model and Preprocessing Artifacts ---
@st.cache_resource
def load_artifacts():
    """Load all necessary files for prediction."""
    try:
        model = joblib.load(os.path.join(MODEL_DIR, "reliable_multi_class_xgb_unsw.joblib"))
        scaler = joblib.load(os.path.join(MODEL_DIR, "unsw_scaler_reliable.joblib"))
        model_columns = joblib.load(os.path.join(MODEL_DIR, "unsw_model_columns_reliable.joblib"))
        label_encoder = joblib.load(os.path.join(MODEL_DIR, "unsw_label_encoder_reliable.joblib"))
        with open(os.path.join(MODEL_DIR, 'numeric_medians.json'), 'r') as f:
            numeric_medians = json.load(f)
        with open(os.path.join(MODEL_DIR, 'top_services.json'), 'r') as f:
            top_services = json.load(f)
        return model, scaler, model_columns, label_encoder, numeric_medians, top_services
    except FileNotFoundError:
        return (None,) * 6

model, scaler, model_columns, label_encoder, numeric_medians, top_services = load_artifacts()

def preprocess_data(df, columns, medians, services):
    """Run the full preprocessing pipeline on new data."""
    # Drop columns not used for prediction
    if 'id' in df.columns:
        df = df.drop('id', axis=1)
    # The uploaded data might have these columns, which should be ignored
    df = df.drop(['label', 'attack_cat'], axis=1, errors='ignore')

    # Tame 'service' column based on training data
    df['service'] = df['service'].apply(lambda x: x if x in services else 'other')
    
    # Handle numeric columns
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df[numeric_cols] = df[numeric_cols].fillna(medians)

    # One-Hot Encode categorical columns
    categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
    df_encoded = pd.get_dummies(df, columns=categorical_cols)

    # Align columns to match model's training features
    df_aligned = df_encoded.reindex(columns=columns, fill_value=0)
    
    return df_aligned

# --- Web App UI ---
st.set_page_config(page_title="Threat Detector | CSV Upload", layout="wide")
st.title("🛡️ Network Threat Detector | CSV Analysis")
st.write("Upload a CSV file with network traffic data to classify each connection and identify potential threats.")

if model is None:
    st.error(f"Model artifacts not found in '{MODEL_DIR}'. Please run the training script to generate them.")
else:
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

    if uploaded_file is not None:
        try:
            # Load the uploaded data
            input_df = pd.read_csv(uploaded_file)
            st.success("File uploaded successfully!")
            
            with st.spinner("Preprocessing data and making predictions..."):
                # Preprocess the data
                preprocessed_df = preprocess_data(input_df.copy(), model_columns, numeric_medians, top_services)
                
                # Scale the features
                scaled_data = scaler.transform(preprocessed_df)
                
                # Make predictions
                predictions = model.predict(scaled_data)
                
                # Decode predictions to original labels
                decoded_predictions = label_encoder.inverse_transform(predictions)
            
            st.info("Analysis Complete!")

            # --- Display Results ---
            results_df = input_df.copy()
            results_df['Predicted Threat'] = decoded_predictions
            
            st.subheader("Prediction Results")
            st.write("The table below shows the original data with the model's threat classification for each row.")
            
            # Highlight threats for better visibility
            def highlight_threats(s):
                return ['background-color: #FF7276' if v != 'Normal' else '' for v in s]
            
            st.dataframe(results_df.style.apply(highlight_threats, subset=['Predicted Threat']))
            
            # --- Summary ---
            st.subheader("Threat Summary")
            threat_counts = results_df['Predicted Threat'].value_counts()
            st.bar_chart(threat_counts)
            
        except Exception as e:
            st.error(f"An error occurred during processing: {e}")