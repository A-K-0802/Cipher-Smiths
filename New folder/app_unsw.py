import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import shap
import matplotlib.pyplot as plt

# ---------------------------
# Page Configuration
# ---------------------------
st.set_page_config(
    page_title="UNSW-NB15 Threat Detection",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------
# Model and Column Paths
# ---------------------------
# Ensure these files are in a 'models_unsw' subfolder
MODEL_PATH = os.path.join("models_unsw", "supervised_xgb_unsw.joblib")
COLUMNS_PATH = os.path.join("models_unsw", "unsw_model_columns.joblib")


# ---------------------------
# Main Application
# ---------------------------
st.title("🛡️ AI-Powered Threat Detection with UNSW-NB15")
st.markdown(
    "This application uses a supervised XGBoost model trained on the UNSW-NB15 dataset to detect network attacks from log files."
)

# --- File Uploader ---
st.header("Upload Network Log for Analysis")
uploaded_file = st.file_uploader(
    "Please upload a CSV file with network data conforming to the UNSW-NB15 format.",
    type=["csv"],
)

# --- Analysis Logic ---
if uploaded_file is not None:
    # Check if model files exist before proceeding
    if not os.path.exists(MODEL_PATH) or not os.path.exists(COLUMNS_PATH):
        st.error(
            "Model files not found. Please ensure 'supervised_xgb_unsw.joblib' and "
            "'unsw_model_columns.joblib' are in the 'models_unsw' directory."
        )
    else:
        try:
            # --- Load Model and Training Columns ---
            model = joblib.load(MODEL_PATH)
            training_columns = joblib.load(COLUMNS_PATH)
            
            # --- Read and Preprocess Uploaded Data ---
            df_live = pd.read_csv(uploaded_file)
            df_live.columns = df_live.columns.str.strip()

            X_live = df_live.drop(['Label', 'Attack_cat'], axis=1, errors='ignore')
            categorical_cols = X_live.select_dtypes(include=['object']).columns
            X_live_encoded = pd.get_dummies(X_live, columns=categorical_cols)
            X_live_aligned = X_live_encoded.reindex(columns=training_columns, fill_value=0)

            # --- Make Predictions ---
            predictions = model.predict(X_live_aligned)
            predictions_proba = model.predict_proba(X_live_aligned)[:, 1]

            # --- Build Full Results DataFrame ---
            results = []
            for i in X_live_aligned.index:
                full_row_data = df_live.loc[i]
                prediction_val = predictions[i]
                risk = "HIGH" if prediction_val == 1 else "LOW"
                results.append({
                    "Event ID": i, "Destination Port": full_row_data.get('dsport', 'N/A'),
                    "Service": full_row_data.get('service', '-'), "Protocol": full_row_data.get('proto', '-'),
                    "Prediction": "Attack" if prediction_val == 1 else "Normal",
                    "Confidence": f"{predictions_proba[i]*100:.2f}%", "Risk Score": risk
                })
            results_df = pd.DataFrame(results)

            # --- Display Results and Filtering ---
            st.subheader("Analysis Results")
            attack_count = (results_df['Prediction'] == 'Attack').sum()
            st.success(f"Analysis complete. Found **{attack_count}** potential attacks in **{len(results_df)}** total events.")
            
            filter_option = st.radio(
                "Filter results:",
                ('Show Attacks Only', 'Show All (capped at 1000 rows)'),
                horizontal=True
            )

            display_df = results_df[results_df['Prediction'] == 'Attack'] if filter_option == 'Show Attacks Only' else results_df
            display_df_limited = display_df.head(1000)

            def color_risk(val):
                color = 'red' if val == 'HIGH' else 'green'
                return f'background-color: {color}'

            if not display_df_limited.empty:
                st.write(f"Displaying {len(display_df_limited)} of {len(display_df)} selected records.")
                st.dataframe(display_df_limited.style.applymap(color_risk, subset=['Risk Score']))
            else:
                st.info("No records to display for the selected filter.")

            # --- NEW: Add SHAP Explanations for a single event ---
            st.subheader("🕵️ Explain a Prediction")
            attack_event_ids = results_df[results_df['Prediction'] == 'Attack']['Event ID'].tolist()
            
            if not attack_event_ids:
                st.warning("No attacks were detected, so no explanations can be generated.")
            else:
                event_to_explain = st.selectbox(
                    "Select an Event ID to see why it was flagged as an attack:",
                    attack_event_ids
                )
                if st.button("Generate Explanation"):
                    with st.spinner("Generating SHAP explanation..."):
                        event_data = X_live_aligned.loc[[event_to_explain]]
                        explainer = shap.TreeExplainer(model)
                        shap_values = explainer.shap_values(event_data)

                        st.write(f"**Explanation for Event ID {event_to_explain}:**")
                        st.write("This plot shows the features that pushed the prediction towards 'Attack' (red) vs. 'Normal' (blue).")

                        fig, ax = plt.subplots(figsize=(10, 3))
                        shap.force_plot(
                            explainer.expected_value, 
                            shap_values[0], 
                            event_data.iloc[0], 
                            matplotlib=True,
                            show=False
                        )
                        st.pyplot(fig, bbox_inches='tight')

        except Exception as e:
            st.error(f"An error occurred during analysis: {e}")
            st.error(
                "Please ensure the uploaded CSV file has the correct format and features "
                "expected by the UNSW-NB15 model."
            )
else:
    st.info("Awaiting file upload...")

