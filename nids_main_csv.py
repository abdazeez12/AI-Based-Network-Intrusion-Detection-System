import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder
import seaborn as sns
import matplotlib.pyplot as plt
import gc

# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------
st.set_page_config(page_title="AI NIDS Dashboard", layout="wide")

st.title("AI-Powered Network Intrusion Detection System")
st.markdown("""
### Project Overview
Machine Learning based Network Intrusion Detection using
**Random Forest Algorithm** on CIC-IDS traffic data.

- **BENIGN (0)** → Normal traffic  
- **ATTACK (>0)** → DDoS, DoS, PortScan, Bot, etc.
""")

# --------------------------------------------------
# CSV LOADING (HARD MEMORY LIMIT)
# --------------------------------------------------
@st.cache_data(show_spinner=False)
def load_csv(file, max_rows=10000):
    return pd.read_csv(file, nrows=max_rows)

uploaded_file = st.file_uploader(
    "Upload Network Traffic CSV File",
    type=["csv"]
)

if uploaded_file is not None:
    df = load_csv(uploaded_file)
    st.success("CSV loaded (limited to 10,000 rows for stability)")

    # --------------------------------------------------
    # CLEAN COLUMN NAMES
    # --------------------------------------------------
    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
        .str.replace(" ", "_")
        .str.replace("/", "_per_")
    )

    st.subheader("Dataset Preview")
    st.dataframe(df.head())

    # --------------------------------------------------
    # LABEL SELECTION
    # --------------------------------------------------
    st.subheader("Dataset Configuration")
    label_column = st.selectbox(
        "Select Label / Target Column",
        df.columns.unique().tolist()
    )

    # --------------------------------------------------
    # FEATURE SELECTION (MEMORY SAFE)
    # --------------------------------------------------
    important_features = [
        "Destination_Port",
        "Flow_Duration",
        "Total_Fwd_Packets",
        "Total_Backward_Packets",
        "Packet_Length_Mean",
        "Flow_Bytes_per_s",
        "Flow_Packets_per_s",
        "Fwd_Packet_Length_Mean",
        "Bwd_Packet_Length_Mean",
        "Active_Mean",
        "Idle_Mean",
        "SYN_Flag_Count",
        "ACK_Flag_Count",
        "PSH_Flag_Count",
        "RST_Flag_Count"
    ]

    important_features = [c for c in important_features if c in df.columns]

    df = df[important_features + [label_column]]

    # --------------------------------------------------
    # SPLIT FEATURES & LABEL (FINAL FIX)
    # --------------------------------------------------
    y = df[label_column].iloc[:, 0]     # ✅ ALWAYS 1-D
    X = df.drop(columns=[label_column])

    # --------------------------------------------------
    # LABEL ENCODING (ALWAYS SAFE)
    # --------------------------------------------------
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y.astype(str))

    # --------------------------------------------------
    # NUMERIC CONVERSION & CLEANING
    # --------------------------------------------------
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    X = X.astype("float32")

    # --------------------------------------------------
    # SIDEBAR CONTROLS
    # --------------------------------------------------
    st.sidebar.header("Control Panel")
    split_size = st.sidebar.slider("Training Data Size (%)", 60, 90, 80)
    n_estimators = st.sidebar.slider("Number of Trees", 10, 100, 30)

    # --------------------------------------------------
    # TRAIN / TEST SPLIT
    # --------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=(100 - split_size) / 100,
        random_state=42
    )

    # --------------------------------------------------
    # MODEL TRAINING
    # --------------------------------------------------
    st.divider()
    col_train, col_metrics = st.columns([1, 2])

    with col_train:
        st.subheader("1. Model Training")

        if st.button("Train Model Now"):
            with st.spinner("Training Random Forest Classifier..."):
                model = RandomForestClassifier(
                    n_estimators=n_estimators,
                    max_depth=8,
                    min_samples_split=10,
                    n_jobs=-1,
                    random_state=42
                )
                model.fit(X_train, y_train)
                st.session_state["model"] = model

            st.success("Training Complete!")

        if "model" in st.session_state:
            st.success("Model is Ready")

    # --------------------------------------------------
    # PERFORMANCE METRICS
    # --------------------------------------------------
    with col_metrics:
        st.subheader("2. Performance Metrics")

        if "model" in st.session_state:
            model = st.session_state["model"]
            y_pred = model.predict(X_test)

            acc = accuracy_score(y_test, y_pred)

            m1, m2, m3 = st.columns(3)
            m1.metric("Accuracy", f"{acc * 100:.2f}%")
            m2.metric("Samples Used", len(df))
            m3.metric("Detected Threats", int(np.sum(y_pred)))

            st.write("### Confusion Matrix")
            cm = confusion_matrix(y_test, y_pred)

            fig, ax = plt.subplots(figsize=(4, 3))
            sns.heatmap(cm, annot=True, fmt="d", cmap="Reds", ax=ax)
            st.pyplot(fig)

            st.text("Classification Report")
            st.text(classification_report(y_test, y_pred))
        else:
            st.warning("Please train the model first.")

    # --------------------------------------------------
    # LIVE TRAFFIC SIMULATOR
    # --------------------------------------------------
    st.divider()
    st.subheader("3. Live Traffic Simulator")

    input_data = []
    cols = st.columns(4)

    for i, col in enumerate(X.columns):
        val = cols[i % 4].number_input(
            col,
            value=float(X[col].max())
        )
        input_data.append(val)

    if st.button("Analyze Traffic"):
        if "model" in st.session_state:
            model = st.session_state["model"]
            sample = np.array([input_data], dtype=np.float32)
            pred = model.predict(sample)

            if pred[0] != 0:
                st.error("🚨 ALERT: MALICIOUS TRAFFIC DETECTED!")
            else:
                st.success("✅ Traffic Status: BENIGN (Safe)")

            st.write(f"Predicted Class Label: {pred[0]}")
        else:
            st.error("Please train the model first!")

    # --------------------------------------------------
    # FORCE MEMORY RELEASE
    # --------------------------------------------------
    del X_train, X_test, y_train, y_test
    gc.collect()

else:
    st.info("Please upload a CSV file to begin.")
