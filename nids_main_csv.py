"""
AI-Powered Network Intrusion Detection System (NIDS)
=====================================================
A Streamlit-based dashboard that uses multiple ML algorithms to detect
network intrusions in real-time from CIC-IDS-style CSV traffic data.

Models: Random Forest, XGBoost, Decision Tree
Features: Auto feature selection, ROC curves, confidence scoring,
          attack-type classification, data quality audit, model export.

Author : cazy8
License: MIT
"""

import streamlit as st
import pandas as pd
import numpy as np
import time
import gc
import io
import joblib
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
    precision_recall_curve,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
import seaborn as sns
import matplotlib.pyplot as plt

# Optional: XGBoost
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------
st.set_page_config(
    page_title="AI NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(90deg, #FF4B4B, #FF6B6B);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #888;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #1E1E1E;
        border-radius: 12px;
        padding: 1rem;
        border-left: 4px solid #FF4B4B;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# --------------------------------------------------
# HEADER
# --------------------------------------------------
st.markdown('<div class="main-header">🛡️ AI-Powered Network Intrusion Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Real-time threat detection using ensemble ML models on network traffic data</div>', unsafe_allow_html=True)

# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------
st.sidebar.image("https://img.icons8.com/clouds/200/security-checked.png", width=120)
st.sidebar.title("⚙️ Control Panel")

# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

@st.cache_data(show_spinner=False)
def load_csv(file, max_rows):
    """Load CSV with configurable row limit."""
    return pd.read_csv(file, nrows=max_rows)


def clean_dataframe(df):
    """Standardize column names and clean data."""
    df.columns = (
        df.columns.astype(str)
        .str.strip()
        .str.replace(" ", "_")
        .str.replace("/", "_per_")
    )
    return df


def data_quality_report(df):
    """Generate a data quality summary."""
    total = len(df)
    missing = df.isnull().sum().sum()
    duplicates = df.duplicated().sum()
    numeric_cols = df.select_dtypes(include=[np.number]).shape[1]
    return {
        "Total Rows": total,
        "Total Columns": df.shape[1],
        "Missing Values": missing,
        "Missing %": f"{(missing / (total * df.shape[1])) * 100:.2f}%",
        "Duplicate Rows": duplicates,
        "Numeric Columns": numeric_cols,
    }


IMPORTANT_FEATURES = [
    "Destination_Port",
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Backward_Packets",
    "Total_Length_of_Fwd_Packets",
    "Total_Length_of_Bwd_Packets",
    "Fwd_Packet_Length_Max",
    "Fwd_Packet_Length_Mean",
    "Bwd_Packet_Length_Max",
    "Bwd_Packet_Length_Mean",
    "Packet_Length_Mean",
    "Packet_Length_Std",
    "Packet_Length_Variance",
    "Flow_Bytes_per_s",
    "Flow_Packets_per_s",
    "Flow_IAT_Mean",
    "Flow_IAT_Std",
    "Fwd_IAT_Total",
    "Bwd_IAT_Total",
    "Active_Mean",
    "Idle_Mean",
    "SYN_Flag_Count",
    "ACK_Flag_Count",
    "PSH_Flag_Count",
    "RST_Flag_Count",
    "URG_Flag_Count",
    "Average_Packet_Size",
    "Avg_Fwd_Segment_Size",
    "Avg_Bwd_Segment_Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Subflow_Fwd_Bytes",
    "Subflow_Bwd_Bytes",
]


def get_model(name, n_estimators, max_depth):
    """Return a classifier by name."""
    if name == "Random Forest":
        return RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=10,
            n_jobs=-1,
            random_state=42,
        )
    elif name == "XGBoost" and XGBOOST_AVAILABLE:
        return XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=0.1,
            use_label_encoder=False,
            eval_metric="mlogloss",
            n_jobs=-1,
            random_state=42,
            verbosity=0,
        )
    else:
        return DecisionTreeClassifier(
            max_depth=max_depth,
            min_samples_split=10,
            random_state=42,
        )


def plot_confusion_matrix(cm, labels):
    """Styled confusion matrix heatmap."""
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Reds",
        xticklabels=labels, yticklabels=labels, ax=ax,
        linewidths=0.5, linecolor="grey",
    )
    ax.set_xlabel("Predicted", fontsize=11)
    ax.set_ylabel("Actual", fontsize=11)
    ax.set_title("Confusion Matrix", fontsize=13, fontweight="bold")
    plt.tight_layout()
    return fig


def plot_roc_curve(y_test, y_proba, class_labels):
    """Plot ROC curve (binary or multiclass one-vs-rest)."""
    fig, ax = plt.subplots(figsize=(5, 4))
    n_classes = len(class_labels)

    if n_classes == 2:
        fpr, tpr, _ = roc_curve(y_test, y_proba[:, 1])
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, color="#FF4B4B", lw=2, label=f"AUC = {roc_auc:.3f}")
    else:
        from sklearn.preprocessing import label_binarize
        y_bin = label_binarize(y_test, classes=range(n_classes))
        for i in range(min(n_classes, 6)):  # limit to 6 for readability
            if y_bin[:, i].sum() == 0:
                continue
            fpr, tpr, _ = roc_curve(y_bin[:, i], y_proba[:, i])
            roc_auc = auc(fpr, tpr)
            ax.plot(fpr, tpr, lw=1.5, label=f"{class_labels[i]} (AUC={roc_auc:.2f})")

    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve", fontsize=13, fontweight="bold")
    ax.legend(fontsize=8, loc="lower right")
    plt.tight_layout()
    return fig


def plot_feature_importance(model, feature_names, top_n=15):
    """Bar chart of top feature importances."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]
    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]

    fig, ax = plt.subplots(figsize=(6, 4))
    colors = plt.cm.Reds(np.linspace(0.4, 0.9, len(top_features)))[::-1]
    ax.barh(range(len(top_features)), top_importances[::-1], color=colors)
    ax.set_yticks(range(len(top_features)))
    ax.set_yticklabels(top_features[::-1], fontsize=9)
    ax.set_xlabel("Importance Score")
    ax.set_title(f"Top {top_n} Feature Importances", fontsize=13, fontweight="bold")
    plt.tight_layout()
    return fig


def plot_class_distribution(y, labels):
    """Pie chart of class distribution."""
    unique, counts = np.unique(y, return_counts=True)
    display_labels = [labels[u] if u < len(labels) else str(u) for u in unique]
    fig, ax = plt.subplots(figsize=(4, 4))
    colors = plt.cm.Set2(np.linspace(0, 1, len(unique)))
    wedges, texts, autotexts = ax.pie(
        counts, labels=display_labels, autopct="%1.1f%%",
        colors=colors, startangle=90, pctdistance=0.85,
    )
    centre_circle = plt.Circle((0, 0), 0.55, fc="white")
    ax.add_artist(centre_circle)
    ax.set_title("Class Distribution", fontsize=13, fontweight="bold")
    plt.tight_layout()
    return fig


def plot_precision_recall(y_test, y_proba, class_labels):
    """Precision-Recall curve."""
    fig, ax = plt.subplots(figsize=(5, 4))
    n_classes = len(class_labels)

    if n_classes == 2:
        prec, rec, _ = precision_recall_curve(y_test, y_proba[:, 1])
        ax.plot(rec, prec, color="#FF4B4B", lw=2)
    else:
        from sklearn.preprocessing import label_binarize
        y_bin = label_binarize(y_test, classes=range(n_classes))
        for i in range(min(n_classes, 6)):
            if y_bin[:, i].sum() == 0:
                continue
            prec, rec, _ = precision_recall_curve(y_bin[:, i], y_proba[:, i])
            ax.plot(rec, prec, lw=1.5, label=f"{class_labels[i]}")

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve", fontsize=13, fontweight="bold")
    if n_classes > 2:
        ax.legend(fontsize=8, loc="lower left")
    plt.tight_layout()
    return fig


# ==================================================
# MAIN APP FLOW
# ==================================================

uploaded_file = st.sidebar.file_uploader("📂 Upload Network Traffic CSV", type=["csv"])
max_rows = st.sidebar.slider("Max rows to load", 5000, 100000, 20000, step=5000)

if uploaded_file is not None:
    # --------------------------------------------------
    # LOAD & CLEAN
    # --------------------------------------------------
    with st.spinner("Loading dataset..."):
        df = load_csv(uploaded_file, max_rows)
    df = clean_dataframe(df)

    st.success(f"✅ Loaded **{len(df):,}** rows × **{df.shape[1]}** columns")

    # --------------------------------------------------
    # TABS
    # --------------------------------------------------
    tab_data, tab_train, tab_metrics, tab_simulate, tab_export = st.tabs([
        "📊 Data Explorer",
        "🤖 Model Training",
        "📈 Performance Metrics",
        "🔍 Live Traffic Simulator",
        "💾 Export & Logs",
    ])

    # ==========  TAB 1: DATA EXPLORER  ==========
    with tab_data:
        st.subheader("📋 Data Quality Report")
        quality = data_quality_report(df)
        cols = st.columns(len(quality))
        for i, (k, v) in enumerate(quality.items()):
            cols[i].metric(k, v)

        st.divider()

        col_preview, col_stats = st.columns([3, 2])
        with col_preview:
            st.subheader("Dataset Preview")
            st.dataframe(df.head(20), use_container_width=True)

        with col_stats:
            st.subheader("Statistical Summary")
            st.dataframe(df.describe().T.round(2), use_container_width=True)

    # --------------------------------------------------
    # LABEL & FEATURE SELECTION (Sidebar)
    # --------------------------------------------------
    st.sidebar.divider()
    st.sidebar.subheader("🎯 Target & Features")

    label_column = st.sidebar.selectbox(
        "Label / Target Column",
        df.columns.unique().tolist(),
        index=len(df.columns) - 1,  # default to last column
    )

    # Filter available features
    available_features = [c for c in IMPORTANT_FEATURES if c in df.columns]

    if not available_features:
        # Fallback: use all numeric columns except label
        available_features = [
            c for c in df.select_dtypes(include=[np.number]).columns
            if c != label_column
        ]

    use_custom_features = st.sidebar.checkbox("Custom feature selection", value=False)
    if use_custom_features:
        selected_features = st.sidebar.multiselect(
            "Select features",
            [c for c in df.columns if c != label_column],
            default=available_features[:15],
        )
    else:
        selected_features = available_features

    if not selected_features:
        st.error("No features selected or found. Please check your dataset columns.")
        st.stop()

    # --------------------------------------------------
    # PREPARE DATA
    # --------------------------------------------------
    work_df = df[selected_features + [label_column]].copy()

    # Safe label extraction (handles both Series and DataFrame)
    y_raw = work_df[label_column]
    if isinstance(y_raw, pd.DataFrame):
        y_raw = y_raw.iloc[:, 0]

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw.astype(str))
    class_labels = label_encoder.classes_.tolist()

    X = work_df.drop(columns=[label_column])
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Normalize
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

    # Show class distribution in data tab
    with tab_data:
        st.divider()
        col_dist, col_corr = st.columns(2)
        with col_dist:
            fig_dist = plot_class_distribution(y, class_labels)
            st.pyplot(fig_dist)
        with col_corr:
            st.subheader("Feature Correlation (Top 10)")
            top_cols = X.columns[:10]
            fig_corr, ax_corr = plt.subplots(figsize=(6, 5))
            sns.heatmap(
                X[top_cols].corr(), annot=True, fmt=".1f",
                cmap="coolwarm", ax=ax_corr, vmin=-1, vmax=1,
                linewidths=0.5,
            )
            ax_corr.set_title("Feature Correlation Matrix", fontsize=13, fontweight="bold")
            plt.tight_layout()
            st.pyplot(fig_corr)

    # --------------------------------------------------
    # SIDEBAR: MODEL CONFIG
    # --------------------------------------------------
    st.sidebar.divider()
    st.sidebar.subheader("🧠 Model Configuration")

    model_choices = ["Random Forest", "Decision Tree"]
    if XGBOOST_AVAILABLE:
        model_choices.insert(1, "XGBoost")

    model_name = st.sidebar.selectbox("Algorithm", model_choices)
    split_size = st.sidebar.slider("Training split (%)", 60, 90, 80)
    n_estimators = st.sidebar.slider("Estimators / Trees", 10, 200, 50)
    max_depth = st.sidebar.slider("Max tree depth", 3, 20, 8)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=(100 - split_size) / 100,
        random_state=42,
        stratify=y if len(np.unique(y)) > 1 else None,
    )

    # ==========  TAB 2: MODEL TRAINING  ==========
    with tab_train:
        st.subheader(f"🤖 Train: {model_name}")

        col_info, col_action = st.columns([2, 1])
        with col_info:
            st.markdown(f"""
            | Parameter | Value |
            |-----------|-------|
            | Algorithm | **{model_name}** |
            | Features | **{len(selected_features)}** |
            | Train samples | **{len(X_train):,}** |
            | Test samples | **{len(X_test):,}** |
            | Classes | **{len(class_labels)}** ({', '.join(class_labels[:5])}) |
            | Estimators | **{n_estimators}** |
            | Max Depth | **{max_depth}** |
            """)

        with col_action:
            train_clicked = st.button("🚀 Train Model", type="primary", use_container_width=True)

            if train_clicked:
                progress_bar = st.progress(0, text="Initializing...")
                start_time = time.time()

                progress_bar.progress(10, text="Building model...")
                model = get_model(model_name, n_estimators, max_depth)

                progress_bar.progress(30, text="Training in progress...")
                model.fit(X_train, y_train)

                progress_bar.progress(80, text="Evaluating...")
                elapsed = time.time() - start_time

                st.session_state["model"] = model
                st.session_state["model_name"] = model_name
                st.session_state["train_time"] = elapsed
                st.session_state["class_labels"] = class_labels
                st.session_state["feature_names"] = list(X.columns)
                st.session_state["scaler"] = scaler
                st.session_state["label_encoder"] = label_encoder

                progress_bar.progress(100, text="Done!")
                st.success(f"✅ Training complete in **{elapsed:.2f}s**")
                st.balloons()

            if "model" in st.session_state:
                st.info(f"Active model: **{st.session_state.get('model_name', 'N/A')}** "
                        f"(trained in {st.session_state.get('train_time', 0):.2f}s)")

    # ==========  TAB 3: PERFORMANCE METRICS  ==========
    with tab_metrics:
        if "model" not in st.session_state:
            st.warning("⚠️ Please train a model first (Tab 2).")
        else:
            model = st.session_state["model"]
            y_pred = model.predict(X_test)
            y_proba = model.predict_proba(X_test)

            acc = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred, average="weighted")
            prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
            rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
            threats = int(np.sum(y_pred != 0)) if len(class_labels) > 1 else 0

            # KPI Cards
            st.subheader("📊 Key Performance Indicators")
            k1, k2, k3, k4, k5 = st.columns(5)
            k1.metric("Accuracy", f"{acc * 100:.2f}%")
            k2.metric("F1 Score", f"{f1:.4f}")
            k3.metric("Precision", f"{prec:.4f}")
            k4.metric("Recall", f"{rec:.4f}")
            k5.metric("Threats Found", f"{threats:,}")

            st.divider()

            # Charts Row 1
            chart1, chart2 = st.columns(2)
            with chart1:
                cm = confusion_matrix(y_test, y_pred)
                cm_labels = class_labels if len(class_labels) <= 10 else [str(i) for i in range(len(class_labels))]
                fig_cm = plot_confusion_matrix(cm, cm_labels)
                st.pyplot(fig_cm)

            with chart2:
                fig_roc = plot_roc_curve(y_test, y_proba, class_labels)
                st.pyplot(fig_roc)

            st.divider()

            # Charts Row 2
            chart3, chart4 = st.columns(2)
            with chart3:
                if hasattr(model, "feature_importances_"):
                    fig_fi = plot_feature_importance(model, list(X.columns))
                    st.pyplot(fig_fi)
                else:
                    st.info("Feature importances not available for this model type.")

            with chart4:
                fig_pr = plot_precision_recall(y_test, y_proba, class_labels)
                st.pyplot(fig_pr)

            st.divider()

            # Classification Report
            st.subheader("📝 Detailed Classification Report")
            report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
            report_df = pd.DataFrame(report_dict).T.round(4)
            st.dataframe(report_df, use_container_width=True)

    # ==========  TAB 4: LIVE TRAFFIC SIMULATOR  ==========
    with tab_simulate:
        st.subheader("🔍 Analyze Network Traffic")

        if "model" not in st.session_state:
            st.warning("⚠️ Please train a model first (Tab 2).")
        else:
            model = st.session_state["model"]

            sim_mode = st.radio(
                "Input Method",
                ["Manual Input", "Random Sample from Test Data"],
                horizontal=True,
            )

            if sim_mode == "Manual Input":
                input_data = []
                cols = st.columns(4)
                for i, col_name in enumerate(X.columns):
                    val = cols[i % 4].number_input(
                        col_name,
                        value=float(X[col_name].median()),
                        format="%.4f",
                        key=f"sim_{col_name}",
                    )
                    input_data.append(val)
                sample_raw = np.array([input_data], dtype=np.float64)

            else:
                if st.button("🎲 Generate Random Sample"):
                    idx = np.random.randint(0, len(X_test))
                    st.session_state["random_sample_idx"] = idx

                if "random_sample_idx" in st.session_state:
                    idx = st.session_state["random_sample_idx"]
                    sample_display = X_test.iloc[idx]
                    st.dataframe(sample_display.to_frame().T, use_container_width=True)
                    sample_raw = X_test.iloc[[idx]].values
                    true_label = y_test[idx]
                    st.caption(f"True label: **{class_labels[true_label]}**")
                else:
                    sample_raw = None

            st.divider()

            if st.button("⚡ Analyze Traffic", type="primary"):
                if sample_raw is not None:
                    pred = model.predict(sample_raw)
                    proba = model.predict_proba(sample_raw)[0]
                    confidence = np.max(proba) * 100
                    predicted_class = class_labels[pred[0]] if pred[0] < len(class_labels) else str(pred[0])

                    st.divider()

                    if predicted_class.upper() == "BENIGN" or pred[0] == 0:
                        st.success(f"✅ **BENIGN** — Normal traffic detected")
                    else:
                        st.error(f"🚨 **ALERT: INTRUSION DETECTED** — Type: **{predicted_class}**")

                    r1, r2, r3 = st.columns(3)
                    r1.metric("Predicted Class", predicted_class)
                    r2.metric("Confidence", f"{confidence:.1f}%")
                    r3.metric("Risk Level", "HIGH" if pred[0] != 0 else "LOW")

                    # Confidence breakdown
                    st.subheader("Confidence Breakdown")
                    proba_df = pd.DataFrame({
                        "Class": class_labels[:len(proba)],
                        "Probability": proba[:len(class_labels)],
                    }).sort_values("Probability", ascending=True)

                    fig_bar, ax_bar = plt.subplots(figsize=(6, 3))
                    colors = ["#FF4B4B" if c != "BENIGN" else "#4CAF50" for c in proba_df["Class"]]
                    ax_bar.barh(proba_df["Class"], proba_df["Probability"], color=colors)
                    ax_bar.set_xlabel("Probability")
                    ax_bar.set_title("Prediction Confidence", fontweight="bold")
                    plt.tight_layout()
                    st.pyplot(fig_bar)

                    # Log prediction
                    if "prediction_log" not in st.session_state:
                        st.session_state["prediction_log"] = []
                    st.session_state["prediction_log"].append({
                        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "Prediction": predicted_class,
                        "Confidence": f"{confidence:.1f}%",
                        "Risk": "HIGH" if pred[0] != 0 else "LOW",
                    })
                else:
                    st.warning("Generate a sample first.")

    # ==========  TAB 5: EXPORT & LOGS  ==========
    with tab_export:
        st.subheader("💾 Export Trained Model")

        if "model" in st.session_state:
            col_exp1, col_exp2 = st.columns(2)

            with col_exp1:
                # Export model
                buf = io.BytesIO()
                joblib.dump(st.session_state["model"], buf)
                buf.seek(0)
                st.download_button(
                    "📥 Download Model (.joblib)",
                    data=buf,
                    file_name=f"nids_model_{st.session_state.get('model_name', 'rf').replace(' ', '_').lower()}.joblib",
                    mime="application/octet-stream",
                )

            with col_exp2:
                # Export scaler
                buf2 = io.BytesIO()
                joblib.dump(st.session_state.get("scaler"), buf2)
                buf2.seek(0)
                st.download_button(
                    "📥 Download Scaler (.joblib)",
                    data=buf2,
                    file_name="nids_scaler.joblib",
                    mime="application/octet-stream",
                )
        else:
            st.info("Train a model to enable export.")

        st.divider()

        st.subheader("📜 Prediction Log")
        if "prediction_log" in st.session_state and st.session_state["prediction_log"]:
            log_df = pd.DataFrame(st.session_state["prediction_log"])
            st.dataframe(log_df, use_container_width=True)

            csv_log = log_df.to_csv(index=False)
            st.download_button(
                "📥 Download Prediction Log (.csv)",
                data=csv_log,
                file_name="prediction_log.csv",
                mime="text/csv",
            )
        else:
            st.info("No predictions logged yet. Use the Live Traffic Simulator first.")

    # Memory cleanup
    gc.collect()

else:
    # --------------------------------------------------
    # LANDING PAGE (no file uploaded)
    # --------------------------------------------------
    st.divider()

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown("### 📂 Step 1: Upload Data")
        st.markdown("Upload a CIC-IDS2017/2018 CSV file using the sidebar uploader.")

    with col_b:
        st.markdown("### 🤖 Step 2: Train Model")
        st.markdown("Choose an algorithm (Random Forest, XGBoost, Decision Tree) and train.")

    with col_c:
        st.markdown("### 🔍 Step 3: Detect Threats")
        st.markdown("Analyze live traffic or random samples with confidence scoring.")

    st.divider()

    st.markdown("""
    #### 🔗 Compatible Datasets
    - [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — Canadian Institute for Cybersecurity
    - [CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) — Updated with newer attack patterns
    - Any CSV with network flow features and a label column

    #### 🛡️ Supported Attack Types
    `DDoS` · `DoS Hulk` · `DoS GoldenEye` · `DoS Slowloris` · `PortScan` · `Bot` · `FTP-Patator` · `SSH-Patator` · `Web Attack` · `Infiltration` · `Heartbleed`
    """)

    st.info("👈 Upload a CSV file from the sidebar to begin.")
