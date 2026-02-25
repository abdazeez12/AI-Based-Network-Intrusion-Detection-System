# 🛡️ AI-Powered Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.54-FF4B4B?logo=streamlit&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8-F7931E?logo=scikit-learn&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-3.2-189FDD?logo=xgboost&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-2.3-150458?logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-2.4-013243?logo=numpy&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-3.10-11557C)
![Seaborn](https://img.shields.io/badge/Seaborn-0.13-76B7B2)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📖 Introduction

**AI-Powered Network Intrusion Detection System (NIDS)** is an interactive machine learning web application that detects malicious activity in computer network traffic. Built using Python and Streamlit, it provides a complete end-to-end pipeline — from raw data ingestion to real-time threat classification.

### What Problem Does It Solve?

Every day, millions of data packets flow through computer networks. Hidden within normal traffic (browsing, email, streaming) can be **cyberattacks** — DDoS floods, port scans, brute force logins, bot activity, and more. Manually monitoring network logs is impossible at scale.

This project uses **Machine Learning** to automatically learn the difference between **normal (BENIGN)** and **malicious (ATTACK)** traffic patterns, and then classify new, unseen traffic in real-time with confidence scores.

### How It Works

```
CSV Upload → Data Cleaning → Feature Selection → Model Training → Evaluation → Live Detection
```

1. **Upload** a network traffic CSV file (CIC-IDS2017/2018 format or similar)
2. **Explore** the dataset — view statistics, class distribution, data quality, and feature correlations
3. **Train** an ML model — choose between Random Forest, XGBoost, or Decision Tree with configurable hyperparameters
4. **Evaluate** — view accuracy, F1-score, precision, recall, confusion matrix, ROC curves, precision-recall curves, and feature importance rankings
5. **Simulate** — feed individual network packets into the trained model and get instant classification (BENIGN / Attack Type) with confidence percentages
6. **Export** — download the trained model (`.joblib`) for production deployment, and export prediction logs as CSV

### What the AI Detects

The system classifies network traffic into:
- ✅ **BENIGN** — Normal, safe traffic (web browsing, video streaming, emails)
- 🚨 **DDoS** — Distributed Denial of Service attacks
- 🚨 **DoS Hulk / GoldenEye / Slowloris** — Various Denial of Service attack variants
- 🚨 **PortScan** — Network reconnaissance/scanning
- 🚨 **Bot** — Botnet command & control traffic
- 🚨 **FTP-Patator / SSH-Patator** — Brute force login attacks
- 🚨 **Web Attack** — SQL Injection, XSS, Brute Force on web apps
- 🚨 **Infiltration** — Lateral movement inside a network
- 🚨 **Heartbleed** — OpenSSL vulnerability exploitation

---

## 📋 Table of Contents

- [Introduction](#-introduction)
- [Features](#-features)
- [Complete Tech Stack](#-complete-tech-stack)
- [Screenshots](#-screenshots)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Dataset](#-dataset)
- [ML Techniques Used](#-ml-techniques-used)
- [Project Structure](#-project-structure)
- [Future Improvements](#-future-improvements)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Multi-Model Support** | Random Forest, XGBoost, Decision Tree — train and compare algorithms |
| **Interactive Dashboard** | 5-tab Streamlit UI with sidebar controls and real-time updates |
| **Data Quality Audit** | Auto-detects missing values, duplicates, class imbalance, data types |
| **Smart Feature Selection** | Auto-selects 33 CIC-IDS features, or manual custom selection |
| **5 Performance Metrics** | Accuracy, F1 Score, Precision, Recall, Threat Count |
| **4 Visualizations** | Confusion Matrix, ROC Curve, Precision-Recall Curve, Feature Importance |
| **Class Distribution** | Donut chart showing BENIGN vs attack type breakdown |
| **Correlation Matrix** | Heatmap of top feature correlations |
| **Live Traffic Simulator** | Manual input or random sampling with real-time prediction |
| **Confidence Scoring** | `predict_proba()` — shows probability for each class, not just the label |
| **Attack Type Identification** | Maps prediction back to human-readable label (e.g., "DDoS", "Bot") |
| **Risk Level Assessment** | Categorizes predictions as HIGH / LOW risk |
| **Model Export** | Download trained model as `.joblib` for deployment |
| **Scaler Export** | Download fitted StandardScaler for consistent preprocessing |
| **Prediction Logging** | Timestamped audit trail of all predictions, exportable as CSV |
| **Feature Normalization** | StandardScaler preprocessing for consistent model performance |
| **Stratified Splitting** | Preserves class ratios in train/test split |

---

## 🛠️ Complete Tech Stack

### Core Language
| Technology | Version | Role |
|------------|---------|------|
| **Python** | 3.13 | Primary programming language for the entire application |

### Web Framework
| Technology | Version | Role |
|------------|---------|------|
| **Streamlit** | 1.54 | Full-stack web framework — handles frontend UI, sidebar controls, tabs, file uploads, buttons, sliders, metrics display, and server-side rendering. No HTML/CSS/JS needed. |

### Machine Learning & Data Science
| Technology | Version | Role |
|------------|---------|------|
| **scikit-learn** | 1.8 | Core ML library — provides `RandomForestClassifier`, `DecisionTreeClassifier`, `train_test_split`, `StandardScaler`, `LabelEncoder`, `accuracy_score`, `f1_score`, `precision_score`, `recall_score`, `confusion_matrix`, `classification_report`, `roc_curve`, `precision_recall_curve`, `auc` |
| **XGBoost** | 3.2 | Gradient boosting library — provides `XGBClassifier` for high-performance ensemble learning with regularization |
| **Pandas** | 2.3 | Data manipulation — CSV loading, DataFrame operations, column cleaning, type conversion, statistical summaries |
| **NumPy** | 2.4 | Numerical computing — array operations, random generation, infinity/NaN handling, data type casting |

### Data Visualization
| Technology | Version | Role |
|------------|---------|------|
| **Matplotlib** | 3.10 | Base plotting library — creates ROC curves, precision-recall curves, feature importance bar charts, confidence breakdown charts, custom colormaps |
| **Seaborn** | 0.13 | Statistical visualization — generates styled confusion matrix heatmaps and feature correlation heatmaps on top of matplotlib |

### Utilities
| Technology | Version | Role |
|------------|---------|------|
| **Joblib** | 1.5 | Model serialization — saves trained sklearn/XGBoost models and fitted scalers to `.joblib` binary format for download and reuse |

### Python Standard Library Modules Used
| Module | Role |
|--------|------|
| `time` | Training duration measurement |
| `gc` | Garbage collection for memory management after training |
| `io` | In-memory byte streams for model export (BytesIO) |
| `datetime` | Timestamps for prediction logging |

### Development & Deployment
| Tool | Role |
|------|------|
| **Git** | Version control |
| **GitHub** | Repository hosting & collaboration |
| **pip** | Package management |
| **venv** | Virtual environment isolation |

---

## 📸 Screenshots

### Landing Page
![Landing Page](screenshots/start.png)

### CSV Upload & Data Explorer
![CSV Upload](screenshots/csv.png)
![Dataset Preview](screenshots/dataset_preview.png)

### Model Training
![Model Training](screenshots/model_training.png)

### Performance Metrics
![Performance Metrics](screenshots/performance_matrix.png)

### Intrusion Detection Alert
![Intrusion Detected](screenshots/intrusion_detected.png)

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    STREAMLIT FRONTEND                     │
│  ┌──────────┬──────────┬──────────┬──────────┬─────────┐ │
│  │   Data   │  Model   │  Perf.   │  Live    │ Export  │ │
│  │ Explorer │ Training │ Metrics  │ Simulate │ & Logs  │ │
│  └────┬─────┴────┬─────┴────┬─────┴────┬─────┴───┬─────┘ │
│       │          │          │          │         │        │
│  ┌────▼──────────▼──────────▼──────────▼─────────▼──────┐ │
│  │              ML PIPELINE (scikit-learn)               │ │
│  │                                                       │ │
│  │  ┌─────────────┐   ┌──────────────┐   ┌───────────┐  │ │
│  │  │ Preprocess  │──▶│   Training   │──▶│ Inference  │  │ │
│  │  │             │   │              │   │            │  │ │
│  │  │ LabelEncoder│   │ RandomForest │   │ predict()  │  │ │
│  │  │ StdScaler   │   │ XGBoost      │   │ predict    │  │ │
│  │  │ NaN/Inf fix │   │ DecisionTree │   │  _proba()  │  │ │
│  │  └─────────────┘   └──────────────┘   └───────────┘  │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌───────────────────────────────────────────────────────┐ │
│  │           VISUALIZATION (matplotlib + seaborn)        │ │
│  │                                                       │ │
│  │  Confusion Matrix · ROC Curve · PR Curve · Feature    │ │
│  │  Importance · Class Distribution · Correlation Matrix │ │
│  │  Confidence Breakdown · Statistical Summary           │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              EXPORT (joblib + pandas)                  │ │
│  │                                                       │ │
│  │  Model .joblib · Scaler .joblib · Prediction Log CSV  │ │
│  └───────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/cazy8/AI-Based-Network-Intrusion-Detection-System.git
cd AI-Based-Network-Intrusion-Detection-System

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## 💡 Usage

```bash
# Run the Streamlit dashboard
streamlit run nids_main_csv.py
```

Then open your browser to `http://localhost:8501` and:

1. **Upload** a CIC-IDS CSV file via the sidebar (or use the included `sample_dataset.csv`)
2. **Explore** your data in the Data Explorer tab — view quality report, statistics, distributions
3. **Configure** model parameters in the sidebar — algorithm, split ratio, estimators, depth
4. **Train** the model by clicking "Train Model" and watch the progress bar
5. **Analyze** performance metrics — accuracy, F1, confusion matrix, ROC/PR curves
6. **Simulate** live traffic detection with confidence scores and risk levels
7. **Export** the trained model and prediction logs for production use

---

## 📂 Dataset

This project works with **CIC-IDS2017** and **CIC-IDS2018** datasets from the Canadian Institute for Cybersecurity. A synthetic **sample_dataset.csv** (5,000 rows) is included in the repo for quick testing.

| Dataset | Link | Size |
|---------|------|------|
| CIC-IDS2017 | [Download](https://www.unb.ca/cic/datasets/ids-2017.html) | ~6 GB |
| CIC-IDS2018 | [Download](https://www.unb.ca/cic/datasets/ids-2018.html) | ~16 GB |
| Sample (included) | `sample_dataset.csv` | 5,000 rows |

### Key Features Used from Dataset
| Feature | Description |
|---------|-------------|
| Destination Port | Target service port (80=HTTP, 443=HTTPS, 22=SSH) |
| Flow Duration | Total duration of the network flow (μs) |
| Total Fwd/Bwd Packets | Packet count in forward and backward direction |
| Packet Length Mean/Max/Std | Statistical properties of packet sizes |
| Flow Bytes/s | Data transfer rate |
| Flow Packets/s | Packet transmission rate |
| Flow IAT Mean/Std | Inter-arrival time between packets |
| SYN/ACK/PSH/RST/URG Flag Count | TCP flag statistics (key attack indicators) |
| Active/Idle Mean | Connection activity patterns |
| Init Win Bytes | Initial TCP window size (forward/backward) |

---

## 🧠 ML Techniques Used

### Algorithms
| Algorithm | Type | Strengths |
|-----------|------|-----------|
| **Random Forest** | Ensemble (Bagging) | Robust, handles noise well, provides feature importances, parallelizable |
| **XGBoost** | Ensemble (Boosting) | High accuracy, built-in regularization (L1/L2), handles imbalanced data |
| **Decision Tree** | Single Tree | Fast, interpretable, good baseline model |

### Preprocessing
| Technique | Purpose |
|-----------|---------|
| **LabelEncoder** | Converts text labels ("BENIGN", "DDoS") → numeric (0, 1, 2...) |
| **StandardScaler** | Normalizes features to zero mean, unit variance — prevents features with large ranges from dominating |
| **Inf/NaN Replacement** | Replaces infinity values and missing data with 0 for model stability |
| **Stratified Train/Test Split** | Ensures each class (BENIGN, DDoS, etc.) has proportional representation in both train and test sets |

### Evaluation Metrics
| Metric | What It Measures |
|--------|-----------------|
| **Accuracy** | % of all predictions that are correct |
| **F1 Score** | Harmonic mean of precision & recall (balanced metric) |
| **Precision** | Of all predicted attacks, how many are real attacks? (false positive rate) |
| **Recall** | Of all real attacks, how many did the model catch? (false negative rate) |
| **ROC-AUC** | Model's ability to distinguish between classes across all thresholds |
| **Confusion Matrix** | Detailed breakdown of correct vs incorrect predictions per class |

---

## 📁 Project Structure

```
AI-Based-Network-Intrusion-Detection-System/
├── nids_main_csv.py          # Main Streamlit application (500+ lines)
├── sample_dataset.csv        # Synthetic CIC-IDS test data (5,000 rows)
├── requirements.txt          # Python dependencies with version pins
├── .gitignore               # Git ignore rules
├── LICENSE                  # MIT License
├── README.md                # Project documentation (this file)
└── screenshots/             # App screenshots
    ├── start.png            # Landing page
    ├── csv.png              # CSV upload view
    ├── dataset_preview.png  # Data explorer
    ├── model_training.png   # Training interface
    ├── performance_matrix.png # Metrics dashboard
    └── intrusion_detected.png # Alert screen
```

---

## 🔮 Future Improvements

- [ ] Deep Learning model (LSTM / Autoencoder) for anomaly detection
- [ ] Real-time packet capture integration with Scapy / PyShark
- [ ] REST API endpoint with FastAPI for production deployment
- [ ] Docker containerization for easy deployment
- [ ] Database-backed prediction logging (SQLite / PostgreSQL)
- [ ] Model comparison dashboard — train and compare multiple models simultaneously
- [ ] SHAP explainability for individual predictions
- [ ] Email/Slack alerting on threat detection
- [ ] Batch prediction mode for large CSV files
- [ ] User authentication for multi-user environments

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with ❤️ using Python & Streamlit<br>
  <strong>⭐ Star this repo if you found it helpful!</strong>
</p>
