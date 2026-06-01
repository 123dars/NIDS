#!/usr/bin/env python3
# ml/anomaly_detector.py
# Step 3 — Train Isolation Forest model and detect anomalies

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib
import os

MODEL_FILE = "ml/nids_model.pkl"
DATA_FILE  = "data/packets.csv"
OUTPUT_FILE = "data/alerts.csv"

SUSPICIOUS_PORTS = {22, 23, 3389, 445, 135, 137, 138, 139, 4444, 6666, 31337}

def load_and_preprocess(filepath):
    df = pd.read_csv(filepath)

    # Encode protocol as number
    le = LabelEncoder()
    df["protocol_enc"] = le.fit_transform(df["protocol"])

    # Feature columns for ML
    features = ["protocol_enc", "src_port", "dst_port", "packet_size"]
    X = df[features].fillna(0)

    return df, X, le

def train_model(X):
    print("[*] Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,   # assume 5% of traffic is suspicious
        random_state=42
    )
    model.fit(X)
    joblib.dump(model, MODEL_FILE)
    print(f"[*] Model saved to {MODEL_FILE}")
    return model

def detect_anomalies(df, X, model):
    predictions = model.predict(X)        # -1 = anomaly, 1 = normal
    scores      = model.decision_function(X)

    df["anomaly"]   = predictions
    df["risk_score"] = np.round((1 - scores) * 50, 2)  # 0–100 scale

    # Extra rule-based checks on top of ML
    df["suspicious_port"] = df["dst_port"].apply(lambda p: p in SUSPICIOUS_PORTS)

    df["alert"] = (df["anomaly"] == -1) | df["suspicious_port"]
    df["severity"] = df.apply(classify_severity, axis=1)

    return df

def classify_severity(row):
    if row["risk_score"] > 75 or row["suspicious_port"]:
        return "HIGH"
    elif row["risk_score"] > 50:
        return "MEDIUM"
    elif row["anomaly"] == -1:
        return "LOW"
    return "NORMAL"

def run_detection():
    if not os.path.isfile(DATA_FILE):
        print(f"[!] No data file found at {DATA_FILE}. Run sniffer first.")
        return

    print(f"[*] Loading packet data from {DATA_FILE}...")
    df, X, le = load_and_preprocess(DATA_FILE)

    if os.path.isfile(MODEL_FILE):
        print("[*] Loading existing model...")
        model = joblib.load(MODEL_FILE)
    else:
        model = train_model(X)

    print("[*] Running anomaly detection...")
    df = detect_anomalies(df, X, model)

    alerts = df[df["alert"] == True]
    print(f"\n[!] Total packets analysed : {len(df)}")
    print(f"[!] Suspicious packets found: {len(alerts)}")

    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[*] Full results saved to {OUTPUT_FILE}\n")

    if not alerts.empty:
        print("=== TOP ALERTS ===")
        print(alerts[["timestamp","src_ip","dst_ip","protocol","dst_port","severity","risk_score"]].head(10).to_string(index=False))

if __name__ == "__main__":
    run_detection()
