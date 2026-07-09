#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import random

base_dir = os.path.dirname(__file__)
MODEL_FILE = os.path.join(base_dir, "nids_model.pkl")
LABEL_FILE = os.path.join(base_dir, "label_encoder.pkl")
os.makedirs(os.path.join(base_dir, "../data"), exist_ok=True)

def generate_synthetic_data(n_samples=5000, anomaly_ratio=0.05):
    print(f"[*] Generating {n_samples} synthetic packets for training...")
    protocols = ["TCP", "UDP", "ICMP", "OTHER"]
    data = []
    labels = []
    
    n_anomalies = int(n_samples * anomaly_ratio)
    n_normal = n_samples - n_anomalies
    
    # Generate normal traffic
    for _ in range(n_normal):
        data.append({
            "protocol": random.choice(["TCP", "UDP"]),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53]), # standard web/dns
            "packet_size": random.randint(40, 1500)
        })
        labels.append(1) # 1 is normal in IsolationForest
        
    # Generate anomalous traffic (e.g., weird ports, huge packets)
    for _ in range(n_anomalies):
        data.append({
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "src_port": random.randint(1, 1023), # privileged
            "dst_port": random.choice([22, 23, 445, 3389, 4444]), # SSH, Telnet, SMB, RDP, shells
            "packet_size": random.randint(1500, 5000) # unusually large
        })
        labels.append(-1) # -1 is anomaly in IsolationForest
        
    df = pd.DataFrame(data)
    y_true = np.array(labels)
    return df, y_true

def train_and_evaluate():
    df, y_true = generate_synthetic_data()
    
    # Preprocess
    le = LabelEncoder()
    df["protocol_enc"] = le.fit_transform(df["protocol"])
    X = df[["protocol_enc", "src_port", "dst_port", "packet_size"]]
    
    print("[*] Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)
    
    print("[*] Evaluating model...")
    y_pred = model.predict(X)
    
    print("\n--- Model Evaluation Report ---")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print("\nClassification Report (1=Normal, -1=Anomaly):")
    print(classification_report(y_true, y_pred))
    
    # Save model and label encoder
    joblib.dump(model, MODEL_FILE)
    joblib.dump(le, LABEL_FILE)
    print(f"[*] Model saved to {MODEL_FILE}")
    print(f"[*] Label Encoder saved to {LABEL_FILE}")

if __name__ == "__main__":
    train_and_evaluate()
