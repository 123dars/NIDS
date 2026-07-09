#!/usr/bin/env python3
# ml/anomaly_detector.py
# Step 3 — Train Isolation Forest model and detect anomalies

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.models import SessionLocal, Packet

base_dir = os.path.dirname(__file__)
MODEL_FILE = os.path.join(base_dir, "nids_model.pkl")

SUSPICIOUS_PORTS = {22, 23, 3389, 445, 135, 137, 138, 139, 4444, 6666, 31337}

def load_and_preprocess(session):
    # Fetch all packets that haven't been analyzed yet (severity IS NULL)
    packets = session.query(Packet).filter(Packet.severity == None).all()
    if not packets:
        return None, None, None, None

    # Convert to DataFrame for ML
    data = []
    for p in packets:
        data.append({
            "id": p.id,
            "protocol": p.protocol,
            "src_port": p.src_port,
            "dst_port": p.dst_port,
            "packet_size": p.packet_size
        })
    df = pd.DataFrame(data)

    # Encode protocol as number
    le = LabelEncoder()
    # Safely fit the known labels plus any we find
    known_labels = ["TCP", "UDP", "ICMP", "OTHER"]
    le.fit(known_labels + list(df["protocol"].unique()))
    df["protocol_enc"] = le.transform(df["protocol"])

    # Feature columns for ML
    features = ["protocol_enc", "src_port", "dst_port", "packet_size"]
    X = df[features].fillna(0)

    return df, X, le, packets

# Training function removed. Use ml/train_model.py for training.

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
    session = SessionLocal()
    try:
        df, X, le, packets = load_and_preprocess(session)
        if df is None or len(df) == 0:
            return

        if os.path.isfile(MODEL_FILE):
            model = joblib.load(MODEL_FILE)
        else:
            print(f"[!] No model found at {MODEL_FILE}. Please run ml/train_model.py first.")
            return

        print(f"[*] Running anomaly detection on {len(df)} packets...")
        df = detect_anomalies(df, X, model)
        
        # Threat intel simulation function mapping
        def get_threat_intel(severity, port):
            if severity != "HIGH" and severity != "MEDIUM":
                return None, None, None
            # Fake OSINT mappings
            if port in [22, 23]:
                return "APT29", "AS12345 (Evil Corp)", "Russia"
            if port in [4444, 31337]:
                return "Lazarus Group", "AS666 (HackerNet)", "North Korea"
            if port == 3389:
                return "FIN7", "AS777 (Bulletproof Hosting)", "Unknown"
            return "Unknown Actor", "AS000", "Unknown"

        # Update DB rows
        for i, p in enumerate(packets):
            row = df.iloc[i]
            p.protocol_enc = int(row["protocol_enc"])
            p.anomaly = int(row["anomaly"])
            p.risk_score = float(row["risk_score"])
            p.suspicious_port = bool(row["suspicious_port"])
            p.alert = bool(row["alert"])
            p.severity = row["severity"]
            
            # Enrich with Threat Intel
            actor, asn, loc = get_threat_intel(p.severity, p.dst_port)
            p.threat_actor = actor
            p.asn = asn
            p.location = loc

        session.commit()
        
        alerts_count = len(df[df["alert"] == True])
        if alerts_count > 0:
            print(f"[!] Updated {len(packets)} packets. Found {alerts_count} suspicious packets.")
            
    except Exception as e:
        print(f"[!] Error in detection: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    run_detection()
