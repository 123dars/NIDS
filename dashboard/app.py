#!/usr/bin/env python3
# dashboard/app.py
# Step 5 — Flask web dashboard for live monitoring

from flask import Flask, render_template, jsonify
import pandas as pd
import os
import json
from datetime import datetime

app = Flask(__name__)

ALERTS_FILE  = "../data/alerts.csv"
PACKETS_FILE = "../data/packets.csv"
SNORT_FILE   = "../data/snort_alerts.csv"

def load_csv(filepath):
    if os.path.isfile(filepath):
        return pd.read_csv(filepath)
    return pd.DataFrame()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    df = load_csv(ALERTS_FILE)
    if df.empty:
        return jsonify({"total": 0, "high": 0, "medium": 0, "low": 0, "normal": 0})

    return jsonify({
        "total":   int(len(df)),
        "high":    int(len(df[df["severity"] == "HIGH"])),
        "medium":  int(len(df[df["severity"] == "MEDIUM"])),
        "low":     int(len(df[df["severity"] == "LOW"])),
        "normal":  int(len(df[df["severity"] == "NORMAL"])),
    })

@app.route("/api/alerts")
def alerts():
    df = load_csv(ALERTS_FILE)
    if df.empty:
        return jsonify([])

    # Return only flagged packets, most recent first
    flagged = df[df["alert"] == True].copy()
    flagged = flagged.sort_values("timestamp", ascending=False).head(100)
    cols = ["timestamp","src_ip","dst_ip","protocol","dst_port","severity","risk_score"]
    cols = [c for c in cols if c in flagged.columns]
    return jsonify(flagged[cols].fillna("").to_dict(orient="records"))

@app.route("/api/packets")
def packets():
    df = load_csv(PACKETS_FILE)
    if df.empty:
        return jsonify([])
    recent = df.sort_values("timestamp", ascending=False).head(50)
    return jsonify(recent.fillna("").to_dict(orient="records"))

@app.route("/api/snort")
def snort_alerts():
    df = load_csv(SNORT_FILE)
    if df.empty:
        return jsonify([])
    return jsonify(df.fillna("").to_dict(orient="records"))

@app.route("/api/protocol_counts")
def protocol_counts():
    df = load_csv(PACKETS_FILE)
    if df.empty:
        return jsonify({})
    counts = df["protocol"].value_counts().to_dict()
    return jsonify(counts)

@app.route("/api/osint/<ip>")
def osint(ip):
    # Highly realistic mock of AbuseIPDB API response
    # Use the IP address string to deterministically generate a score
    import hashlib
    hash_val = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    
    # "192.168" or local IPs are clean
    if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("127."):
        return jsonify({
            "ip": ip,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "usageType": "Local Network"
        })
        
    # Generate random but consistent threat intel for external IPs
    score = hash_val % 100
    
    # Bias the score so ~80% are clean, 10% suspicious, 10% highly malicious
    if score < 80:
        score = 0
    elif score < 90:
        score = (score % 40) + 20 # 20-60
    else:
        score = (score % 20) + 80 # 80-100
        
    countries = ["US", "RU", "CN", "BR", "NL", "DE", "GB", "IR", "KP"]
    country = countries[hash_val % len(countries)]
    
    usage_types = ["Data Center/Web Hosting", "Fixed Line ISP", "Mobile ISP", "Commercial"]
    usage = usage_types[hash_val % len(usage_types)]
    
    return jsonify({
        "ip": ip,
        "abuseConfidenceScore": score,
        "countryCode": country,
        "usageType": usage
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting NIDS Dashboard at http://0.0.0.0:{port}")
    app.run(debug=True, host="0.0.0.0", port=port)
