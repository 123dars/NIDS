import os
import joblib
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import datetime

base_dir = os.path.dirname(__file__)
MODEL_PATH = os.path.join(base_dir, "nids_model.pkl")
LABEL_PATH = os.path.join(base_dir, "label_encoder.pkl")

def get_protocol_name(proto_num):
    mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return mapping.get(proto_num, "Other")

def extract_features(packet):
    """Extract the exact same features as the live packet_sniffer.py"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)
        
        src_port = 0
        dst_port = 0
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        return {
            "timestamp": datetime.datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S'),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": get_protocol_name(protocol),
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": length
        }
    return None

def analyze_pcap_file(filepath):
    print(f"[*] Analyzing PCAP file: {filepath}")
    
    # 1. Load model
    if not os.path.exists(MODEL_PATH) or not os.path.exists(LABEL_PATH):
        raise FileNotFoundError(f"Model or Label Encoder file not found.")
    model = joblib.load(MODEL_PATH)
    le = joblib.load(LABEL_PATH)
    
    # 2. Parse packets
    packets = rdpcap(filepath)
    extracted = []
    
    for pkt in packets:
        feat = extract_features(pkt)
        if feat:
            extracted.append(feat)
            
    if not extracted:
        return {"stats": {"total": 0, "high": 0, "medium": 0, "normal": 0}, "alerts": []}
        
    df = pd.DataFrame(extracted)
    
    # Transform protocol, safely defaulting 'Other' or unseen to an existing class
    known_classes = list(le.classes_)
    df["protocol"] = df["protocol"].apply(lambda x: x if x in known_classes else known_classes[0])
    df["protocol_enc"] = le.transform(df["protocol"])
    
    # 3. Predict
    features = ["protocol_enc", "src_port", "dst_port", "packet_size"]
    X = df[features].fillna(0)
    
    predictions = model.predict(X)
    scores = model.score_samples(X)
    
    # 4. Map results
    df["alert"] = predictions == -1
    # Convert raw score to positive risk score
    df["risk_score"] = -scores
    
    # Define severity based on risk_score
    def get_severity(row):
        if not row["alert"]: return "NORMAL"
        # Adjusted threshold so scores around 0.76 trigger the High Risk red badge
        if row["risk_score"] > 0.7: return "HIGH"
        if row["risk_score"] > 0.6: return "MEDIUM"
        return "LOW"
        
    df["severity"] = df.apply(get_severity, axis=1)
    
    # Calculate stats
    stats = {
        "total": int(len(df)),
        "high": int(len(df[df["severity"] == "HIGH"])),
        "medium": int(len(df[df["severity"] == "MEDIUM"])),
        "low": int(len(df[df["severity"] == "LOW"])),
        "normal": int(len(df[df["severity"] == "NORMAL"]))
    }
    
    # Extract only the alerts to return to the frontend
    alerts_df = df[df["alert"] == True].copy()
    alerts = alerts_df.to_dict(orient="records")
    
    return {
        "stats": stats,
        "alerts": alerts
    }

if __name__ == "__main__":
    # Test script locally
    import sys
    if len(sys.argv) > 1:
        res = analyze_pcap_file(sys.argv[1])
        print(f"Stats: {res['stats']}")
        print(f"Found {len(res['alerts'])} alerts.")
