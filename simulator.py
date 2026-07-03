import time
import random
import csv
import os
import requests
import json
from datetime import datetime

DATA_DIR = "data"
PACKETS_FILE = os.path.join(DATA_DIR, "packets.csv")
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.csv")
SNORT_FILE = os.path.join(DATA_DIR, "snort_alerts.csv")

# SECURE: Get Webhook URL from environment variables for deployment
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", None)

def send_slack_alert(ip, port, risk, mitre):
    if not SLACK_WEBHOOK:
        return
    
    payload = {
        "text": f"🚨 *CRITICAL THREAT DETECTED* 🚨\n*Source IP:* {ip}\n*Target Port:* {port}\n*Risk Score:* {risk}/100\n*Threat Type:* {mitre}"
    }
    try:
        requests.post(SLACK_WEBHOOK, json=payload, timeout=2)
    except:
        pass

def setup_files():
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Initialize packets.csv if it doesn't exist
    if not os.path.exists(PACKETS_FILE):
        with open(PACKETS_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp","src_ip","dst_ip","protocol","src_port","dst_port","packet_size","flags"])
            
    # Initialize alerts.csv if it doesn't exist
    if not os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp","src_ip","dst_ip","protocol","src_port","dst_port","packet_size","flags","protocol_enc","anomaly","risk_score","suspicious_port","alert","severity"])

def generate_random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def simulate_traffic():
    print("[*] Simulation Mode Started: Generating dummy network traffic...")
    setup_files()
    
    protocols = ["TCP", "UDP", "ICMP", "OTHER"]
    
    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 90% chance of normal traffic, 10% chance of anomaly
        is_anomaly = random.random() < 0.10
        
        if is_anomaly:
            src_ip = generate_random_ip()
            dst_ip = "192.168.1.100"  # Target server
            protocol = "TCP"
            src_port = random.randint(1024, 65535)
            # Pick a suspicious port
            dst_port = random.choice([22, 23, 445, 3389, 4444, 31337])
            packet_size = random.randint(40, 1500)
            flags = "S" # SYN scan
            risk_score = round(random.uniform(75.0, 99.9), 2)
            severity = "HIGH" if risk_score > 90 else "MEDIUM"
            alert = True
            
            # Fire Webhook Alert for HIGH severity threats
            if severity == "HIGH":
                mitre_tag = "T1110 (Brute Force)" if dst_port == 22 else "T1046 (Service Discovery)" if dst_port in [23, 445, 3389] else "T1059 (Command & Control)" if dst_port in [4444, 31337] else "T1071 (Standard App Layer)"
                send_slack_alert(src_ip, dst_port, risk_score, mitre_tag)
        else:
            src_ip = generate_random_ip()
            dst_ip = generate_random_ip()
            protocol = random.choices(protocols, weights=[0.7, 0.2, 0.05, 0.05])[0]
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 53, 8080])
            packet_size = random.randint(40, 1500)
            flags = "PA"
            risk_score = round(random.uniform(1.0, 30.0), 2)
            severity = "NORMAL"
            alert = False
            
        # Write to packets.csv
        with open(PACKETS_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, flags])
            
        # Write to alerts.csv (dashboard reads from here for the main stats)
        with open(ALERTS_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, flags,
                1, int(is_anomaly), risk_score, is_anomaly, alert, severity
            ])
            
        # Trim files if they get too big (keep last 500 lines) to prevent memory bloat on free tier
        if random.random() < 0.05:
            try:
                for file_path in [PACKETS_FILE, ALERTS_FILE]:
                    with open(file_path, 'r') as f:
                        lines = f.readlines()
                    if len(lines) > 500:
                        with open(file_path, 'w') as f:
                            f.writelines(lines[0:1] + lines[-500:])
            except Exception as e:
                pass
                
        # Wait 1-3 seconds before next packet batch to simulate realistic flow
        time.sleep(random.uniform(0.5, 2.5))

if __name__ == "__main__":
    simulate_traffic()
