import time
import random
import csv
import os
import requests
import json
import json
from datetime import datetime
import sys
import os

# Add parent directory to path so we can import database
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.models import SessionLocal, Packet

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

def generate_random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def simulate_traffic():
    print("[*] Simulation Mode Started: Generating dummy network traffic...")
    while True:
        is_anomaly = random.random() < 0.1  # 10% chance of attack
        
        if is_anomaly:
            src_ip = generate_random_ip()
            dst_ip = "192.168.1.100"  # Target server
            protocol = "TCP"
            src_port = random.randint(1024, 65535)
            # Pick a highly suspicious port
            dst_port = random.choice([22, 23, 3389, 4444, 31337])
            packet_size = random.randint(500, 1500)
            flags = "S"
            risk_score = random.uniform(80.0, 99.9)
            alert = True
            severity = "HIGH"
            
            # Send Slack Alert for high risk
            if risk_score > 90:
                send_slack_alert(src_ip, dst_port, int(risk_score), f"MITRE T1071 (Port {dst_port})")
        else:
            src_ip = f"192.168.1.{random.randint(10, 50)}"
            dst_ip = f"192.168.1.{random.randint(1, 9)}"
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 53])
            packet_size = random.randint(40, 500)
            flags = "A"
            risk_score = random.uniform(0.0, 20.0)
            alert = False
            severity = "NORMAL"

        # Write to Postgres
        session = SessionLocal()
        try:
            actor, asn, loc = get_threat_intel(severity, dst_port)
            new_packet = Packet(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                packet_size=packet_size,
                flags=flags,
                protocol_enc=1,
                anomaly=-1 if is_anomaly else 1,
                risk_score=risk_score,
                suspicious_port=is_anomaly,
                alert=alert,
                severity=severity,
                threat_actor=actor,
                asn=asn,
                location=loc
            )
            session.add(new_packet)
            session.commit()
            
            # Keep table from getting too large
            if random.random() < 0.05:
                count = session.query(Packet).count()
                if count > 500:
                    old_packets = session.query(Packet).order_by(Packet.timestamp.asc()).limit(count - 500).all()
                    for op in old_packets:
                        session.delete(op)
                    session.commit()
                    
        except Exception as e:
            print(f"[!] DB Error in simulator: {e}")
            session.rollback()
        finally:
            session.close()

        # Wait 0.5-2.5 seconds before next packet batch to simulate realistic flow
        time.sleep(random.uniform(0.5, 2.5))

if __name__ == "__main__":
    simulate_traffic()
