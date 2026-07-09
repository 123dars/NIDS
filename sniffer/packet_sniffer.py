#!/usr/bin/env python3
# sniffer/packet_sniffer.py
# Step 1 & 2 — Capture live packets and save to CSV

from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv
import os
import time
import json
from datetime import datetime
import sys
import os

# Add parent directory to path so we can import database
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.models import SessionLocal, Packet

START_TIME = time.time()
PACKET_COUNT = 0
LAST_LOG_TIME = time.time()
LAST_PACKET_COUNT = 0

STATS_FILE = "data/stats.json"

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

def get_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"

def get_ports(pkt):
    src_port, dst_port = 0, 0
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    return src_port, dst_port

def get_flags(pkt):
    if pkt.haslayer(TCP):
        return str(pkt[TCP].flags)
    return ""

def process_packet(pkt):
    global PACKET_COUNT, LAST_LOG_TIME, LAST_PACKET_COUNT
    
    if not pkt.haslayer(IP):
        return

    src_port, dst_port = get_ports(pkt)

    # Write to Postgres
    session = SessionLocal()
    try:
        new_packet = Packet(
            timestamp=datetime.now(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            protocol=get_protocol(pkt),
            src_port=src_port,
            dst_port=dst_port,
            packet_size=len(pkt),
            flags=get_flags(pkt)
        )
        session.add(new_packet)
        session.commit()
    except Exception as e:
        print(f"[!] DB Error: {e}")
        session.rollback()
    finally:
        session.close()
        
    # Update throughput tracking
    PACKET_COUNT += 1
    current_time = time.time()
    
    # Log stats every 1 second
    if current_time - LAST_LOG_TIME >= 1.0:
        elapsed = current_time - LAST_LOG_TIME
        packets_since_last = PACKET_COUNT - LAST_PACKET_COUNT
        pps = packets_since_last / elapsed
        ppm = pps * 60
        
        stats = {
            "pps": round(pps, 2),
            "ppm": round(ppm, 2),
            "total_packets": PACKET_COUNT,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            with open(STATS_FILE, "w") as f:
                json.dump(stats, f)
        except Exception as e:
            print(f"[!] Error writing stats: {e}")
            
        LAST_LOG_TIME = current_time
        LAST_PACKET_COUNT = PACKET_COUNT

def start_sniffing(interface="eth0", packet_count=0):
    print(f"[*] Starting packet capture on interface: {interface}")
    print(f"[*] Saving packets to PostgreSQL database")
    print(f"[*] Press Ctrl+C to stop\n")
    sniff(iface=interface, prn=process_packet, count=packet_count, store=False)

if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    start_sniffing(interface=iface)
