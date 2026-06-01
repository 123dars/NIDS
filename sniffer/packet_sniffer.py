#!/usr/bin/env python3
# sniffer/packet_sniffer.py
# Step 1 & 2 — Capture live packets and save to CSV

from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv
import os
import time
from datetime import datetime

LOG_FILE = "data/packets.csv"
FIELDNAMES = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags"]

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
    if not pkt.haslayer(IP):
        return

    src_port, dst_port = get_ports(pkt)

    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":     pkt[IP].src,
        "dst_ip":     pkt[IP].dst,
        "protocol":   get_protocol(pkt),
        "src_port":   src_port,
        "dst_port":   dst_port,
        "packet_size": len(pkt),
        "flags":       get_flags(pkt),
    }

    print(f"[{row['timestamp']}] {row['src_ip']}:{src_port} -> {row['dst_ip']}:{dst_port} | {row['protocol']} | {row['packet_size']} bytes")

    # Write to CSV
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def start_sniffing(interface="eth0", packet_count=0):
    print(f"[*] Starting packet capture on interface: {interface}")
    print(f"[*] Saving packets to: {LOG_FILE}")
    print(f"[*] Press Ctrl+C to stop\n")
    sniff(iface=interface, prn=process_packet, count=packet_count, store=False)

if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    start_sniffing(interface=iface)
