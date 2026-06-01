#!/usr/bin/env python3
# run.py — Main entry point for NIDS
# Run this file to start the full system

import subprocess
import threading
import time
import os
import sys

def run_sniffer(interface="eth0"):
    print(f"[*] Starting sniffer on {interface}...")
    os.system(f"sudo python3 sniffer/packet_sniffer.py {interface}")

def run_detector():
    print("[*] Starting anomaly detector (runs every 30 seconds)...")
    while True:
        time.sleep(30)
        os.system("python3 ml/anomaly_detector.py")

def run_dashboard():
    print("[*] Starting web dashboard at http://localhost:5000 ...")
    time.sleep(2)
    os.chdir("dashboard")
    os.system("python3 app.py")

def parse_snort_logs():
    print("[*] Parsing Snort/Suricata logs...")
    os.system("python3 sniffer/log_parser.py")

if __name__ == "__main__":
    print("""
    ███╗   ██╗██╗██████╗ ███████╗
    ████╗  ██║██║██╔══██╗██╔════╝
    ██╔██╗ ██║██║██║  ██║███████╗
    ██║╚██╗██║██║██║  ██║╚════██║
    ██║ ╚████║██║██████╔╝███████║
    ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝
    Network Intrusion Detection System
    Built by: Darshan B
    """)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 run.py sniff   [interface]  — Start packet capture")
        print("  python3 run.py detect               — Run anomaly detection")
        print("  python3 run.py dashboard             — Start web dashboard")
        print("  python3 run.py logs                 — Parse Snort/Suricata logs")
        print("  python3 run.py all     [interface]  — Run everything together")
        sys.exit(0)

    cmd = sys.argv[1]
    iface = sys.argv[2] if len(sys.argv) > 2 else "eth0"

    if cmd == "sniff":
        run_sniffer(iface)

    elif cmd == "detect":
        os.system("python3 ml/anomaly_detector.py")

    elif cmd == "dashboard":
        run_dashboard()

    elif cmd == "logs":
        parse_snort_logs()

    elif cmd == "all":
        # Run all components in parallel threads
        threads = [
            threading.Thread(target=run_sniffer,   args=(iface,), daemon=True),
            threading.Thread(target=run_detector,  daemon=True),
            threading.Thread(target=run_dashboard, daemon=True),
        ]
        for t in threads:
            t.start()
        print("\n[*] All components running. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down NIDS...")
    else:
        print(f"[!] Unknown command: {cmd}")
