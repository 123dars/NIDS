#!/usr/bin/env python3
# sniffer/log_parser.py
# Step 4 — Parse Snort/Suricata alert logs

import re
import json
import os
import csv
from datetime import datetime

SNORT_LOG    = "/var/log/snort/alert"
SURICATA_LOG = "/var/log/suricata/eve.json"
OUTPUT_FILE  = "data/snort_alerts.csv"

# ── Snort parser ──────────────────────────────────────────────────────────────
def parse_snort_alerts(logfile=SNORT_LOG):
    alerts = []
    if not os.path.isfile(logfile):
        print(f"[!] Snort log not found at {logfile}")
        return alerts

    pattern = re.compile(
        r'\[(?P<sid>[^\]]+)\]\s+(?P<msg>[^\[]+)\[Classification:\s*(?P<classification>[^\]]*)\].*?'
        r'(?P<src>\d+\.\d+\.\d+\.\d+)(?::(?P<sport>\d+))?\s+->\s+'
        r'(?P<dst>\d+\.\d+\.\d+\.\d+)(?::(?P<dport>\d+))?',
        re.DOTALL
    )

    with open(logfile, "r") as f:
        content = f.read()
        blocks = content.strip().split("\n\n")
        for block in blocks:
            m = pattern.search(block)
            if m:
                alerts.append({
                    "source":         "snort",
                    "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "sid":            m.group("sid").strip(),
                    "message":        m.group("msg").strip(),
                    "classification": m.group("classification").strip(),
                    "src_ip":         m.group("src"),
                    "src_port":       m.group("sport") or "",
                    "dst_ip":         m.group("dst"),
                    "dst_port":       m.group("dport") or "",
                })

    print(f"[*] Parsed {len(alerts)} Snort alerts")
    return alerts

# ── Suricata parser ───────────────────────────────────────────────────────────
def parse_suricata_alerts(logfile=SURICATA_LOG):
    alerts = []
    if not os.path.isfile(logfile):
        print(f"[!] Suricata log not found at {logfile}")
        return alerts

    with open(logfile, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append({
                        "source":         "suricata",
                        "timestamp":       event.get("timestamp", ""),
                        "sid":            event["alert"].get("signature_id", ""),
                        "message":        event["alert"].get("signature", ""),
                        "classification": event["alert"].get("category", ""),
                        "src_ip":         event.get("src_ip", ""),
                        "src_port":       event.get("src_port", ""),
                        "dst_ip":         event.get("dest_ip", ""),
                        "dst_port":       event.get("dest_port", ""),
                    })
            except json.JSONDecodeError:
                continue

    print(f"[*] Parsed {len(alerts)} Suricata alerts")
    return alerts

# ── Save combined alerts ──────────────────────────────────────────────────────
def save_alerts(alerts):
    if not alerts:
        print("[!] No alerts to save.")
        return

    fieldnames = ["source","timestamp","sid","message","classification","src_ip","src_port","dst_ip","dst_port"]
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)
    print(f"[*] Saved {len(alerts)} alerts to {OUTPUT_FILE}")

if __name__ == "__main__":
    all_alerts = parse_snort_alerts() + parse_suricata_alerts()
    save_alerts(all_alerts)
