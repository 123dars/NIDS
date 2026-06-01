# 🛡 NIDS — Network Intrusion Detection System

A real-time Network Intrusion Detection System built with Python, Scapy, Machine Learning, and Flask.
Detects suspicious network activity using live packet sniffing, ML-based anomaly detection, and rule-based analysis — all visualized on a live web dashboard.

> 📊 Captured and analysed **800+ live packets** | Detected **11 anomalies** | **94%** normal classification rate

<img width="1919" height="745" alt="image" src="https://github.com/user-attachments/assets/9e7c5378-7fc7-4ba8-9df5-c8a40729878e" />


---

## ⚡ Features

- 📡 **Live Packet Capture** — Real-time network traffic capture using Scapy
- 🤖 **ML Anomaly Detection** — Isolation Forest algorithm flags suspicious packets automatically
- 🔍 **Rule-based Detection** — Flags known suspicious ports (22, 445, 4444, 31337 etc.)
- 📊 **Live Dashboard** — Flask web dashboard with auto-refresh every 5 seconds
- 🔎 **Filter & Search** — Filter alerts by IP, protocol, and severity in real time
- ⬇ **Export CSV** — One-click download of all alerts
- 📈 **Packet Rate Graph** — Live chart showing network activity over last 60 seconds
- 🚨 **Severity Classification** — HIGH / MEDIUM / LOW / NORMAL risk scoring (0–100)
- 🔗 **Snort & Suricata Integration** — Deep packet inspection with signature-based rules
- 📦 **ELK Stack Ready** — Push logs to Elasticsearch + Kibana for enterprise monitoring

---

## 🛠 Tech Stack

| Component | Technology |
|-----------|-----------|
| Packet Capture | Python, Scapy |
| Anomaly Detection | Scikit-learn (Isolation Forest) |
| Rule-based Detection | Python |
| Log Analysis | Snort, Suricata |
| Web Dashboard | Flask, HTML, CSS, JavaScript |
| Data Processing | Pandas, NumPy |
| Visualization | ELK Stack (Elasticsearch + Kibana) |

---

## 📁 Project Structure

```
NIDS/
├── sniffer/
│   ├── packet_sniffer.py     # Live packet capture using Scapy
│   └── log_parser.py         # Parse Snort & Suricata alert logs
├── ml/
│   └── anomaly_detector.py   # Isolation Forest ML anomaly detection
├── dashboard/
│   ├── app.py                # Flask backend API
│   └── templates/
│       └── index.html        # Live monitoring dashboard
├── data/                     # Auto-created: CSV logs & alerts
├── logs/                     # Snort/Suricata raw logs
├── run.py                    # Main entry point
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Step 1 — Clone the repository
```bash
git clone https://github.com/123dars/NIDS.git
cd NIDS
```

### Step 2 — Create virtual environment
```bash
python3 -m venv nids-env
source nids-env/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Install Snort & Suricata (optional, for deep inspection)
```bash
sudo apt update
sudo apt install snort suricata -y
```

### Step 5 — Find your network interface
```bash
ip a
# Look for eth0, wlan0, or ens33
```

---

## 🚀 Quick Start — Single Command

```bash
sudo nids-env/bin/python3 run.py all eth0
```

This runs everything together — sniffer, anomaly detector (every 15 seconds), and dashboard all at once.

Open browser → **http://localhost:5000**

Browse any website to generate live traffic and watch the dashboard update automatically!

### Run components individually (optional)

```bash
# Capture packets only
sudo nids-env/bin/python3 run.py sniff eth0

# Run anomaly detection only
nids-env/bin/python3 run.py detect

# Start dashboard only
nids-env/bin/python3 run.py dashboard

# Parse Snort/Suricata logs
nids-env/bin/python3 run.py logs
```

---

## 📊 Dashboard Features

| Feature | Description |
|---------|-------------|
| Total Packets | Live count of all captured packets |
| Risk Cards | HIGH / MEDIUM / LOW / NORMAL breakdown |
| Packet Rate Graph | Live chart of packets per second (last 60s) |
| Active Alerts | Filterable table of suspicious packets with risk scores |
| Protocol Breakdown | TCP / UDP / ICMP / Other percentage bars |
| Top Source IPs | Most active IP addresses on your network |
| Export CSV | Download all alerts as a CSV file with one click |
| System Status | Sniffer, ML model, and interface status |

---

## 🧠 How Anomaly Detection Works

1. **Packet Sniffer** captures live traffic and saves to CSV
2. **Feature Extraction** — protocol, ports, packet size are extracted
3. **Isolation Forest** model trained on captured data
4. Packets with anomaly score > threshold are flagged
5. **Rule-based checks** add flags for known suspicious ports
6. **Risk score** (0–100) calculated for each flagged packet
7. All results visible on live dashboard with auto-refresh

---

## 🔒 Suspicious Ports Monitored

| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Brute force attempts |
| 23 | Telnet | Unencrypted access |
| 445 | SMB | Ransomware / WannaCry |
| 3389 | RDP | Remote access attacks |
| 4444 | Metasploit | Common exploit payload |
| 31337 | Back Orifice | Legacy trojan |

---

## 👨‍💻 Author

**Darshan B**
- GitHub: [github.com/123dars](https://github.com/123dars)
- LinkedIn: [linkedin.com/in/darshan-vishwakarma](https://linkedin.com/in/darshan-vishwakarma)
- Email: darshanvishwakarma092@gmail.com

---

## 📄 License

MIT License — feel free to use and modify for educational purposes.
