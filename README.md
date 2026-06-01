# 🛡 Open-Source Network Intrusion Detection System (NIDS)

A real-time Network Intrusion Detection System built with Python, Scapy, ML (Isolation Forest), and Flask.
Detects suspicious network activity using packet sniffing, anomaly detection, and rule-based analysis.

---

## 📁 Project Structure

```
NIDS/
├── sniffer/
│   ├── packet_sniffer.py   # Live packet capture using Scapy
│   └── log_parser.py       # Parse Snort & Suricata alert logs
├── ml/
│   └── anomaly_detector.py # Isolation Forest ML model for anomaly detection
├── dashboard/
│   ├── app.py              # Flask web dashboard backend
│   └── templates/
│       └── index.html      # Live monitoring dashboard UI
├── data/                   # Auto-created: CSV logs & alerts
├── logs/                   # Snort/Suricata raw logs
├── run.py                  # Main entry point
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Installation

### Step 1 — Clone & Install dependencies
```bash
git clone https://github.com/123dars/NIDS.git
cd NIDS
pip install -r requirements.txt
```

### Step 2 — Install Snort & Suricata (Kali Linux)
```bash
sudo apt update
sudo apt install snort suricata -y
```

### Step 3 — Find your network interface
```bash
ip a        # look for eth0, wlan0, or ens33
```

---

## 🚀 How to Run

### Option A — Run everything at once
```bash
sudo python3 run.py all eth0
```

### Option B — Run components individually

**1. Start packet sniffer (needs sudo)**
```bash
sudo python3 run.py sniff eth0
```

**2. Run anomaly detection on captured packets**
```bash
python3 run.py detect
```

**3. Start web dashboard**
```bash
python3 run.py dashboard
# Open browser: http://localhost:5000
```

**4. Parse Snort/Suricata logs**
```bash
python3 run.py logs
```

---

## 🧠 How It Works

| Component | Technology | What it does |
|-----------|-----------|--------------|
| Packet Sniffer | Scapy | Captures live packets, extracts IP, port, protocol, size |
| Anomaly Detection | Scikit-learn (Isolation Forest) | Flags statistically unusual traffic patterns |
| Rule-based Detection | Python | Flags known suspicious ports (22, 445, 4444, etc.) |
| Log Analysis | Snort + Suricata | Deep packet inspection with signature-based rules |
| Dashboard | Flask + HTML/JS | Live monitoring, auto-refreshes every 5 seconds |

---

## 📊 Dashboard Features
- Live packet count and severity breakdown
- Real-time alert table with risk scores (0–100)
- Color-coded severity: HIGH / MEDIUM / LOW / NORMAL
- Recent packets table
- Auto-refreshes every 5 seconds

---

## 🛠 Tech Stack
`Python` `Scapy` `Flask` `Scikit-learn` `Pandas` `Snort` `Suricata` `HTML/CSS/JS`

---

## 👨‍💻 Author
**Darshan B** | github.com/123dars | linkedin.com/in/darshan-vishwakarma
