# 🛡️ Network Intrusion Detection System (NIDS)

An Enterprise-Grade, Machine Learning powered Network Intrusion Detection System built with Python, Docker, and PostgreSQL.

This project monitors network traffic in real-time, extracts features from raw packets, and uses an **Isolation Forest Machine Learning model** to detect anomalous and potentially malicious network activity. It includes OSINT threat-intelligence correlation, forensic PCAP analysis, and a real-time web dashboard.

![NIDS Dashboard](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.9-blue)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791)
![Machine Learning](https://img.shields.io/badge/Scikit--Learn-Isolation%20Forest-orange)

---

## 🌟 Key Features

1. **Real-time Packet Sniffing**: Uses `Scapy` to intercept live network traffic on your interface, extracting vital packet metadata (Ports, Flags, Protocols).
2. **Machine Learning Anomaly Detection**: An offline-trained Isolation Forest model scores each packet for anomalies, tagging deviations from standard network baselines as suspicious.
3. **OSINT Threat Intelligence**: Correlates anomalous IPs with deterministic, simulated threat actors (e.g., Lazarus Group, APT29) and geolocates the source.
4. **Forensic PCAP Analysis**: Drag-and-drop historic `.pcap` files into the web portal to run forensic ML analysis on past network captures.
5. **Real-time Web Dashboard**: A Flask-powered, authenticated portal displaying live network topology, protocol distribution, and high-risk alerts.
6. **Enterprise PDF Reporting**: Generate cleanly formatted Executive Threat Reports summarizing high-risk incidents.

---

## 🏗️ Architecture

The system is designed with a microservices architecture, fully containerized using `docker-compose`:

- **Sniffer Container** (`network_mode: host`): Listens directly on the host's network interfaces and writes raw packet data to the central database.
- **Detector Container**: A background daemon that polls the database, runs the ML inference pipeline, enriches alerts with Threat Intel, and writes risk scores back to the DB.
- **Web Dashboard**: A secure Flask application that serves the real-time UI and API endpoints.
- **PostgreSQL Database**: The central nervous system storing millions of packets efficiently, resolving file-locking issues found in traditional CSV-based prototypes.

---

## 🚀 Getting Started

### Prerequisites
- **Docker** & **Docker Compose** installed on your system.
- Ensure ports `5000` (Flask) and `5432` (Postgres) are free.

### 1. Build and Run the System
Navigate to the project directory and build the Docker containers:

```bash
docker-compose up --build
```

*Note: The system will automatically train the ML model and initialize the database on first boot.*

### 2. Access the Dashboard
Open your web browser and navigate to:
**http://localhost:5000**

- **Default Username:** `admin`
- **Default Password:** `password123`

### 3. Simulate an Attack (Demo Mode)
Want to see the system in action without waiting for a real cyber attack? Run the included traffic simulator to inject dummy traffic and simulated Advanced Persistent Threats (APTs) into the network:

```bash
docker-compose exec dashboard python simulator.py
```
*Watch your live dashboard light up with real-time Threat Intelligence and MITRE ATT&CK tags!*

---

## 📁 Project Structure

```
NIDS/
│
├── dashboard/               # Web Application
│   ├── app.py               # Flask backend & API routes
│   └── templates/           # UI (HTML/CSS/JS)
│
├── database/                # Database Layer
│   └── models.py            # SQLAlchemy schemas (User, Packet)
│
├── ml/                      # Machine Learning Engine
│   ├── anomaly_detector.py  # Inference script
│   ├── train_model.py       # Training pipeline
│   └── pcap_analyzer.py     # Forensic PCAP analysis module
│
├── sniffer/                 # Network Capture
│   └── packet_sniffer.py    # Live Scapy packet capture
│
├── simulator.py             # Fake traffic generator for demos
├── docker-compose.yml       # Microservices orchestration
└── Dockerfile               # Base image definition
```

---

## 🤝 Disclaimer
This tool is built for educational and portfolio demonstration purposes. Do not use this as a standalone security appliance in a production corporate network without integrating it with enterprise firewalls and proper alert orchestration tools (like Splunk or Elastic SIEM).

**Developed by Darshan B.**
