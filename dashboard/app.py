#!/usr/bin/env python3
# dashboard/app.py

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import pandas as pd
import os
import sys
import json
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

# Add parent directory to path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ml.pcap_analyzer import analyze_pcap_file
from database.models import SessionLocal, Packet, User, init_db

app = Flask(__name__)
app.secret_key = "super_secret_cyber_key"
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

UPLOAD_FOLDER = "../data/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    session = SessionLocal()
    user = session.query(User).get(int(user_id))
    session.close()
    return user

def init_admin():
    session = SessionLocal()
    try:
        if not session.query(User).filter_by(username="admin").first():
            pw_hash = bcrypt.generate_password_hash("password123").decode('utf-8')
            admin = User(username="admin", password_hash=pw_hash)
            session.add(admin)
            session.commit()
    except Exception as e:
        print(f"[!] Could not init admin: {e}")
    finally:
        session.close()

def load_db_to_df(session):
    try:
        df = pd.read_sql(session.query(Packet).statement, session.bind)
        return df
    except Exception as e:
        print(f"[!] Error loading DB: {e}")
        return pd.DataFrame()

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        session = SessionLocal()
        user = session.query(User).filter_by(username=username).first()
        session.close()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials. Use admin / password123", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/analyze")
@login_required
def analyze():
    return render_template("analyze.html")

@app.route("/api/upload_pcap", methods=["POST"])
@login_required
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if file and file.filename.endswith(('.pcap', '.pcapng', '.cap')):
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        try:
            results = analyze_pcap_file(filepath)
            os.remove(filepath)
            return jsonify(results)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
            
    return jsonify({"error": "Invalid file type. Only .pcap allowed."}), 400

@app.route("/api/stats")
@login_required
def stats():
    session = SessionLocal()
    df = load_db_to_df(session)
    session.close()
    if df.empty:
        return jsonify({"total": 0, "high": 0, "medium": 0, "low": 0, "normal": 0})

    return jsonify({
        "total":   int(len(df)),
        "high":    int(len(df[df["severity"] == "HIGH"])),
        "medium":  int(len(df[df["severity"] == "MEDIUM"])),
        "low":     int(len(df[df["severity"] == "LOW"])),
        "normal":  int(len(df[(df["severity"] == "NORMAL") | (df["severity"].isna())])),
    })

@app.route("/api/alerts")
@login_required
def alerts():
    session = SessionLocal()
    df = load_db_to_df(session)
    session.close()
    if df.empty:
        return jsonify([])

    flagged = df[df["alert"] == True].copy()
    flagged = flagged.sort_values("timestamp", ascending=False).head(100)
    flagged['timestamp'] = flagged['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    cols = ["timestamp","src_ip","dst_ip","protocol","dst_port","severity","risk_score", "threat_actor", "asn", "location"]
    cols = [c for c in cols if c in flagged.columns]
    
    return jsonify(flagged[cols].to_dict(orient="records"))

@app.route("/api/throughput")
@login_required
def throughput():
    stats_file = "../data/stats.json"
    if os.path.isfile(stats_file):
        try:
            with open(stats_file, "r") as f:
                stats = json.load(f)
            return jsonify(stats)
        except Exception as e:
            print(f"[!] Error reading stats: {e}")
    return jsonify({"pps": 0, "ppm": 0, "total_packets": 0, "timestamp": ""})

@app.route("/api/packets")
@login_required
def packets():
    session = SessionLocal()
    df = load_db_to_df(session)
    session.close()
    if df.empty:
        return jsonify([])
    recent = df.sort_values("timestamp", ascending=False).head(50)
    recent['timestamp'] = recent['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(recent.fillna("").to_dict(orient="records"))

@app.route("/api/protocol_counts")
@login_required
def protocol_counts():
    session = SessionLocal()
    df = load_db_to_df(session)
    session.close()
    if df.empty:
        return jsonify({})
    counts = df["protocol"].value_counts().to_dict()
    return jsonify(counts)

@app.route("/api/osint/<ip>")
@login_required
def osint(ip):
    import hashlib
    hash_val = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    
    if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("127."):
        return jsonify({
            "ip": ip,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "usageType": "Local Network"
        })
        
    score = hash_val % 100
    if score < 80:
        score = 0
    elif score < 90:
        score = (score % 40) + 20 
    else:
        score = (score % 20) + 80 
        
    countries = ["US", "RU", "CN", "BR", "NL", "DE", "GB", "IR", "KP"]
    country = countries[hash_val % len(countries)]
    
    usage_types = ["Data Center/Web Hosting", "Fixed Line ISP", "Mobile ISP", "Commercial"]
    usage = usage_types[hash_val % len(usage_types)]
    
    return jsonify({
        "ip": ip,
        "abuseConfidenceScore": score,
        "countryCode": country,
        "usageType": usage
    })

@app.route("/api/export_pdf")
@login_required
def export_pdf():
    session = SessionLocal()
    df = load_db_to_df(session)
    session.close()
    
    flagged = df[df["alert"] == True] if not df.empty else pd.DataFrame()
    html_content = f"""
    <html>
        <head>
            <title>NIDS Executive Threat Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
                h1 {{ color: #0d2240; border-bottom: 2px solid #0d2240; padding-bottom: 10px; }}
                .summary {{ background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #0d2240; color: white; }}
                .high {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body onload="window.print()">
            <h1>Executive Threat Report</h1>
            <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <div class="summary">
                <h3>Executive Summary</h3>
                <p>Total Packets Analyzed: {len(df)}</p>
                <p>Total Security Alerts: {len(flagged)}</p>
                <p>High Severity Threats: {len(flagged[flagged['severity'] == 'HIGH']) if not flagged.empty else 0}</p>
            </div>
            <h3>Top 50 Recent Threats</h3>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Target Port</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Threat Actor</th>
                </tr>
    """
    if not flagged.empty:
        for _, row in flagged.sort_values("timestamp", ascending=False).head(50).iterrows():
            severity_class = "high" if row["severity"] == "HIGH" else ""
            html_content += f"""
                <tr>
                    <td>{row['timestamp']}</td>
                    <td>{row['src_ip']}</td>
                    <td>{row['dst_port']}</td>
                    <td class="{severity_class}">{row['severity']}</td>
                    <td>{row['risk_score']}</td>
                    <td>{row.get('threat_actor', 'Unknown')}</td>
                </tr>
            """
    html_content += """
            </table>
        </body>
    </html>
    """
    return html_content

if __name__ == "__main__":
    init_db()
    init_admin()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting NIDS Dashboard at http://0.0.0.0:{port}")
    app.run(debug=True, host="0.0.0.0", port=port)
