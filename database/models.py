import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from flask_login import UserMixin
from datetime import datetime

# Fetch DB connection string, fallback to localhost for testing outside Docker
# Note: Inside docker, the host is 'db'. Outside, it is 'localhost'.
db_host = os.environ.get("DB_HOST", "localhost")
DB_URL = os.environ.get("DATABASE_URL", f"postgresql://nids_user:nids_password@{db_host}:5432/nids_db")
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(128), nullable=False)

class Packet(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(50), index=True)
    dst_ip = Column(String(50), index=True)
    protocol = Column(String(20))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    packet_size = Column(Integer)
    flags = Column(String(20))
    
    # ML & Threat Intel Fields (Nullable for raw packets)
    protocol_enc = Column(Integer, nullable=True)
    anomaly = Column(Integer, nullable=True) # -1 or 1
    risk_score = Column(Float, nullable=True)
    suspicious_port = Column(Boolean, nullable=True)
    alert = Column(Boolean, nullable=True)
    severity = Column(String(20), nullable=True)
    threat_actor = Column(String(100), nullable=True)
    asn = Column(String(100), nullable=True)
    location = Column(String(100), nullable=True)

def init_db():
    import time
    for _ in range(15):
        try:
            Base.metadata.create_all(bind=engine)
            print("[*] Database tables created/verified successfully.")
            return
        except Exception as e:
            print(f"[!] Database initialization failed, retrying in 2 seconds... ({e})")
            time.sleep(2)

if __name__ == "__main__":
    init_db()
