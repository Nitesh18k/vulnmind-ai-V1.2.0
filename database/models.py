"""
VulnMind AI - Database Layer (SQLite for portability on Kali)
"""

import os
import json
import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime,
    Float, Boolean, ForeignKey, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import StaticPool

# Use SQLite in ~/.vulnmind/
DB_DIR = os.path.expanduser("~/.vulnmind")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "vulnmind.db")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


# ─── Models ───────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(16), default="user")  # admin/user
    api_keys = Column(Text, default="{}")  # JSON: provider -> key
    default_provider = Column(String(32), default="openai")
    default_model = Column(String(64), default="gpt-4o-mini")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    targets = relationship("Target", back_populates="user")
    scans = relationship("Scan", back_populates="user")


class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String(256), nullable=False)
    target_type = Column(String(32))  # domain/ip/url/subdomain
    description = Column(Text, default="")
    tags = Column(String(256), default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target")
    assets = relationship("Asset", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    scan_type = Column(String(64))  # recon/portscan/vuln/full
    status = Column(String(32), default="pending")  # pending/running/done/failed
    progress = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    raw_results = Column(Text, default="{}")
    ai_analysis = Column(Text, default="")
    risk_score = Column(Float, default=0.0)
    severity_counts = Column(Text, default="{}")
    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    assets = relationship("Asset", back_populates="scan")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    asset_type = Column(String(32))  # subdomain/ip/url/port
    value = Column(String(512))
    extra = Column(Text, default="{}")  # JSON extra data
    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)
    scan = relationship("Scan", back_populates="assets")
    target = relationship("Target", back_populates="assets")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    name = Column(String(256))
    vuln_type = Column(String(64))  # sqli/xss/ssrf/etc
    severity = Column(String(16))   # critical/high/medium/low/info
    cvss_score = Column(Float, default=0.0)
    cve_ids = Column(Text, default="[]")   # JSON list
    cwe_ids = Column(Text, default="[]")   # JSON list
    affected_url = Column(Text, default="")
    affected_param = Column(String(256), default="")
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    remediation = Column(Text, default="")
    business_impact = Column(Text, default="")
    false_positive = Column(Boolean, default=False)
    confirmed = Column(Boolean, default=False)
    tool = Column(String(64), default="")  # which tool found it
    mitre_attack = Column(Text, default="[]")
    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)
    scan = relationship("Scan", back_populates="vulnerabilities")


class Config(Base):
    __tablename__ = "configs"
    id = Column(Integer, primary_key=True)
    key = Column(String(128), unique=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    report_type = Column(String(16))  # pdf/html/docx
    file_path = Column(String(512))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


# ─── Init ────────────────────────────────────────────────────────────────────

def init_db():
    """Create all tables."""
    Base.metadata.create_all(engine)


def get_session():
    """Get a database session."""
    return SessionLocal()


def get_or_create_config(session, key, default=None):
    """Get config value or create with default."""
    cfg = session.query(Config).filter_by(key=key).first()
    if not cfg:
        cfg = Config(key=key, value=json.dumps(default))
        session.add(cfg)
        session.commit()
    return json.loads(cfg.value) if cfg.value else default


def set_config(session, key, value):
    """Set config value."""
    cfg = session.query(Config).filter_by(key=key).first()
    if not cfg:
        cfg = Config(key=key)
        session.add(cfg)
    cfg.value = json.dumps(value)
    cfg.updated_at = datetime.datetime.utcnow()
    session.commit()
