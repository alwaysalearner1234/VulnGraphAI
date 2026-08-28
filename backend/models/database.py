import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Determine absolute path for database file to avoid path resolution errors across working directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DB_DIR, exist_ok=True)
DATABASE_URL = f"sqlite:///{os.path.join(DB_DIR, 'vulngraph.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    last_scan = Column(DateTime, default=datetime.utcnow)
    sbom_type = Column(String)  # 'cyclonedx' or 'spdx'
    status = Column(String, default="unscanned")  # 'unscanned', 'scanned', 'scanning'
    risk_score = Column(Float, default=0.0)
    build_status = Column(String, default="PASS")  # 'PASS', 'WARNING', 'BLOCKED'

class Package(Base):
    __tablename__ = "packages"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"))
    name = Column(String, index=True)
    version = Column(String)
    type = Column(String)  # 'npm' or 'pip'
    is_direct = Column(Boolean, default=False)
    depth = Column(Integer, default=1)
    dependents_count = Column(Integer, default=0)

class DependencyEdge(Base):
    __tablename__ = "dependency_edges"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"))
    parent_name = Column(String)
    child_name = Column(String)

class VulnerabilityDb(Base):
    __tablename__ = "vulnerability_db"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    package_name = Column(String, index=True)
    affected_range = Column(String)  # e.g., "<4.17.21" or ">=3.0.0,<3.2.1"
    fixed_version = Column(String)
    cvss = Column(Float)
    epss = Column(Float)
    exploit_available = Column(Boolean, default=False)
    title = Column(String)
    description = Column(Text)
    publish_date = Column(DateTime, default=datetime.utcnow)

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"))
    package_name = Column(String, index=True)
    package_version = Column(String)
    cve_id = Column(String)
    cvss = Column(Float)
    epss = Column(Float)
    exploit_available = Column(Boolean, default=False)
    depth = Column(Integer, default=1)
    patch_lag = Column(Float, default=0.0)  # Age in years since release or version-distance factor
    calculated_risk = Column(Float, default=0.0)
    ml_probability = Column(Float, default=0.0)
    ml_priority = Column(String, default="LOW")  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    status = Column(String, default="active")  # 'active', 'remediated'
    remediation_cmd = Column(String)
    patch_diff = Column(Text)
    fixed_version = Column(String)
    dependency_path = Column(Text)  # JSON list of paths from app root: e.g. '["my-app", "express", "body-parser", "lodash"]'

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
