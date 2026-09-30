"""SQLite evidence store. Schema changes are additive; legacy evidence is not rewritten."""
import json
import os
from pathlib import Path
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql import func

DB_PATH = os.getenv("SECUREMAILSCOPE_DATABASE_URL", "sqlite:///" + str(Path(__file__).with_name("securemailscope.db")))
engine = create_engine(DB_PATH, connect_args={"check_same_thread": False, "timeout": 30})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AnalyzedSession(Base):
    __tablename__ = "analyzed_sessions"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    stream_index = Column(String, default="0")
    src_ip = Column(String)
    dst_ip = Column(String)
    protocol = Column(String)
    score = Column(Integer, nullable=True)
    status = Column(String, default="unknown")
    tls_version = Column(String)
    ja3_hash = Column(String)
    anomaly_count = Column(Integer, default=0)
    full_json = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    analysis_id = Column(String)
    session_id = Column(String)
    capture_sha256 = Column(String)
    capture_start = Column(String)
    capture_end = Column(String)
    provenance_json = Column(Text)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    analysis_id = Column(String, primary_key=True)
    capture_sha256 = Column(String, nullable=False)
    source = Column(String, nullable=False)
    session_count = Column(Integer, nullable=False)
    provenance_json = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())


class ResponseAttempt(Base):
    __tablename__ = "response_attempts"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    operation = Column(String, nullable=False)
    outcome_json = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())


def init_db():
    Base.metadata.create_all(bind=engine)
    columns = {c["name"] for c in inspect(engine).get_columns("analyzed_sessions")}
    additions = {"analysis_id": "TEXT", "session_id": "TEXT", "capture_sha256": "TEXT",
                 "capture_start": "TEXT", "capture_end": "TEXT", "provenance_json": "TEXT"}
    with engine.begin() as conn:
        for name, kind in additions.items():
            if name not in columns:
                conn.execute(text(f"ALTER TABLE analyzed_sessions ADD COLUMN {name} {kind}"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_session_identity ON analyzed_sessions(session_id) WHERE session_id IS NOT NULL"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_analysis_identity ON analyzed_sessions(analysis_id)"))


def _record(result):
    ja3 = result.get("ja3")
    return AnalyzedSession(
        stream_index=str(result.get("stream_index", "")), src_ip=result.get("src_ip"),
        dst_ip=result.get("dst_ip"), protocol=result.get("email_protocol"), score=result.get("score"),
        status=result.get("status", "unknown"), tls_version=result.get("tls_version"),
        ja3_hash=ja3.get("hash") if isinstance(ja3, dict) else ja3,
        anomaly_count=len(result.get("risk_factors") or []), full_json=json.dumps(result, default=str),
        analysis_id=result.get("analysis_id"), session_id=result.get("session_id"),
        capture_sha256=result.get("capture_sha256"), capture_start=str(result.get("start_time") or ""),
        capture_end=str(result.get("end_time") or ""), provenance_json=json.dumps(result.get("provenance", {})))


def save_session(result):
    with SessionLocal() as db:
        if result.get("session_id") and db.query(AnalyzedSession).filter_by(session_id=result["session_id"]).first():
            return
        db.add(_record(result))
        db.commit()


def save_analysis(analysis_id, digest, source, results, provenance):
    """Persist an entire run atomically, including valid zero-session captures."""
    with SessionLocal() as db:
        db.add(AnalysisRun(analysis_id=analysis_id, capture_sha256=digest, source=source,
                           session_count=len(results), provenance_json=json.dumps(provenance)))
        db.add_all([_record(r) for r in results])
        db.commit()


def get_recent_sessions(limit=50, analysis_id=None):
    with SessionLocal() as db:
        query = db.query(AnalyzedSession)
        if analysis_id:
            if analysis_id.startswith("legacy-"):
                try:
                    query = query.filter(AnalyzedSession.id == int(analysis_id[7:]), AnalyzedSession.analysis_id.is_(None))
                except ValueError:
                    return []
            else:
                query = query.filter_by(analysis_id=analysis_id)
        rows = query.order_by(AnalyzedSession.id.desc()).limit(max(1, min(limit, 10000))).all()
        return [{c.name: getattr(row, c.name) for c in AnalyzedSession.__table__.columns} for row in rows]


def analysis_exists(analysis_id):
    with SessionLocal() as db:
        return db.query(AnalysisRun).filter_by(analysis_id=analysis_id).first() is not None


def record_response(analysis_id, ip, operation, outcome):
    with SessionLocal() as db:
        db.add(ResponseAttempt(analysis_id=analysis_id, ip=ip, operation=operation,
                               outcome_json=json.dumps(outcome)))
        db.commit()


def readiness():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT analysis_id FROM analysis_runs LIMIT 1"))
        return "ready"
    except Exception:
        return "unavailable"


def flush_sessions():
    with SessionLocal() as db:
        db.query(AnalyzedSession).delete()
        db.query(AnalysisRun).delete()
        # Response audit records intentionally survive analysis deletion.
        db.commit()
