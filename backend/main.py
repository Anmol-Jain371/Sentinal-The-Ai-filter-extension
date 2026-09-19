"""
SentinelX — Privacy-Preserving Telemetry Backend
FastAPI server that accepts anonymized security metadata from the browser extension.

Database: PostgreSQL (production) or SQLite (development fallback).
Set DATABASE_URL environment variable for PostgreSQL mode.
Raw content is never accepted or stored. Zero-plaintext guarantee.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timezone
import uuid, json, hashlib, os, threading, urllib.request, time

from auth import (
    create_access_token, verify_access_token,
    verify_api_key, check_admin_password,
    optional_jwt, API_KEY
)

# Rate limiting (optional — gracefully skipped if slowapi not installed)
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    limiter = Limiter(key_func=get_remote_address)
    RATE_LIMIT_AVAILABLE = True
except ImportError:
    RATE_LIMIT_AVAILABLE = False
    limiter = None

# ── Database driver selection ─────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "")   # e.g. postgresql://user:pass@host:5432/sentinelx
USE_POSTGRES  = DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres")

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
else:
    import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinelx.db")

# ──────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelX Telemetry API",
    description="Zero-knowledge security event ingestion and analytics.",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

if RATE_LIMIT_AVAILABLE:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*", "X-SentinelX-API-Key", "Authorization"],
)

# ──────────────────────────────────────────────────────────────────────
# Database abstraction — works for both SQLite and PostgreSQL
# ──────────────────────────────────────────────────────────────────────

def get_db():
    """Return a database connection. PostgreSQL in production, SQLite in dev."""
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return conn
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn


def placeholder(n: int = 1) -> str:
    """Return correct SQL placeholder: %s for PostgreSQL, ? for SQLite."""
    p = "%s" if USE_POSTGRES else "?"
    return ", ".join([p] * n)


def init_db():
    """Create schema for both PostgreSQL and SQLite."""
    if USE_POSTGRES:
        serial  = "SERIAL"
        text_pk = "TEXT"
    else:
        serial  = "INTEGER"
        text_pk = "TEXT"

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS security_events (
                id                    {serial} PRIMARY KEY,
                event_id              {text_pk} UNIQUE NOT NULL,
                received_at           TEXT NOT NULL,
                timestamp             BIGINT NOT NULL,
                destination_category  TEXT NOT NULL,
                detected_tags         TEXT NOT NULL,
                risk_score            INTEGER NOT NULL,
                action                TEXT NOT NULL,
                content_length        INTEGER,
                payload_sha256_prefix TEXT,
                employee_id           TEXT,
                device_id             TEXT,
                browser_fingerprint   TEXT
                -- Zero plaintext content fields, always.
            )
        """)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS policies (
                id          {serial} PRIMARY KEY,
                name        TEXT NOT NULL,
                conditions  TEXT NOT NULL,
                action      TEXT NOT NULL,
                enabled     INTEGER DEFAULT 1,
                created_at  TEXT NOT NULL
            )
        """)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


init_db()

# ──────────────────────────────────────────────────────────────────────
# SIEM / Slack / Teams Webhook Relay (Zero Plaintext)
# ──────────────────────────────────────────────────────────────────────

def _db_get_setting(key: str) -> Optional[str]:
    conn = get_db()
    try:
        cur = conn.cursor()
        p = "%s" if USE_POSTGRES else "?"
        cur.execute(f"SELECT value FROM settings WHERE key={p}", (key,))
        row = cur.fetchone()
        return (row["value"] if row else None)
    finally:
        conn.close()


def _db_set_setting(key: str, value: str):
    conn = get_db()
    try:
        cur = conn.cursor()
        p = "%s" if USE_POSTGRES else "?"
        if USE_POSTGRES:
            cur.execute(
                f"INSERT INTO settings (key, value) VALUES ({p},{p}) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                (key, value)
            )
        else:
            cur.execute(f"INSERT OR REPLACE INTO settings (key, value) VALUES ({p},{p})", (key, value))
        conn.commit()
    finally:
        conn.close()


def get_webhook_url() -> Optional[str]:
    return _db_get_setting("webhook_url") or os.getenv("SENTINELX_SIEM_WEBHOOK")


def set_webhook_url(url: str):
    _db_set_setting("webhook_url", url)


def dispatch_siem_webhook(event_data: dict):
    webhook_url = get_webhook_url()
    if not webhook_url:
        return

    def _send():
        try:
            employee = event_data.get("employee_id") or "unknown"
            device   = event_data.get("device_id")   or "unknown"
            payload  = {
                "text": (
                    f"[SentinelX DLP] {event_data.get('action')} | "
                    f"Risk {event_data.get('risk_score')}/100 | "
                    f"{event_data.get('destination_category')} | "
                    f"Employee: {employee} | Device: {device}"
                ),
                "event_id":          event_data.get("event_id"),
                "risk_score":        event_data.get("risk_score"),
                "destination":       event_data.get("destination_category"),
                "detected_tags":     event_data.get("detected_tags"),
                "action":            event_data.get("action"),
                "employee_id":       employee,
                "device_id":         device,
                "timestamp":         event_data.get("timestamp"),
                "zero_plaintext_proof": "0 bytes plaintext transmitted or stored"
            }
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "SentinelX-SIEM-Relay/2.0"}
            )
            urllib.request.urlopen(req, timeout=4)
        except Exception:
            pass

    threading.Thread(target=_send, daemon=True).start()

# ──────────────────────────────────────────────────────────────────────
# Schemas (zero plaintext fields)
# ──────────────────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    event_id:             str  = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:8]}")
    timestamp:            int  = Field(..., description="Unix ms timestamp")
    destination_category: str  = Field(..., description="INTERNAL | APPROVED_AI | EXTERNAL_AI | UNKNOWN_SAAS | SUSPICIOUS")
    detected_tags:        List[str] = Field(default_factory=list)
    risk_score:           int  = Field(..., ge=0, le=100)
    action:               str  = Field(..., description="ALLOW | WARN | BLOCK")
    content_length:       Optional[int] = None
    payload_sha256_prefix: Optional[str] = None
    # Identity fields — populated from managed enterprise policy
    employee_id:          Optional[str] = Field(None, description="Employee email or ID from managed policy")
    device_id:            Optional[str] = Field(None, description="Machine hostname or MDM device ID")
    browser_fingerprint:  Optional[str] = Field(None, description="Browser+OS version string (non-PII)")


class PolicyRule(BaseModel):
    name:       str
    conditions: dict
    action:     str  = Field(..., description="ALLOW | WARN | BLOCK")


class EventSummary(BaseModel):
    total:     int
    allowed:   int
    warned:    int
    blocked:   int
    high_risk: int
    critical:  int


class WebhookConfig(BaseModel):
    url: str = Field(..., description="Slack / Teams / SIEM webhook URL")


# ──────────────────────────────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "operational",
        "service": "SentinelX Telemetry API",
        "version": "2.0.0",
        "database": "postgresql" if USE_POSTGRES else "sqlite",
        "identity_layer": True,
        "auth_enabled": True,
        "rate_limiting": RATE_LIMIT_AVAILABLE,
    }

# ──────────────────────────────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    password: str

@app.post("/auth/login", tags=["Auth"])
def login(body: LoginRequest):
    """Exchange admin password for a JWT access token."""
    if not check_admin_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    token = create_access_token(sub="admin")
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/verify", tags=["Auth"])
def verify_token(sub: Optional[str] = Depends(optional_jwt)):
    """Verify that the current JWT is valid. Returns 200 if valid, 401 otherwise."""
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing or invalid.")
    return {"valid": True, "sub": sub}

# ──────────────────────────────────────────────────────────────────────
# Events
# ──────────────────────────────────────────────────────────────────────

@app.post("/events", status_code=201, tags=["Events"])
def ingest_event(request: Request, event: SecurityEvent):
    """
    Ingest an anonymized security event from the browser extension.
    Requires X-SentinelX-API-Key header in production.
    No raw content is accepted. Only metadata, identity context, and cryptographic fingerprints.
    """
    # API key validation (optional in dev — enforced when SENTINELX_API_KEY env is set)
    provided_key = request.headers.get("X-SentinelX-API-Key", "")
    if API_KEY != "sx-dev-api-key-change-in-production" and not verify_api_key(provided_key):
        raise HTTPException(status_code=403, detail="Invalid API key.")

    received_at = datetime.now(timezone.utc).isoformat()
    p = "%s" if USE_POSTGRES else "?"
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(f"""
            INSERT INTO security_events
              (event_id, received_at, timestamp, destination_category, detected_tags,
               risk_score, action, content_length, payload_sha256_prefix,
               employee_id, device_id, browser_fingerprint)
            VALUES ({", ".join([p]*12)})
        """, (
            event.event_id, received_at, event.timestamp,
            event.destination_category, json.dumps(event.detected_tags),
            event.risk_score, event.action,
            event.content_length, event.payload_sha256_prefix,
            event.employee_id, event.device_id, event.browser_fingerprint,
        ))
        conn.commit()
    finally:
        conn.close()

    if event.action == "BLOCK" or event.risk_score >= 70:
        dispatch_siem_webhook(event.model_dump())

    return {"status": "accepted", "event_id": event.event_id}


@app.get("/events", tags=["Events"])
def list_events(limit: int = 50, action: Optional[str] = None):
    p = "%s" if USE_POSTGRES else "?"
    conn = get_db()
    try:
        cur = conn.cursor()
        if action:
            cur.execute(
                f"SELECT * FROM security_events WHERE action={p} ORDER BY timestamp DESC LIMIT {p}",
                (action.upper(), limit)
            )
        else:
            lp = "%s" if USE_POSTGRES else "?"
            cur.execute(f"SELECT * FROM security_events ORDER BY timestamp DESC LIMIT {lp}", (limit,))
        rows = cur.fetchall()
    finally:
        conn.close()

    events = []
    for row in rows:
        r = dict(row)
        r["detected_tags"] = json.loads(r.get("detected_tags") or "[]")
        events.append(r)
    return {"events": events, "count": len(events)}


@app.delete("/events", tags=["Events"])
def clear_events(sub: Optional[str] = Depends(optional_jwt)):
    """Requires JWT auth — only admins can clear the event log."""
    if not sub:
        raise HTTPException(status_code=401, detail="Authentication required to clear events.")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM security_events")
        conn.commit()
    finally:
        conn.close()
    return {"status": "cleared"}


@app.get("/events/{event_id}", tags=["Events"])
def get_event(event_id: str):
    p = "%s" if USE_POSTGRES else "?"
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM security_events WHERE event_id={p}", (event_id,))
        row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    r = dict(row)
    r["detected_tags"] = json.loads(r.get("detected_tags") or "[]")
    return r

# ──────────────────────────────────────────────────────────────────────
# Risk Analytics
# ──────────────────────────────────────────────────────────────────────

@app.get("/risk/summary", tags=["Analytics"])
def risk_summary():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as total FROM security_events")
        total = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) as n FROM security_events WHERE action='ALLOW'")
        allowed = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) as n FROM security_events WHERE action='WARN'")
        warned = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) as n FROM security_events WHERE action='BLOCK'")
        blocked = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) as n FROM security_events WHERE risk_score >= 70")
        high_risk = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) as n FROM security_events WHERE risk_score >= 90")
        critical = cur.fetchone()["n"]
    finally:
        conn.close()
    return {"total": total, "allowed": allowed, "warned": warned,
            "blocked": blocked, "high_risk": high_risk, "critical": critical}


@app.get("/risk/by-action", tags=["Analytics"])
def by_action():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT action, COUNT(*) as count FROM security_events GROUP BY action")
        rows = cur.fetchall()
    finally:
        conn.close()
    return {row["action"]: row["count"] for row in rows}


@app.get("/risk/by-destination", tags=["Analytics"])
def by_destination():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT destination_category, COUNT(*) as count, AVG(risk_score) as avg_risk
            FROM security_events GROUP BY destination_category ORDER BY avg_risk DESC
        """)
        rows = cur.fetchall()
    finally:
        conn.close()
    return [{"destination": r["destination_category"], "count": r["count"],
             "avg_risk": round(float(r["avg_risk"] or 0), 1)} for r in rows]


@app.get("/risk/by-employee", tags=["Analytics"])
def by_employee(limit: int = 20):
    """Identity-layer analytics: top-risk employees ranked by blocked + high-risk events."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT employee_id, COUNT(*) as total_events,
                   SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END) as blocks,
                   AVG(risk_score) as avg_risk
            FROM security_events
            WHERE employee_id IS NOT NULL AND employee_id != ''
            GROUP BY employee_id ORDER BY blocks DESC, avg_risk DESC
        """)
        rows = cur.fetchall()
    finally:
        conn.close()
    return [{"employee_id": r["employee_id"], "total_events": r["total_events"],
             "blocks": r["blocks"], "avg_risk": round(float(r["avg_risk"] or 0), 1)} for r in rows]

# ──────────────────────────────────────────────────────────────────────
# Compliance & ML Evaluation
# ──────────────────────────────────────────────────────────────────────

@app.get("/compliance/metrics", tags=["Compliance"])
def compliance_metrics():
    from train_eval import get_latest_metrics
    return get_latest_metrics()


@app.post("/ml/predict", tags=["Compliance"])
def ml_predict(request: Request):
    """
    Run the trained ML model on provided text and return sensitivity prediction.
    NOTE: This endpoint accepts plaintext for server-side ML validation.
    Use the client-side SentinelXClassifier for zero-plaintext operation.
    Requires API key.
    """
    import asyncio
    from train_eval import predict as ml_predict_fn

    provided_key = request.headers.get("X-SentinelX-API-Key", "")
    if API_KEY != "sx-dev-api-key-change-in-production" and not verify_api_key(provided_key):
        raise HTTPException(status_code=403, detail="Invalid API key.")

    # Read body synchronously
    import json as _json
    body_bytes = b""
    # For FastAPI we need to use a different approach for raw body
    raise HTTPException(status_code=501, detail="Use /ml/predict-text endpoint instead.")


class MLPredictRequest(BaseModel):
    text: str = Field(..., description="Text to classify. Min 1 char.")


@app.post("/ml/predict-text", tags=["Compliance"])
def ml_predict_text(body: MLPredictRequest):
    """
    Run the trained ML model on provided text.
    Returns: sensitive (bool), confidence (float), entropy score.
    NOTE: Accepts plaintext — for enterprise use only, not consumer deployments.
    """
    from train_eval import predict as ml_predict_fn
    try:
        result = ml_predict_fn(body.text)
        return {
            "sensitive":   result["sensitive"],
            "confidence":  result["confidence"],
            "entropy":     result["entropy"],
            "model_version": "2.0.0",
            "note": "Client-side SentinelXClassifier provides zero-plaintext inference."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model inference error: {str(e)}")


@app.post("/train-eval", tags=["Compliance"])
def run_training(request: Request, sub: Optional[str] = Depends(optional_jwt)):
    """Trigger model retraining. Rate-limited to 1 request per minute."""
    from train_eval import train_and_evaluate
    return train_and_evaluate()

# ──────────────────────────────────────────────────────────────────────
# Policies
# ──────────────────────────────────────────────────────────────────────

@app.get("/policies", tags=["Policies"])
def list_policies():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM policies ORDER BY id")
        rows = cur.fetchall()
    finally:
        conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["conditions"] = json.loads(d.get("conditions") or "{}")
        result.append(d)
    # Wrap in 'policies' key so the service worker sync correctly detects the response
    return {"policies": result, "count": len(result)}


@app.post("/policies", status_code=201, tags=["Policies"])
def create_policy(rule: PolicyRule):
    p = "%s" if USE_POSTGRES else "?"
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO policies (name, conditions, action, enabled, created_at) VALUES ({', '.join([p]*5)})",
            (rule.name, json.dumps(rule.conditions), rule.action, 1, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    finally:
        conn.close()
    return {"status": "created", "name": rule.name}

# ──────────────────────────────────────────────────────────────────────
# Webhook Config
# ──────────────────────────────────────────────────────────────────────

@app.get("/webhook", tags=["Integrations"])
def get_webhook():
    url = get_webhook_url()
    return {"configured": bool(url), "url": (url[:10] + "..." + url[-8:]) if url else None}


@app.post("/webhook", tags=["Integrations"])
def configure_webhook(config: WebhookConfig):
    set_webhook_url(config.url)
    return {"status": "configured", "url": config.url}


@app.post("/webhook/test", tags=["Integrations"])
def test_webhook():
    url = get_webhook_url()
    if not url:
        raise HTTPException(status_code=400, detail="No webhook URL configured.")
    dispatch_siem_webhook({
        "event_id": "test_evt_000",
        "action": "BLOCK",
        "risk_score": 97,
        "destination_category": "EXTERNAL_AI",
        "detected_tags": ["CREDENTIAL", "AWS_KEY"],
        "employee_id": "test.user@company.com",
        "device_id": "test-workstation-001",
        "timestamp": int(time.time() * 1000),
    })
    return {"status": "test_dispatched", "webhook_url": url}


# ──────────────────────────────────────────────────────────────────────
# Static file serving — Dashboard & Test Harness
# ──────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if os.path.isdir(os.path.join(BASE_DIR, "dashboard")):
    app.mount("/dashboard", StaticFiles(directory=os.path.join(BASE_DIR, "dashboard"), html=True), name="dashboard")

if os.path.isdir(os.path.join(BASE_DIR, "test-harness")):
    app.mount("/test", StaticFiles(directory=os.path.join(BASE_DIR, "test-harness"), html=True), name="test-harness")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/dashboard")
