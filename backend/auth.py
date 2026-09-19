"""
SentinelX — JWT Authentication & API Key Verification
Zero-dependency auth layer using python-jose for JWT and .env for secrets.
"""

from __future__ import annotations

import os
import time
import hashlib
from typing import Optional
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

try:
    from jose import jwt, JWTError
    JOSE_AVAILABLE = True
except ImportError:
    JOSE_AVAILABLE = False

# ── Secrets (set via .env or environment variables) ───────────────────
JWT_SECRET      = os.getenv("JWT_SECRET",       "sentinelx-change-in-production-secret-key-2024")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))
ADMIN_PASSWORD  = os.getenv("ADMIN_PASSWORD",   "sentinelx-admin-2024")   # Change in production
API_KEY         = os.getenv("SENTINELX_API_KEY", "sx-dev-api-key-change-in-production")

_bearer = HTTPBearer(auto_error=False)


# ── Token creation ─────────────────────────────────────────────────────

def create_access_token(sub: str = "admin") -> str:
    if not JOSE_AVAILABLE:
        # Fallback: simple HMAC-based token for demo without python-jose
        payload = f"{sub}:{int(time.time()) + JWT_EXPIRE_HOURS * 3600}"
        sig = hashlib.sha256(f"{payload}:{JWT_SECRET}".encode()).hexdigest()[:16]
        return f"demo.{payload}.{sig}"

    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": sub, "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> Optional[str]:
    """Returns subject string if valid, None if invalid."""
    if not token:
        return None

    if not JOSE_AVAILABLE:
        # Demo fallback token verification
        try:
            parts = token.split(".", 2)
            if len(parts) != 3 or parts[0] != "demo":
                return None
            payload_str = parts[1]
            sig = parts[2]
            expected_sig = hashlib.sha256(f"{payload_str}:{JWT_SECRET}".encode()).hexdigest()[:16]
            if sig != expected_sig:
                return None
            sub, exp_ts = payload_str.rsplit(":", 1)
            if int(time.time()) > int(exp_ts):
                return None
            return sub
        except Exception:
            return None

    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return data.get("sub")
    except JWTError:
        return None


# ── FastAPI dependency — JWT bearer ───────────────────────────────────

def require_jwt(credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer)) -> str:
    """FastAPI dependency: validates Bearer JWT. Raises 401 if missing/invalid."""
    token = credentials.credentials if credentials else None
    sub = verify_access_token(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in.")
    return sub


def optional_jwt(credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer)) -> Optional[str]:
    """FastAPI dependency: returns subject if JWT valid, None otherwise (no error)."""
    token = credentials.credentials if credentials else None
    return verify_access_token(token)


# ── API Key verification ───────────────────────────────────────────────

def verify_api_key(key: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    expected = API_KEY.encode()
    provided = key.encode()
    if len(expected) != len(provided):
        return False
    result = 0
    for a, b in zip(expected, provided):
        result |= a ^ b
    return result == 0


# ── Password check (for login endpoint) ───────────────────────────────

def check_admin_password(password: str) -> bool:
    """Constant-time password comparison."""
    expected = ADMIN_PASSWORD.encode()
    provided = password.encode()
    if len(expected) != len(provided):
        return False
    result = 0
    for a, b in zip(expected, provided):
        result |= a ^ b
    return result == 0
