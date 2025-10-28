# app/auth/utils.py
import hashlib
from typing import Optional

from fastapi import Request
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta, timezone
import uuid
import secrets

from app.config import settings

# Use Argon2 for password hashing (already set)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# -------- password helpers (existing) --------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# -------- access token helpers (existing) --------
def create_access_token(sub: str, fingerprint: str, scopes: list[str] = None, expires_seconds: int = None):
    if expires_seconds is None:
        expires_seconds = settings.ACCESS_TOKEN_EXPIRE_SECONDS
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=expires_seconds)
    jti = str(uuid.uuid4())
    payload = {
        "sub": sub,
        "exp": int(expires.timestamp()),
        "iat": int(now.timestamp()),
        "jti": jti,
        "scopes": scopes or [],
        "fingerprint": fingerprint,
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, expires, jti

def decode_token(token: str):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except Exception:
        raise

# -------- refresh token helpers (new) --------
def create_raw_refresh_token(days_valid: int = 7):
    """
    Create an opaque refresh token with an included jti.
    Token format returned to client: "<jti>.<secret>"
    We will store hash(secret) + jti in DB.
    Returns (token_string, expires_at_datetime, jti, secret)
    """
    jti = str(uuid.uuid4())
    # secret part: high-entropy urlsafe string
    secret = secrets.token_urlsafe(48)
    token_string = f"{jti}.{secret}"
    expires = datetime.now(timezone.utc) + timedelta(days=days_valid)
    return token_string, expires, jti, secret

def hash_refresh_secret(secret: str) -> str:
    """
    Hash only the secret part of refresh token for storage.
    Using same Argon2 context is fine.
    """
    return pwd_context.hash(secret)

def verify_refresh_secret(secret: str, token_hash: str) -> bool:
    return pwd_context.verify(secret, token_hash)


def generate_fingerprint(ip: Optional[str], user_agent: Optional[str]) -> str:
    """
    Create a deterministic fingerprint from ip and user-agent.
    Returns a hex SHA256 hash.
    """
    base = f"{ip or ''}|{(user_agent or '').strip()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def extract_request_fingerprint(request: Request) -> tuple[str, str]:
    """
    Returns (ip, user_agent)
    - ip: request.client.host (or X-Forwarded-For if you trust proxies — see notes)
    - user_agent: header
    """
    # If you're behind a reverse proxy, you'd use request.headers.get("x-forwarded-for")
    # BUT only do that if you trust it (set in config).
    client = request.client
    ip = client.host if client else None
    ua = request.headers.get("user-agent", "")
    return ip, ua
