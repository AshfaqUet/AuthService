import hashlib
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.utils import create_raw_refresh_token, hash_refresh_secret, create_access_token, verify_password, \
    extract_request_fingerprint, generate_fingerprint
from app.models import User, LoginAttempt, RefreshToken, Token
# from app.core.security import create_access_token, create_raw_refresh_token, hash_refresh_secret
from app.config import settings

def authenticate_user(email: str, password: str, db: Session, request: Request | None = None):
    user = db.query(User).filter(User.email == email).first()
    now = datetime.now(timezone.utc)

    # ---- user not found ----
    if not user:
        if request:
            ip, ua = extract_request_fingerprint(request)
            db.add(LoginAttempt(email=email, ip_address=ip, success=False, reason="no_user"))
            db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ---- account locked ----
    if user.locked_until and user.locked_until > now:
        if request:
            ip, ua = extract_request_fingerprint(request)
            db.add(LoginAttempt(email=email, ip_address=ip, success=False, reason="locked"))
            db.commit()
        raise HTTPException(status_code=423, detail="Account locked")

    # ---- password verification ----
    if not verify_password(password, user.password):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        reason = "wrong_password"
        if user.failed_attempts >= settings.MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(seconds=settings.LOCK_TIME_SECONDS)
            reason = "locked_after_max_attempts"

        if request:
            ip, ua = extract_request_fingerprint(request)
            db.add(LoginAttempt(email=email, ip_address=ip, success=False, reason=reason))
            db.commit()
        db.add(user)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ---- success: reset lock/attempts ----
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = now

    # ---- extract fingerprint from middleware ----
    fingerprint = None
    if request:
        fingerprint = getattr(request.state, "fingerprint", None)
        if not fingerprint:
            # fallback (in case middleware not used)
            _, ua = extract_request_fingerprint(request)
            fingerprint = hashlib.sha256((ua or "").encode()).hexdigest()

    # ---- issue new access token ----
    access_token_str, access_expires, access_jti = create_access_token(sub=str(user.id), fingerprint=fingerprint)

    # fingerprint: from request (if provided)
    ip = None
    ua = None
    user_agent_hash = None
    if request:
        ip, ua = extract_request_fingerprint(request)
        user_agent_hash = generate_fingerprint(ip, ua)

    new_access = Token(
        jti=access_jti,
        token=access_token_str,
        user_id=user.id,
        expires_at=access_expires,
        user_agent_hash=user_agent_hash,
        ip_address=ip,
    )

    # ---- enforce single-device refresh ----
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()

    # ---- issue refresh token ----
    raw_refresh_token, refresh_expires, refresh_jti, refresh_secret = create_raw_refresh_token(days_valid=7)
    refresh_hash = hash_refresh_secret(refresh_secret)
    refresh_row = RefreshToken(
        jti=refresh_jti,
        token_hash=refresh_hash,
        user_id=user.id,
        expires_at=refresh_expires,
        revoked=False,
    )

    # ---- record successful login ----
    if ip:
        db.add(LoginAttempt(user_id=user.id, email=user.email, ip_address=ip, success=True))

    # ---- persist changes ----
    db.add(user)
    db.add(new_access)
    db.add(refresh_row)
    db.commit()

    return {
        "access_token": access_token_str,
        "token_type": "bearer",
        "expires_at": access_expires,
        "refresh_token": raw_refresh_token,
        "refresh_expires_at": refresh_expires,
    }