
# app/auth/routes.py (only showing the relevant endpoints and helpers)
from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
import uuid
import jwt

from app.auth.services import authenticate_user
from app.database import get_db
from app.models import User, Token, LoginAttempt, RefreshToken
from app.schemas import UserCreate, UserResponse, LoginRequest, TokenResponse, ForgotPasswordRequest, ResetPasswordRequest
from app.auth.utils import (
    hash_password, verify_password,
    create_access_token, decode_token,
    create_raw_refresh_token, hash_refresh_secret, verify_refresh_secret, extract_request_fingerprint,
    generate_fingerprint
)
from app.config import settings

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional



router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/swagger-login",
    scopes={
        "read": "Read access to protected resources.",
        "write": "Write access to protected resources.",
        "admin": "Administrative privileges."
    },
)



def _get_client_ip(request: Request) -> Optional[str]:
    # If behind proxy you may want to trust X-Forwarded-For
    return request.client.host if request.client else None

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(email=user.email, password=hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# ---------- Swagger login endpoint -------------------------------------------
@router.post("/swagger-login", response_model=TokenResponse)
def login_swagger(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None, db: Session = Depends(get_db)):
    """
    OAuth2 login endpoint for Swagger UI.
    Form data: username, password, scope.
    """
    return authenticate_user(email=form_data.username, password=form_data.password, db=db, request=request)


# ---------- LOGIN (now issues hashed refresh token & single-device) ----------
@router.post("/login", response_model=TokenResponse)
def login_json(login_req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return authenticate_user(email=login_req.email, password=login_req.password, db=db, request=request)


# ---------- REFRESH ----------
@router.post("/refresh")
def refresh(request:Request, refresh_token: str = Body(..., embed=True), db: Session = Depends(get_db)):
    """
    Body: { "refresh_token": "<jti>.<secret>" }
    We split by '.' to obtain jti + secret. Look up refresh row by jti, verify secret against token_hash.
    On success: rotate (delete old refresh row), create new refresh row, issue new access token.
    """
    now = datetime.now(timezone.utc)
    if not refresh_token or "." not in refresh_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token format")

    jti_part, secret_part = refresh_token.split(".", 1)
    rt = db.query(RefreshToken).filter(RefreshToken.jti == jti_part, RefreshToken.revoked == False).first()
    if not rt:
        raise HTTPException(status_code=401, detail="Invalid or revoked refresh token")

    if rt.expires_at < now:
        # cleanup
        db.delete(rt)
        db.commit()
        raise HTTPException(status_code=401, detail="Expired refresh token")

    # verify secret against stored hash
    if not verify_refresh_secret(secret_part, rt.token_hash):
        # possible attack; revoke this token row to be safe
        rt.revoked = True
        db.add(rt)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # lookup user
    user = db.query(User).get(rt.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid user")

    # rotate: delete old refresh token (single use)
    db.delete(rt)
    db.commit()

    # Get fingerprint from middleware
    fingerprint = getattr(request.state, "fingerprint", None)
    if not fingerprint:
        raise HTTPException(status_code=400, detail="Fingerprint missing from request")


    # issue new access token
    access_token_str, access_expires, access_jti = create_access_token(sub=str(user.id), fingerprint=fingerprint)
    new_access = Token(jti=access_jti, token=access_token_str, user_id=user.id, expires_at=access_expires)

    # create new refresh token (single-device enforced by deleting existing earlier)
    new_raw_refresh_token, new_refresh_expires, new_refresh_jti, new_refresh_secret = create_raw_refresh_token(days_valid=7)
    new_refresh_hash = hash_refresh_secret(new_refresh_secret)
    new_refresh_row = RefreshToken(jti=new_refresh_jti, token_hash=new_refresh_hash, user_id=user.id, expires_at=new_refresh_expires, revoked=False)

    db.add(new_access)
    db.add(new_refresh_row)
    db.add(user)
    db.commit()

    return {
        "access_token": access_token_str,
        "token_type": "bearer",
        "expires_at": access_expires,
        "refresh_token": new_raw_refresh_token,
        "refresh_expires_at": new_refresh_expires
    }

# ---------- LOGOUT ----------
@router.post("/logout")
def logout(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Logout removes the access token and any refresh tokens associated with the user.
    """
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        # token expired — still try to revoke refresh tokens if possible by user sub
        payload = None
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload:
        jti = payload.get("jti")
        sub = payload.get("sub")
        t = db.query(Token).filter(Token.jti == jti).first()
        if t:
            user_id = t.user_id
            db.delete(t)
            # revoke/delete any refresh tokens for that user (single-device)
            db.query(RefreshToken).filter(RefreshToken.user_id == user_id).delete()
            db.commit()
            return {"ok": True}
    # If token didn't map to a stored access token we cannot find user id reliably
    raise HTTPException(status_code=400, detail="Token not found or already invalidated")


# @router.post("/refresh", response_model=TokenResponse)
# def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
#     r = db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
#     now = datetime.now(timezone.utc)
#     if not r or r.revoked or r.expires_at < now:
#         raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
#
#     user = db.query(User).get(r.user_id)
#     if not user or not user.is_active:
#         raise HTTPException(status_code=401, detail="Invalid user")
#
#     # Rotate refresh token (optional)
#     new_refresh_token, new_refresh_expires, new_refresh_jti = create_refresh_token(user.id)
#     r.revoked = True
#     new_r = RefreshToken(
#         jti=new_refresh_jti,
#         token=new_refresh_token,
#         user_id=user.id,
#         expires_at=new_refresh_expires,
#     )
#
#     # Issue new access token
#     access_token, access_expires, jti = create_access_token(sub=str(user.id))
#     new_access = Token(
#         jti=jti,
#         token=access_token,
#         user_id=user.id,
#         expires_at=access_expires
#     )
#
#     db.add(new_access)
#     db.add(new_r)
#     db.commit()
#
#     return {
#         "access_token": access_token,
#         "refresh_token": new_refresh_token,
#         "expires_at": access_expires,
#         "refresh_expires_at": new_refresh_expires,
#         "token_type": "bearer",
#     }


# @router.post("/logout")
# def logout(request, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
#     try:
#         payload = decode_token(token)
#     except Exception:
#         raise HTTPException(status_code=401, detail="Invalid token")
#     jti = payload.get("jti")
#     t = db.query(Token).filter(Token.jti == jti).first()
#     if t:
#         # delete access token
#         db.delete(t)
#         # also revoke all refresh tokens for this user
#         db.query(RefreshToken).filter(RefreshToken.user_id == t.user_id, RefreshToken.revoked == False).update({"revoked": True})
#         db.commit()
#         return {"ok": True}
#     raise HTTPException(status_code=400, detail="Token not found")



# Helper dependency: get current user and ensure token exists in DB
def get_current_user(request: Request, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Validate fingerprint consistency
    expected_fingerprint = payload.get("fingerprint")
    actual_fingerprint = getattr(request.state, "fingerprint", None)
    if not expected_fingerprint or expected_fingerprint != actual_fingerprint:
        raise HTTPException(status_code=401, detail="Session fingerprint mismatch (possible hijack)")

    jti = payload.get("jti")
    sub = payload.get("sub")
    if not jti or not sub:
        raise HTTPException(status_code=401, detail="Malformed token")

    # token must exist in DB and belong to same user
    token_obj = db.query(Token).filter(Token.jti == jti, Token.user_id == int(sub)).first()
    if not token_obj:
        # token deleted/revoked -> force re-login
        raise HTTPException(status_code=401, detail="Token revoked or not found")

    now = datetime.now(timezone.utc)
    expires_at = token_obj.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < now:
        raise HTTPException(status_code=401, detail="Token expired")

    # --- fingerprint check ---
    ip, ua = extract_request_fingerprint(request)
    incoming_fp = generate_fingerprint(ip, ua)

    # token_obj.user_agent_hash may be None if issued without fingerprint (back-compat)
    if token_obj.user_agent_hash:
        if token_obj.user_agent_hash != incoming_fp:
            # Possible hijack: revoke token and raise
            token_obj.revoked = True
            db.add(token_obj)
            db.commit()
            raise HTTPException(status_code=401, detail="Session mismatch detected")

    # finally, fetch user
    user = db.query(User).get(token_obj.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive user")
    # optional check if account locked
    if user.locked_until and user.locked_until > now:
        raise HTTPException(status_code=423, detail="Account locked")
    return user

# Example protected route
@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user

# Forgot password: generate reset token and expiry
@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        # do not reveal existence in prod — but for dev return 200 anyway
        return {"ok": True, "message": "If an account exists, an email will be sent."}

    reset_token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.PASSWORD_RESET_EXPIRE_SECONDS)
    user.reset_token = reset_token
    user.reset_expires_at = expires_at
    db.add(user)
    db.commit()
    # In prod: send email containing reset_token (link). For dev we return the token.
    return {"ok": True, "reset_token": reset_token, "expires_at": expires_at.isoformat()}

# Reset password using reset_token
@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.reset_token == req.reset_token).first()
    now = datetime.now(timezone.utc)
    if not user or not user.reset_expires_at or user.reset_expires_at < now:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    # set new password
    user.password = hash_password(req.new_password)
    user.reset_token = None
    user.reset_expires_at = None
    # reset failed attempts + lock
    user.failed_attempts = 0
    user.locked_until = None
    db.add(user)
    db.commit()
    return {"ok": True}
