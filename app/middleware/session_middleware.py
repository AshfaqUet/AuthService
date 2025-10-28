# app/middleware/session_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.database import SessionLocal
from app.auth.utils import extract_request_fingerprint, generate_fingerprint, decode_token
from app.models import Token
import jwt

class SessionIntegrityMiddleware(BaseHTTPMiddleware):
    """
    Middleware that attempts to detect token reuse from different client context.
    If Authorization Bearer token present and fingerprint mismatch -> revoke token and block.
    This runs BEFORE routes and protects all endpoints.
    """

    async def dispatch(self, request: Request, call_next):
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
            try:
                payload = decode_token(token)
                jti = payload.get("jti")
                sub = payload.get("sub")
                if jti and sub:
                    db = SessionLocal()
                    try:
                        token_obj = db.query(Token).filter(Token.jti == jti, Token.user_id == int(sub)).first()
                        if token_obj and token_obj.user_agent_hash:
                            # compute incoming fp
                            ip, ua = extract_request_fingerprint(request)
                            incoming_fp = generate_fingerprint(ip, ua)
                            if token_obj.user_agent_hash != incoming_fp:
                                # revoke token and respond 401
                                token_obj.revoked = True
                                db.add(token_obj)
                                db.commit()
                                # return early 401
                                return JSONResponse({"detail": "Session mismatch detected"}, status_code=401)
                    finally:
                        db.close()
            except jwt.ExpiredSignatureError:
                # let route-level handler respond as expired
                pass
            except Exception:
                # any decode error -> continue to routing (route will handle invalid token)
                pass

        response = await call_next(request)
        return response
