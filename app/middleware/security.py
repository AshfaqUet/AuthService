# app/middleware/security.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette import status
from hashlib import sha256
import json


class RequestSmugglingGuardMiddleware(BaseHTTPMiddleware):
    """
    Protects against HTTP request smuggling attacks
    by validating Transfer-Encoding and Content-Length headers.
    """
    async def dispatch(self, request: Request, call_next):
        headers = {k.decode().lower(): v.decode() for k, v in request.scope.get("headers", [])}
        te = headers.get("transfer-encoding")
        cl = headers.get("content-length")

        # Rule 1: Reject conflicting TE and CL
        if te is not None and cl is not None:
            return Response(
                content="Bad Request: conflicting Transfer-Encoding and Content-Length",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Rule 2: Validate TE
        if te is not None:
            encodings = [part.strip().lower() for part in te.split(",")]
            if any(e != "chunked" for e in encodings):
                return Response(
                    content="Bad Request: unsupported Transfer-Encoding",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )

        # Rule 3: Validate Content-Length matches actual body
        if cl is not None:
            try:
                expected = int(cl)
            except ValueError:
                return Response(
                    content="Bad Request: invalid Content-Length",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )

            body = await request.body()
            actual = len(body)
            if actual != expected:
                return Response(
                    content="Bad Request: Content-Length mismatch",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )

            # Restore body for downstream usage
            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = receive

        # ✅ Rule 4: Block malformed bodies (non-JSON in POST/PUT requests)
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = headers.get("content-type", "")
            if "application/json" in content_type or not content_type:
                try:
                    json.loads(body.decode() or "{}")
                except Exception:
                    return Response(
                        content="Bad Request: malformed request body",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )

        # Strip TE/CL headers downstream (optional for safety)
        new_headers = [
            (k, v)
            for (k, v) in request.scope["headers"]
            if k.decode().lower() not in ("transfer-encoding", "content-length")
        ]
        request.scope["headers"] = new_headers

        return await call_next(request)


class FingerprintMiddleware(BaseHTTPMiddleware):
    """
    Prevent session hijacking by binding tokens to a fingerprint
    derived from client headers.
    """
    async def dispatch(self, request: Request, call_next):
        # Compute a simple fingerprint based on IP + User-Agent
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        fingerprint = sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()

        # Attach fingerprint for downstream token validation
        request.state.fingerprint = fingerprint
        response = await call_next(request)
        response.headers["X-Session-Fingerprint"] = fingerprint[:16]  # debug / audit trace
        return response
