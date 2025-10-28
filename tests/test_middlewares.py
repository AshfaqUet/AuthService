from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from app.middleware import (
    SessionIntegrityMiddleware,
    RequestSmugglingGuardMiddleware,
    FingerprintMiddleware,
)


# --------------------------
# Fixtures
# --------------------------
@pytest.fixture
def base_app():
    app = FastAPI()

    @app.get("/ping")
    async def ping():
        return {"msg": "pong"}

    return app


# --------------------------
# SessionIntegrityMiddleware Tests
# --------------------------
def test_session_integrity_valid(base_app):
    app = base_app
    app.add_middleware(SessionIntegrityMiddleware)
    client = TestClient(app)

    # Normal request should pass
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"msg": "pong"}

def test_session_integrity_tampered(base_app, monkeypatch):
    app = base_app
    app.add_middleware(SessionIntegrityMiddleware)
    client = TestClient(app)

    # Patch dependencies as they are imported inside app.middleware.session_middleware
    monkeypatch.setattr(
        "app.middleware.session_middleware.decode_token",
        lambda t: {"jti": "1", "sub": "1"}
    )

    mock_db = MagicMock()
    mock_token_obj = MagicMock()
    mock_token_obj.user_agent_hash = "original_fp"
    mock_db.query().filter().first.return_value = mock_token_obj
    monkeypatch.setattr(
        "app.middleware.session_middleware.SessionLocal",
        lambda: mock_db
    )

    # Force mismatch
    monkeypatch.setattr(
        "app.middleware.session_middleware.extract_request_fingerprint",
        lambda r: ("1.1.1.1", "fakeUA")
    )
    monkeypatch.setattr(
        "app.middleware.session_middleware.generate_fingerprint",
        lambda ip, ua: "mismatched_fp"
    )

    response = client.get(
        "/ping",
        headers={"Authorization": "Bearer fake.jwt.token"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Session mismatch detected"

# --------------------------
# RequestSmugglingGuardMiddleware Tests
# --------------------------
def test_request_smuggling_valid(base_app):
    app = base_app
    app.add_middleware(RequestSmugglingGuardMiddleware)
    client = TestClient(app)

    response = client.get("/ping")
    assert response.status_code == 200


def test_request_smuggling_detects_malformed_body(base_app):
    app = base_app
    app.add_middleware(RequestSmugglingGuardMiddleware)
    client = TestClient(app)

    # Simulate smuggling attempt: both Content-Length and Transfer-Encoding
    response = client.post(
        "/ping",
        data="fakebody",
        headers={
            "Transfer-Encoding": "chunked",
            "Content-Length": "10",  # conflicting headers
        },
    )
    assert response.status_code == 400
    assert "conflicting" in response.text.lower()

# --------------------------
# FingerprintMiddleware Tests
# --------------------------
def test_fingerprint_valid(base_app):
    app = base_app
    app.add_middleware(FingerprintMiddleware)
    client = TestClient(app)

    response = client.get("/ping", headers={"X-Device-Fingerprint": "valid-fp"})
    assert response.status_code == 200


def test_fingerprint_mismatch(base_app):
    app = base_app
    app.add_middleware(FingerprintMiddleware)
    client = TestClient(app)

    # Two requests with different User-Agents should yield different fingerprints
    r1 = client.get("/ping", headers={"User-Agent": "AgentA"})
    r2 = client.get("/ping", headers={"User-Agent": "AgentB"})

    fp1 = r1.headers.get("X-Session-Fingerprint")
    fp2 = r2.headers.get("X-Session-Fingerprint")

    assert fp1 != fp2  # mismatch detected
    assert r1.status_code == 200
    assert r2.status_code == 200

