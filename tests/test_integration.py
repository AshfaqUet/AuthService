import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from app.auth import authenticate_user
from app.middleware import (
    SessionIntegrityMiddleware,
    RequestSmugglingGuardMiddleware,
    FingerprintMiddleware,
)
from app.models import User


@pytest.fixture
def app_with_stack():
    app = FastAPI()

    # Add middlewares in correct order
    app.add_middleware(SessionIntegrityMiddleware)
    app.add_middleware(RequestSmugglingGuardMiddleware)
    app.add_middleware(FingerprintMiddleware)

    @app.post("/login")
    async def login(request: Request):
        data = await request.json()
        db = MagicMock()
        user = authenticate_user(
            email=data["email"],
            password=data["password"],
            db=db,
            request=request,
        )
        if not user:
            return {"error": "invalid credentials"}
        return {"user": user.email}

    return app


@pytest.fixture
def client(app_with_stack):
    return TestClient(app_with_stack)


def test_auth_success(client, monkeypatch):
    """Middleware stack allows valid auth."""
    mock_user = User(email="user@example.com", password="hashed")
    # monkeypatch.setattr("app.auth.authenticate_user", lambda **_: mock_user)
    monkeypatch.setattr("tests.test_integration.authenticate_user", lambda **_: mock_user)

    response = client.post("/login", json={"email": "user@example.com", "password": "secret"})
    assert response.status_code == 200
    assert response.json()["user"] == "user@example.com"


def test_auth_invalid_credentials(client, monkeypatch):
    """Auth should fail with invalid password."""
    monkeypatch.setattr("tests.test_integration.authenticate_user", lambda **_: None)
    response = client.post("/login", json={"email": "bad@example.com", "password": "wrong"})
    assert "error" in response.json()


def test_auth_fingerprint_block(client, monkeypatch):
    """Fingerprint middleware attaches fingerprint headers but doesn't block."""
    # Mock authentication to avoid touching real DB logic
    mock_user = User(email="user@example.com", password="hashed")
    monkeypatch.setattr("tests.test_integration.authenticate_user", lambda **_: mock_user)

    # Different user agents => different fingerprints
    r1 = client.post("/login", json={"email": "user@example.com", "password": "secret"},
                     headers={"User-Agent": "AgentA"})
    r2 = client.post("/login", json={"email": "user@example.com", "password": "secret"},
                     headers={"User-Agent": "AgentB"})

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.headers["X-Session-Fingerprint"] != r2.headers["X-Session-Fingerprint"]



def test_auth_request_smuggling_detected(client):
    """RequestSmugglingGuardMiddleware should block malformed body."""
    response = client.post("/login", data="malformed\n\nbody")
    assert response.status_code in (400, 403)
