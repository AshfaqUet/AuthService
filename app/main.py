# app/main.py
from fastapi import FastAPI
from app.database import Base, engine
from app.auth.routes import router as auth_router
from app.middleware.security import RequestSmugglingGuardMiddleware, FingerprintMiddleware
from app.middleware.session_middleware import SessionIntegrityMiddleware

app = FastAPI(title="AuthService")

# Middleware order matters: security layers first
app.add_middleware(RequestSmugglingGuardMiddleware)
app.add_middleware(FingerprintMiddleware)
app.add_middleware(SessionIntegrityMiddleware)

Base.metadata.create_all(bind=engine)

app.include_router(auth_router, prefix="/auth", tags=["Auth"])

@app.get("/")
def root():
    return {"message": "Auth Service is running 🚀"}
