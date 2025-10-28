# app/config.py
from pydantic_settings import BaseSettings
from datetime import timedelta

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./auth.db"
    JWT_SECRET: str = "change-me-to-a-very-secret-key"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 3600  # 1 hour
    MAX_FAILED_ATTEMPTS: int = 5
    LOCK_TIME_SECONDS: int = 300  # 5 minutes
    PASSWORD_RESET_EXPIRE_SECONDS: int = 3600  # 1 hour

    class Config:
        env_file = ".env"

settings = Settings()
