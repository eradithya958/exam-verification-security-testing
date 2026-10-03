import os
import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "Exam Verification & Integrity System"
    API_PREFIX: str = "/api"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Remediated: Secure secret key configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "prod-secure-random-" + secrets.token_hex(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours
    
    # SQLite default, or override with PostgreSQL
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./exam_system.db")
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")
    
    # Remediated CORS: Configurable allowed origins list
    ALLOWED_ORIGINS: list = ["http://localhost:3000", "http://localhost:8000", "https://exam.university.edu"]
    
    model_config = SettingsConfigDict(case_sensitive=True)

settings = Settings()
