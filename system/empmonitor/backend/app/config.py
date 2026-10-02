from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    DATABASE_URL: REDACTED
    SECRET_KEY: REDACTED
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    SCREENSHOT_STORAGE_PATH: str = "/app/screenshots"
    CORS_ORIGINS: str = "*"
    APP_NAME: str = "EmpMonitor API"
    APP_VERSION: str = "1.0.0"
    class Config:
        env_file = ".env"
settings = Settings()
