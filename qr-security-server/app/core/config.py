from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "QR Security Scanner API"
    API_V1_STR: str = "/api/v1"

    # CORS
    BACKEND_CORS_ORIGINS: list[str] = ["*"]

    # Model directory (relative to server root)
    MODEL_DIR: str = "models"

    # Analysis timeouts (seconds)
    NETWORK_TIMEOUT: float = 8.0
    WHOIS_TIMEOUT: float = 5.0

    # Cache
    CACHE_MAX_SIZE: int = 2000
    CACHE_TTL: int = 3600  # 1 hour

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
