from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "QR Security Scanner API"
    API_V1_STR: str = "/api/v1"
    
    # CORS Configuration
    BACKEND_CORS_ORIGINS: list[str] = ["*"] # Allow all for demo/mobile app

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
