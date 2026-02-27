from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "QR Security Scanner API"
    API_V1_STR: str = "/api/v1"

    # ── Environment ───────────────────────────────────────────
    # "dev"        — relaxed defaults (no API key required, CORS *).
    # "production" — API_KEY must be set, CORS wildcard is rejected.
    ENVIRONMENT: str = "dev"

    # ── Authentication ────────────────────────────────────────
    # Set via API_KEY env var or .env file. Leave empty to disable (dev mode).
    API_KEY: str = ""

    # ── CORS ──────────────────────────────────────────────────
    # In production, restrict to your mobile app's origin.
    # Example: ["https://yourapp.com"] or ["*"] for dev.
    BACKEND_CORS_ORIGINS: list[str] = ["*"]

    # ── Rate Limiting ─────────────────────────────────────────
    # Requests per minute per IP address.
    RATE_LIMIT_PER_MINUTE: int = 30

    # ── Reverse Proxy ──────────────────────────────────────
    # How many trusted reverse proxy hops sit in front of this server.
    #   0 = no proxy — use the raw TCP peer address (request.client.host).
    #   1 = one proxy (nginx / caddy / ALB) that appends to X-Forwarded-For.
    #   N = N proxies — strip N entries from the right of X-Forwarded-For.
    #
    # WARNING: setting this > 0 without an actual trusted proxy in front
    # lets clients forge X-Forwarded-For and spoof their IP, bypassing
    # rate limiting entirely. Only enable when a proxy is confirmed present.
    TRUSTED_PROXY_COUNT: int = 0

    # ── Input Validation ──────────────────────────────────────
    MAX_URL_LENGTH: int = 2048
    ALLOWED_SCHEMES: list[str] = ["http", "https"]

    # ── Model directory (relative to server root) ─────────────
    MODEL_DIR: str = "models"

    # ── Analysis timeouts (seconds) ───────────────────────────
    NETWORK_TIMEOUT: float = 8.0
    WHOIS_TIMEOUT: float = 5.0

    # ── Cache ─────────────────────────────────────────────────
    CACHE_MAX_SIZE: int = 2000
    CACHE_TTL: int = 3600  # 1 hour

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
