from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from app.core.config import settings


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to analyze")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if len(v) > settings.MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds maximum length of {settings.MAX_URL_LENGTH}")

        # Add scheme if missing (assume https)
        if not any(v.lower().startswith(f"{s}://") for s in settings.ALLOWED_SCHEMES):
            if "://" in v:
                scheme = v.split("://")[0].lower()
                raise ValueError(
                    f"Unsupported scheme '{scheme}'. Allowed: {settings.ALLOWED_SCHEMES}"
                )
            v = f"https://{v}"

        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError("Invalid URL: no hostname found")
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")

        return v


class FeatureContribution(BaseModel):
    """Single SHAP feature-attribution entry."""
    feature: str = Field(description="Feature name")
    shap_value: float = Field(description="SHAP value (positive=risk, negative=safe)")
    feature_value: float = Field(description="Raw feature value for this URL")
    direction: str = Field(description="'risk' or 'safe'")


class MLDetails(BaseModel):
    ml_score: float = Field(description="ML probability of malicious (0=safe, 1=malicious)")
    xgb_score: float = Field(description="XGBoost probability (same as ml_score)")
    dampened_score: float = Field(description="ML score after domain-trust dampening")
    explanation: list[FeatureContribution] | None = Field(
        None, description="SHAP feature-attribution explanations (top contributors)"
    )


class DomainDetails(BaseModel):
    registered_domain: str
    full_domain: str
    reputation_tier: str
    dampening_factor: float
    trust_description: str | None = None
    age_days: int | None = None
    registrar: str | None = None


class NetworkDetails(BaseModel):
    dns_resolved: bool | None = None
    dns_ttl: int | None = None
    dns_flags: list[str] = []
    ssl_valid: bool | None = None
    ssl_issuer: str | None = None
    ssl_days_until_expiry: int | None = None
    ssl_is_new_cert: bool | None = None
    http_status: int | None = None
    redirect_count: int = 0
    final_url: str | None = None
    content_flags: list[str] = []


class ScanDetails(BaseModel):
    ml: MLDetails | None = None
    domain: DomainDetails | None = None
    network: NetworkDetails | None = None
    risk_factors: list[str] = []
    analysis_time_ms: int | None = None


class ScanResult(BaseModel):
    status: str
    message: str
    risk_score: float = Field(0.0, description="Overall risk score 0.0-1.0")
    details: ScanDetails | None = None
