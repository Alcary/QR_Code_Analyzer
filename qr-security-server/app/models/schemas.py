from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str


class MLDetails(BaseModel):
    ensemble_score: float = Field(description="Combined ML probability (0=safe, 1=malicious)")
    xgb_score: float = Field(description="XGBoost probability")
    bert_score: float = Field(description="DistilBERT probability")
    xgb_weight: float = Field(description="XGBoost weight in ensemble")
    dampened_score: float = Field(description="ML score after reputation dampening")


class DomainDetails(BaseModel):
    registered_domain: str
    full_domain: str
    reputation_tier: str
    dampening_factor: float
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
    status: str  # 'safe', 'danger', 'suspicious'
    message: str
    risk_score: float = Field(0.0, description="Overall risk score 0.0-1.0")
    details: ScanDetails | None = None
