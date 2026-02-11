from pydantic import BaseModel

class ScanRequest(BaseModel):
    url: str

class ScanResult(BaseModel):
    status: str  # 'safe', 'danger', 'suspicious'
    message: str
    details: dict | None = None
