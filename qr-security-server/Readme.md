# QR Security Server

A FastAPI-based server for analyzing and validating QR codes with advanced security features.

## Features

- **QR Code Analysis**: Scan and decode QR codes
- **URL Security**: Analyze embedded URLs for malicious content
- **Homograph Detection**: Identify homograph attacks in domain names
- **Domain Reputation**: Check domain reputation scores
- **Network Inspection**: Inspect network characteristics
- **ML Prediction**: Machine learning-based threat prediction
- **Explainability**: Understand prediction reasoning

## Project Structure

```
app/
├── api/              # API endpoints and middleware
├── core/             # Configuration and security
├── models/           # Data schemas
└── services/         # Business logic and analyzers
scripts/              # Testing utilities
```

## API Endpoints

- `GET /api/v1/health` - Health check
- `POST /api/v1/scan` - Analyze URL

### POST /api/v1/scan

**Request**

```json
{
  "url": "https://example.com"
}
```

**Response**

```json
{
  "status": "safe",
  "message": "No threats detected",
  "risk_score": 0.12,
  "details": {
    "ml": {
      "ml_score": 0.08,
      "xgb_score": 0.08,
      "dampened_score": 0.05,
      "explanation": []
    },
    "domain": {
      "registered_domain": "example.com",
      "reputation_tier": "neutral",
      "dampening_factor": 0.7
    },
    "network": {
      "dns_resolved": true,
      "ssl_valid": true,
      "http_status": 200,
      "redirect_count": 0
    },
    "risk_factors": [],
    "analysis_time_ms": 320
  }
}
```

`status` is one of `"safe"`, `"suspicious"`, or `"danger"`.
