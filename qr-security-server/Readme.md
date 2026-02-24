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

- `GET /health` - Health check
- `POST /api/scan` - Analyze QR code
