# QR Code Security Scanner

A mobile application for scanning QR codes and analyzing URLs for security threats before the user opens them. Built as a bachelor's degree project.

## Overview

This project consists of two main components:

- **Mobile App** (`qr-security-scanner`): React Native/Expo application for scanning QR codes
- **Backend Server** (`qr-security-server`): Python FastAPI service for multi-layer URL security analysis

## Features

### Mobile App

- Real-time QR code scanning via camera
- Image-based QR scanning from the photo gallery
- Confirmation step before running security analysis on URLs
- Risk score visualization with explainability cards showing threat indicators
- Detailed result view: domain trust, network info, browser-extracted page features, and ordered risk factors
- Local scan history with per-entry deletion and full history clear
- History saving can be toggled by the user

### Backend Server

- Multi-layer URL security analysis pipeline
- ML-based threat detection (XGBoost)
- Containerized Playwright browser renders pages and extracts ~35 content-level signals (form analysis, script obfuscation, brand impersonation, redirect chains, iframe abuse, etc.)
- DNS, SSL/TLS, WHOIS, and HTTP inspection
- Domain reputation and trust scoring
- Lexical and structural URL heuristics
- SSRF protection: private/reserved IPs are blocked before any outbound request
- Redis-backed scan result cache and sliding-window rate limiter (both fall back to in-memory when Redis is unavailable)
- Structured, explainable response: risk score, verdict, and ordered risk factors

## Architecture

```
Mobile App  →  FastAPI Backend  →  Browser Service (Playwright/Chromium)
                     ↕
                   Redis
```

Three Docker services run together via `docker-compose`:

| Service | Description |
|---|---|
| `api` | FastAPI backend, main analysis orchestrator |
| `browser` | Playwright/Chromium microservice for page rendering |
| `redis` | Result cache and rate limiter |

### Scoring weights

When the browser service is available:
- `0.40 ML + 0.20 network + 0.25 browser + 0.15 heuristic`

When the browser service is unavailable (fallback):
- `0.55 ML + 0.25 network + 0.20 heuristic`

### Verdicts

The backend returns one of three statuses: `safe`, `suspicious`, or `danger`.