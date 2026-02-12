# QR Code Security Scanner

A mobile application that scans QR codes and validates URLs for security threats before allowing users to access them.

## Overview

This project consists of two main components:

- **Mobile App** (`qr-security-scanner`): React Native/Expo application for scanning QR codes
- **Backend Server** (`qr-security-server`): Python FastAPI service for URL security analysis

## Features

- Real-time QR code scanning
- Automatic URL extraction from QR codes
- Server-side security classification
- User warnings for potentially malicious links
- Blocks access to unsafe URLs
- ML-based threat detection

## Architecture

### Mobile App
- Built with React Native and Expo
- Camera permissions handling
- Real-time scanner overlay
- Security status modals and alerts
- Image scanning fallback

### Backend Server
- FastAPI-based REST API
- Machine learning predictor
- Domain reputation checking
- Network inspection utilities
- URL feature analysis

## Getting Started

### Prerequisites
- Node.js 16+ (mobile app)
- Python 3.8+ (server)
- Expo CLI (for mobile development)