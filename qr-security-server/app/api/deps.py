"""
API Dependencies

Reusable FastAPI dependency functions for:
- Rate limiting
- Authentication
- Input validation
"""

from app.core.security import verify_api_key

__all__ = ["verify_api_key"]
