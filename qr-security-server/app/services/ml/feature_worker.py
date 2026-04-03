"""
Top-level worker module for parallel URL feature extraction.

Must be a named importable module (not an inline lambda/closure) so that
ProcessPoolExecutor can pickle it on Windows, where multiprocessing uses
the 'spawn' start method.

Usage (from training notebook):
    from app.services.ml.feature_worker import extract_one
    with ProcessPoolExecutor() as ex:
        results = list(ex.map(extract_one, urls, chunksize=100))
"""

import os

# Minimal env vars so pydantic-settings doesn't raise at import time.
for _var, _default in [
    ("MODEL_DIR", "models"),
    ("ENVIRONMENT", "dev"),
    ("BROWSER_SERVICE_URL", "http://localhost:3000"),
    ("REDIS_URL", ""),
]:
    os.environ.setdefault(_var, _default)

from app.services.url_features import extract_features, FEATURE_NAMES  # noqa: E402


def extract_one(url: str) -> dict:
    """Extract URL features for a single URL. Returns zero-filled dict on error."""
    try:
        return extract_features(str(url))
    except Exception:
        return {name: 0 for name in FEATURE_NAMES}
