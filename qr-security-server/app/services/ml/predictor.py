"""
ML Predictor — v4 (XGBoost-only)

Loads and runs the XGBoost classifier on 95 handcrafted URL features.
The 95 features (entropy, structure, homograph detection, n-grams, etc.)
already capture the character-level patterns that CharCNN was meant to
learn, but more reliably and interpretably.

v4 changes (simplification):
- Removed CharCNN and meta-learner — XGBoost alone with 95 features
  proved more robust than the ensemble which suffered from training
  data format bias in the CharCNN component.
- Removed URL normalization hack (was needed only to work around
  CharCNN's sensitivity to bare domains vs. trailing-slash domains).
- SHAP TreeExplainer provides direct per-feature explanations.

Models expected in `models/`:
  models/
    xgb_model.pkl       — CalibratedClassifierCV(XGBClassifier)
    feature_names.json  — ordered list of 95 feature names
"""

import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np

from app.core.config import settings

logger = logging.getLogger(__name__)

# Server root = the directory that contains the `app/` package.
# Resolving relative to __file__ makes the path CWD-independent:
# uvicorn can be launched from any working directory.
#   predictor.py  →  app/services/ml/predictor.py
#   parents[3]    →  <server-root>/  (sibling of app/)
_SERVER_ROOT = Path(__file__).resolve().parents[3]


class MLPredictor:
    """XGBoost-based URL classifier with SHAP explanations."""

    def __init__(self, model_dir: str | Path | None = None):
        # Resolve model directory:
        #   1. If an explicit path is given, use it as-is (absolute) or
        #      relative to CWD (useful for tests).
        #   2. Otherwise, take settings.MODEL_DIR and resolve it relative to
        #      the server root so the server works regardless of the CWD from
        #      which uvicorn / the test runner is invoked.
        if model_dir is not None:
            self.model_dir = Path(model_dir)
        else:
            cfg_path = Path(settings.MODEL_DIR)
            self.model_dir = (
                cfg_path if cfg_path.is_absolute() else _SERVER_ROOT / cfg_path
            )
        self.loaded = False
        self.xgb_model = None
        self.feature_names: list[str] = []
        self._shap_explainer = None
        self._load_models()

    # ── Model Loading ──────────────────────────────────────────

    def _load_models(self):
        """Load XGBoost model and feature names."""
        xgb_ok = self._load_xgboost()

        if xgb_ok:
            self.loaded = True
            logger.info(
                "ML predictor loaded (XGBoost, %d features)",
                len(self.feature_names),
            )
            self._init_shap()
        else:
            logger.warning("No ML model found in %s — running without ML", self.model_dir)

    def _load_xgboost(self) -> bool:
        try:
            import joblib

            model_path = self.model_dir / "xgb_model.pkl"
            names_path = self.model_dir / "feature_names.json"

            if not model_path.exists():
                logger.info("XGBoost model not found: %s", model_path)
                return False

            self.xgb_model = joblib.load(model_path)
            logger.info("XGBoost model loaded from %s", model_path)

            if names_path.exists():
                with open(names_path) as f:
                    self.feature_names = json.load(f)
                logger.info("Loaded %d feature names", len(self.feature_names))
            else:
                from app.services.url_features import FEATURE_NAMES

                self.feature_names = FEATURE_NAMES
                logger.warning("feature_names.json not found, using module defaults")

            return True
        except Exception as e:
            logger.error("Failed to load XGBoost: %s", e)
            return False

    def _init_shap(self) -> bool:
        """Initialise the SHAP explainer with the loaded XGBoost model."""
        try:
            from app.services.explainability import shap_explainer
            ok = shap_explainer.init_from_model(self.xgb_model, self.feature_names)
            if ok:
                self._shap_explainer = shap_explainer
            return ok
        except Exception as e:
            logger.error("SHAP init failed: %s", e)
            return False

    # ── Prediction ─────────────────────────────────────────────

    def predict(self, url: str) -> dict | None:
        """
        Run XGBoost prediction on a URL.

        Returns dict:
            ml_score    — P(malicious) in [0, 1]
            xgb_score   — same as ml_score (backward compat)
            explanation — SHAP feature contributions (if available)
        or None if model not loaded.
        """
        if not self.loaded:
            return None

        score = self._predict_xgboost(url)
        if score is None:
            return None

        return {
            "ml_score": float(score),
            "xgb_score": float(score),
            "explanation": self._explain(url),
        }

    def _explain(self, url: str) -> Optional[dict]:
        """Generate SHAP feature-attribution explanation."""
        if self._shap_explainer is None:
            return None
        try:
            from app.services.url_features import extract_features
            features = extract_features(url)
            return self._shap_explainer.explain(features, top_k=8)
        except Exception as e:
            logger.error("SHAP explanation error: %s", e)
            return None

    def _predict_xgboost(self, url: str) -> float | None:
        """XGBoost prediction → P(malicious) in [0, 1]."""
        if self.xgb_model is None:
            return None
        try:
            from app.services.url_features import extract_features

            feats = extract_features(url)
            ordered = [feats.get(name, 0) for name in self.feature_names]
            X = np.array([ordered], dtype=np.float32)

            proba = self.xgb_model.predict_proba(X)[0]
            return float(proba[1]) if len(proba) > 1 else float(proba[0])
        except Exception as e:
            logger.error("XGBoost prediction error: %s", e)
            return None


# Singleton — model directory resolved from settings, CWD-independent.
predictor = MLPredictor()