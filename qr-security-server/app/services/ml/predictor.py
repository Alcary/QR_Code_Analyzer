"""
ML Ensemble Predictor

Loads and runs the trained ensemble:
- XGBoost (Platt-calibrated) on 100+ URL features
- DistilBERT (fine-tuned) on raw URL text
- Combined via optimized ensemble weight (α)

Models are expected in the `models/` directory:
  models/
    xgb_model.pkl                  — CalibratedClassifierCV(XGBClassifier)
    feature_names.json             — ordered list of feature names
    distilbert_url_classifier/     — HuggingFace model directory
    ensemble_config.json           — {"alpha": 0.xx, ...}
"""

import json
import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


class EnsemblePredictor:
    """Runs XGBoost + DistilBERT ensemble for binary URL classification."""

    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.loaded = False
        self.xgb_model = None
        self.feature_names: list[str] = []
        self.bert_model = None
        self.bert_tokenizer = None
        self.alpha = 0.5  # XGBoost weight in ensemble (1-α for BERT)
        self.device = None
        self._load_models()

    # ── Model Loading ──────────────────────────────────────────

    def _load_models(self):
        """Load all model artifacts. Graceful if missing."""
        xgb_ok = self._load_xgboost()
        bert_ok = self._load_bert()
        self._load_ensemble_config()

        if xgb_ok and bert_ok:
            self.loaded = True
            logger.info("Ensemble loaded (XGBoost + DistilBERT, alpha=%.2f)", self.alpha)
        elif xgb_ok:
            self.loaded = True
            logger.warning("Only XGBoost loaded (DistilBERT missing)")
        elif bert_ok:
            self.loaded = True
            logger.warning("Only DistilBERT loaded (XGBoost missing)")
        else:
            logger.warning("No ML models found in %s — running without ML", self.model_dir)

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

    def _load_bert(self) -> bool:
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            bert_dir = self.model_dir / "distilbert_url_classifier"
            if not bert_dir.exists():
                logger.info("DistilBERT not found: %s", bert_dir)
                return False

            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.bert_tokenizer = AutoTokenizer.from_pretrained(str(bert_dir))
            self.bert_model = AutoModelForSequenceClassification.from_pretrained(str(bert_dir))
            self.bert_model.to(self.device)
            self.bert_model.eval()

            logger.info("DistilBERT loaded from %s (device: %s)", bert_dir, self.device)
            return True
        except Exception as e:
            logger.error("Failed to load DistilBERT: %s", e)
            return False

    def _load_ensemble_config(self) -> bool:
        try:
            config_path = self.model_dir / "ensemble_config.json"
            if not config_path.exists():
                logger.info("ensemble_config.json not found, using alpha=0.5")
                return False

            with open(config_path) as f:
                cfg = json.load(f)

            self.alpha = cfg.get("alpha", 0.5)
            logger.info("Ensemble config: alpha=%.3f", self.alpha)
            return True
        except Exception as e:
            logger.error("Failed to load ensemble config: %s", e)
            return False

    # ── Prediction ─────────────────────────────────────────────

    def predict(self, url: str) -> dict | None:
        """
        Run ensemble prediction.

        Returns dict:
            ensemble_score  — combined P(malicious) in [0, 1]
            xgb_score       — XGBoost P(malicious)
            bert_score      — DistilBERT P(malicious)
            xgb_weight      — alpha value used
        or None if no models loaded.
        """
        if not self.loaded:
            return None

        xgb_score = self._predict_xgboost(url)
        bert_score = self._predict_bert(url)

        # Ensemble
        if xgb_score is not None and bert_score is not None:
            ensemble = self.alpha * xgb_score + (1 - self.alpha) * bert_score
        elif xgb_score is not None:
            ensemble = xgb_score
        elif bert_score is not None:
            ensemble = bert_score
        else:
            return None

        return {
            "ensemble_score": float(ensemble),
            "xgb_score": float(xgb_score if xgb_score is not None else 0.5),
            "bert_score": float(bert_score if bert_score is not None else 0.5),
            "xgb_weight": float(self.alpha),
        }

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

    def _predict_bert(self, url: str) -> float | None:
        """DistilBERT prediction → P(malicious) in [0, 1]."""
        if self.bert_model is None or self.bert_tokenizer is None:
            return None
        try:
            import torch

            inputs = self.bert_tokenizer(
                url,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=128,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                logits = self.bert_model(**inputs).logits
                probs = torch.softmax(logits, dim=1)[0]

            return float(probs[1].item()) if len(probs) > 1 else float(probs[0].item())
        except Exception as e:
            logger.error("DistilBERT prediction error: %s", e)
            return None


# Singleton
predictor = EnsemblePredictor()