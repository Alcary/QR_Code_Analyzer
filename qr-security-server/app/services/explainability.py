"""
SHAP Explainability Engine

Provides per-prediction feature-attribution explanations using
SHAP (SHapley Additive exPlanations, Lundberg & Lee 2017).

For XGBoost we use TreeExplainer — an exact, polynomial-time
algorithm for tree ensembles that runs in O(TLD²) per prediction
(T = number of trees, L = max leaves, D = max depth).

Output format:
    [
        {"feature": "url_length",  "value": 0.12,  "direction": "risk"},
        {"feature": "has_https",   "value": -0.08, "direction": "safe"},
        ...
    ]

Each item shows how much a feature pushed the prediction away from
the base rate (expected value).  Positive SHAP value → increases
P(malicious); negative → decreases.
"""

import logging
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Guard import — shap is optional at import time
_shap = None


def _ensure_shap():
    """Lazy-load the shap module on first use."""
    global _shap
    if _shap is None:
        try:
            import shap
            _shap = shap
        except Exception as e:
            logger.warning(
                "shap package could not be loaded — explanations will be unavailable. "
                "Error: %s. Install/fix with: pip install --upgrade shap numpy", e
            )
    return _shap


class SHAPExplainer:
    """
    Wraps SHAP TreeExplainer for the XGBoost base learner.

    The explainer is initialised lazily on the first call to `explain()`
    to avoid blocking server startup.
    """

    def __init__(self):
        self._explainer = None
        self._base_value: float | None = None
        self._ready = False

    # ── Initialisation ─────────────────────────────────────────

    def init_from_model(self, xgb_model, feature_names: list[str]) -> bool:
        """
        Build the TreeExplainer from a fitted XGBoost model.

        Parameters
        ----------
        xgb_model : CalibratedClassifierCV or XGBClassifier
            The fitted XGBoost model (possibly wrapped in calibration).
        feature_names : list[str]
            Ordered feature names matching the training columns.

        Returns True if initialisation succeeded.
        """
        shap = _ensure_shap()
        if shap is None:
            return False

        try:
            # Unwrap CalibratedClassifierCV → underlying XGBClassifier
            raw_model = self._unwrap_xgb(xgb_model)
            if raw_model is None:
                logger.warning("Could not unwrap XGBoost model for SHAP")
                return False

            self._explainer = shap.TreeExplainer(raw_model)
            self._feature_names = feature_names
            self._base_value = float(self._explainer.expected_value)
            self._ready = True
            logger.info(
                "SHAP TreeExplainer initialised (base_value=%.4f, features=%d)",
                self._base_value,
                len(feature_names),
            )
            return True
        except Exception as e:
            logger.error("SHAP initialisation failed: %s", e)
            return False

    # ── Explanation ────────────────────────────────────────────

    def explain(
        self,
        feature_vector: dict[str, float],
        top_k: int = 8,
    ) -> Optional[dict]:
        """
        Explain a single prediction.

        Parameters
        ----------
        feature_vector : dict
            {feature_name: value} as returned by extract_features().
        top_k : int
            Number of top contributing features to return.

        Returns
        -------
        dict with:
            base_value         : float — expected value (average model output)
            contributions      : list[dict] — top-k features sorted by |SHAP|
            prediction_shift   : float — sum of all SHAP values (additive)
        or None if explainer is not ready.
        """
        if not self._ready or self._explainer is None:
            return None

        try:
            ordered = [feature_vector.get(name, 0.0) for name in self._feature_names]
            X = np.array([ordered], dtype=np.float32)

            shap_values = self._explainer.shap_values(X)

            # shap_values may be a list [class_0, class_1] for binary classification
            if isinstance(shap_values, list):
                sv = shap_values[1][0]  # SHAP values for class 1 (malicious)
            elif shap_values.ndim == 3:
                sv = shap_values[0, :, 1]  # (samples, features, classes)
            else:
                sv = shap_values[0]

            # Build ranked contributions
            abs_sv = np.abs(sv)
            top_indices = np.argsort(abs_sv)[::-1][:top_k]

            contributions = []
            for idx in top_indices:
                val = float(sv[idx])
                contributions.append({
                    "feature": self._feature_names[idx],
                    "shap_value": round(val, 4),
                    "feature_value": round(ordered[idx], 4),
                    "direction": "risk" if val > 0 else "safe",
                })

            return {
                "base_value": round(self._base_value, 4),
                "contributions": contributions,
                "prediction_shift": round(float(np.sum(sv)), 4),
            }

        except Exception as e:
            logger.error("SHAP explanation failed: %s", e)
            return None

    # ── Helpers ────────────────────────────────────────────────

    @staticmethod
    def _unwrap_xgb(model):
        """
        Dig through CalibratedClassifierCV to reach the
        underlying XGBClassifier.
        """
        # Direct XGBClassifier
        try:
            from xgboost import XGBClassifier

            if isinstance(model, XGBClassifier):
                return model
        except ImportError:
            pass

        # sklearn CalibratedClassifierCV wraps estimators in .calibrated_classifiers_
        if hasattr(model, "calibrated_classifiers_"):
            for cal in model.calibrated_classifiers_:
                base = getattr(cal, "estimator", getattr(cal, "base_estimator", None))
                if base is not None:
                    try:
                        from xgboost import XGBClassifier

                        if isinstance(base, XGBClassifier):
                            return base
                    except ImportError:
                        pass
                    # Return whatever the base is and let SHAP try
                    return base

        # Last resort — return model itself and hope SHAP handles it
        return model


# ── Singleton ──────────────────────────────────────────────────
shap_explainer = SHAPExplainer()
