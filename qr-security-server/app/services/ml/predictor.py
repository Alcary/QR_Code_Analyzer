import os
import logging
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logger = logging.getLogger(__name__)


class MLPredictor:
    """
    Predictor using the pre-trained BERT model from HuggingFace:
    r3ddkahili/final-complete-malicious-url-model
    
    Includes Temperature Scaling for probability calibration to reduce
    overconfident predictions that lead to false positives.
    
    Temperature Scaling:
    - T < 1.0: Makes probabilities more confident (sharper)
    - T = 1.0: No change (default softmax)
    - T > 1.0: Makes probabilities less confident (softer)
    
    The model tends to be overconfident on benign URLs that share lexical
    patterns with malicious ones (e.g., URLs with "login", "verify", etc.).
    A temperature of 1.5-2.0 helps calibrate these predictions.
    """
    
    # Temperature for probability calibration
    # Higher = less confident = fewer false positives
    # Empirically tuned for this model
    TEMPERATURE = 1.8
    
    def __init__(self, model_name: str = "r3ddkahili/final-complete-malicious-url-model"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.temperature = self.TEMPERATURE
        # Labels exactly as defined in the HuggingFace model card
        self.class_names = ["Benign", "Defacement", "Phishing", "Malware"]
        self._load_model()

    def _load_model(self):
        try:
            logger.info(f"Loading HuggingFace model: {self.model_name}...")
            # Detect device (GPU if available)
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Using device: {self.device}")

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.model.to(self.device)
            
            # Try to get labels from config (preserve original casing)
            # NOTE: We skip this for the r3ddkahili model because its config returns generic "LABEL_0", etc.
            # We strictly enforce the mapping provided in the model card: {0: Benign, 1: Defacement, 2: Phishing, 3: Malware}
            if hasattr(self.model.config, "id2label") and self.model.config.id2label:
                 # Check if labels are generic "LABEL_0" style
                 first_label = self.model.config.id2label[0]
                 if str(first_label).upper().startswith("LABEL_"):
                     logger.info("Config has generic labels. Using hardcoded class names.")
                     self.class_names = ["Benign", "Defacement", "Phishing", "Malware"]
                 else:
                    # Ensure correct order based on IDs (0, 1, 2...)
                    sorted_ids = sorted(self.model.config.id2label.keys())
                    self.class_names = [self.model.config.id2label[i] for i in sorted_ids]
                    logger.info(f"Loaded class names from config: {self.class_names}")
            else:
                logger.warning("No id2label found in config, using defaults.")

            self.model.eval() # Set to evaluation mode
            logger.info("Model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load HuggingFace model: {e}")
            self.model = None
            self.tokenizer = None

    def predict(self, url: str) -> dict | None:
        if self.model is None or self.tokenizer is None:
            logger.error("Model not loaded, cannot predict.")
            return None

        try:
            # Tokenize
            inputs = self.tokenizer(
                url, 
                return_tensors="pt", 
                truncation=True, 
                padding=True, 
                max_length=128
            )
            
            # Move inputs to device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Inference with Temperature Scaling
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                
                # Apply temperature scaling for calibration
                # This reduces overconfidence in predictions
                scaled_logits = logits / self.temperature
                probs = F.softmax(scaled_logits, dim=1)[0]
                
                # Also get raw (uncalibrated) probabilities for comparison
                raw_probs = F.softmax(logits, dim=1)[0]

            # Get predicted class (from calibrated probabilities)
            pred_idx = int(torch.argmax(probs).item())
            confidence = float(probs[pred_idx].item())
            raw_confidence = float(raw_probs[pred_idx].item())
            
            # Map index to label
            if pred_idx < len(self.class_names):
                pred_label = self.class_names[pred_idx]
            else:
                pred_label = "unknown"

            # Calculate "Malicious Score" (Probability of NOT being benign)
            # Use case-insensitive search for "Benign" label
            malicious_score = 0.0
            benign_idx = next((i for i, name in enumerate(self.class_names) if name.lower() == "benign"), None)
            if benign_idx is not None:
                malicious_score = float(1.0 - probs[benign_idx].item())
            else:
                # Fallback: assume index 0 is benign
                malicious_score = float(1.0 - probs[0].item())

            is_malicious = bool(pred_label.lower() != "benign")

            # Construct probabilities dict
            probs_dict = {
                name: float(probs[i].item()) 
                for i, name in enumerate(self.class_names) 
                if i < len(probs)
            }

            return {
                "pred_label": pred_label,
                "confidence": confidence,
                "malicious_score": malicious_score,
                "is_malicious": is_malicious,
                "probs": probs_dict,
                "model_used": self.model_name
            }

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return None

# Singleton instance
predictor = MLPredictor()