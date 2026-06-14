from transformers import pipeline as hf_pipeline
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Full expanded scam taxonomy for Indian cybercrime patterns
SCAM_LABELS = [
    "Job Scam",
    "Loan Scam",
    "Investment Scam",
    "UPI Fraud",
    "KYC Scam",
    "Phishing",
    "Sextortion",
    "Crypto Scam",
    "Fake Government Scheme",
    "Courier Parcel Scam",
    "Safe / Non-Scam",
]


class ScamClassifier:
    """
    Zero-shot scam classification using DistilBERT MNLI.
    Falls back to keyword heuristics if the model is unavailable.
    """

    def __init__(self):
        self._model = None
        self.candidate_labels = SCAM_LABELS
        self._load_model()

    def _load_model(self):
        """Lazy-load the transformer model with graceful fallback."""
        try:
            self._model = hf_pipeline(
                "zero-shot-classification",
                model="typeform/distilbert-base-uncased-mnli",
                device=-1,   # CPU; set to 0 for CUDA GPU
            )
            logger.info("[ScamClassifier] Zero-shot model loaded successfully.")
        except Exception as exc:
            logger.warning(
                "[ScamClassifier] Could not load transformer model (%s). "
                "Falling back to keyword heuristics.",
                exc,
            )
            self._model = None

    # ------------------------------------------------------------------
    # Keyword fallback heuristics (works offline without model weights)
    # ------------------------------------------------------------------
    _KEYWORD_MAP = {
        "Job Scam": ["part-time", "earn money", "work from home", "like task", "tmart", "youtube like"],
        "Loan Scam": ["instant loan", "rupeespeedy", "loan approval", "200% interest", "recovery agent"],
        "Investment Scam": ["stock tips", "pump and dump", "crypto profit", "guaranteed returns", "wealth advisory"],
        "KYC Scam": ["kyc update", "kyc verification", "netbanking blocked", "account suspended", "update kyc"],
        "Phishing": ["click here", "verify now", "login", "password reset", "account blocked"],
        "UPI Fraud": ["upi", "paytm", "phonepe", "gpay", "bhim", "transfer now"],
        "Fake Government Scheme": ["pm yojana", "government grant", "subsidy", "customs officer", "irs refund"],
        "Courier Parcel Scam": ["customs", "parcel held", "fedex", "dhl", "clearance fee", "mdma"],
        "Sextortion": ["nude", "compromising", "video call", "blackmail", "screenshot", "morphed"],
        "Crypto Scam": ["bitcoin", "crypto", "wallet", "binance", "usdt", "blockchain bonus"],
    }

    def _keyword_classify(self, text: str) -> tuple[str, float]:
        text_lower = text.lower()
        best_label = "Safe / Non-Scam"
        best_count = 0

        for label, keywords in self._KEYWORD_MAP.items():
            count = sum(1 for kw in keywords if kw in text_lower)
            if count > best_count:
                best_count = count
                best_label = label

        confidence = min(best_count * 0.2, 0.9) if best_count > 0 else 0.0
        return best_label, confidence

    def classify_text(self, text: str) -> tuple[str, float]:
        """
        Returns (label, confidence_score).
        Confidence is a float in [0, 1].
        """
        words = [w for w in text.split() if w.strip()]

        # Heuristic: bare URL with no context → not actionable
        if len(words) == 1 and (words[0].startswith("http://") or words[0].startswith("https://")):
            return "Safe / Non-Scam", 0.0

        # Very short text → unreliable classification
        if len(words) < 5:
            label, conf = self._keyword_classify(text)
            return label, conf

        if self._model is not None:
            try:
                result = self._model(text[:512], candidate_labels=self.candidate_labels)
                top_label: str = result["labels"][0]
                top_score: float = result["scores"][0]

                if top_score < settings.CLASSIFIER_CONFIDENCE_THRESHOLD:
                    return "Safe / Non-Scam", top_score

                return top_label, top_score
            except Exception as exc:
                logger.error("[ScamClassifier] Inference error: %s. Using keyword fallback.", exc)

        # Fallback to keyword heuristics
        return self._keyword_classify(text)