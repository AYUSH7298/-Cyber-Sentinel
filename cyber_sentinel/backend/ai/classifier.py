from transformers import pipeline as hf_pipeline
from backend.config import settings
import logging

logger = logging.getLogger(__name__)

# ─── Expanded 18-category Indian cybercrime taxonomy ──────────────────────────
# Added: Sextortion, Fake Government Scheme, Courier/Parcel Scam,
#        Electricity/Utility Scam, Bank Impersonation, Romance Scam,
#        Digital Arrest Scam (new MHA-classified threat)
SCAM_LABELS = [
    "UPI Fraud",
    "Fake Trading App",
    "Loan App Scam",
    "Investment Scam",
    "Job Scam",
    "OTP Scam",
    "KYC Scam",
    "Fake Customer Care Scam",
    "Crypto Scam",
    "Phishing Campaign",
    "Malware Distribution",
    "APK Distribution Fraud",
    "Sextortion",
    "Fake Government Scheme",
    "Courier Parcel Scam",
    "Electricity Utility Scam",
    "Bank Impersonation",
    "Romance Scam",
    "Digital Arrest Scam",
    "Safe / Non-Scam",
]

# ─── Two-stage classification: fast keyword check → slow NLI model ────────────
# The keyword map now includes Hinglish transliterations of common scam terms
_KEYWORD_MAP: dict[str, list[str]] = {
    "UPI Fraud": [
        "upi", "paytm", "phonepe", "gpay", "bhim", "transfer now",
        "paisa bhejo", "paise transfer", "qr scan karo", "upi link",
        "payment link", "transaction fail", "upi block",
    ],
    "Fake Trading App": [
        "trading app", "forex", "option trading", "binary options", "trade signal",
        "stock tips", "profit guarantee", "trade karo", "trading group", "signal group",
        "sebi registered", "nse bse tips", "intraday tips",
    ],
    "Loan App Scam": [
        "instant loan", "rupeespeedy", "loan approval", "loan app", "recovery agent",
        "payday loan", "contacts hack", "turant loan", "bina cibil loan", "loan scam",
        "200% interest", "loan app harassment", "loan recovery threat",
    ],
    "Investment Scam": [
        "guaranteed returns", "doubling money", "wealth advisory", "pump and dump",
        "stock investment", "mutual fund scam", "guaranteed profit", "money double",
        "paisa double", "invest karo", "return guarantee", "high return",
    ],
    "Job Scam": [
        "part-time", "earn money", "work from home", "like task", "tmart",
        "youtube like", "ghar baithe kama", "daily earning", "task karo paise pao",
        "online task job", "earn per like", "refer and earn", "ghar se kaam",
    ],
    "OTP Scam": [
        "share otp", "otp required", "secret code", "verification code",
        "otp share karo", "otp mat batao", "otp fraud", "sms code",
    ],
    "KYC Scam": [
        "kyc update", "kyc verification", "netbanking blocked", "account suspended",
        "kyc karo", "kyc expire", "kyc link", "update kyc", "account block",
        "kyc nahi hua", "bank kyc", "aadhaar kyc link",
    ],
    "Fake Customer Care Scam": [
        "customer care", "helpline", "toll free", "support dial", "customer service",
        "refund chahiye", "customer care number", "amazon helpline",
        "paytm customer care", "sbi helpline", "bank helpline",
    ],
    "Crypto Scam": [
        "bitcoin", "crypto", "binance", "usdt", "blockchain bonus", "nft",
        "cryptocurrency", "eth", "wallet address", "btc double", "crypto profit",
        "digital currency invest",
    ],
    "Phishing Campaign": [
        "click here", "verify now", "login", "password reset", "account blocked",
        "link click karo", "website kholo", "account verify", "login karo",
    ],
    "Malware Distribution": [
        "download file", "install certificate", "malicious update",
        "apk download", "software install", "update karo",
    ],
    "APK Distribution Fraud": [
        "download apk", "install app", "mod apk", "premium free apk",
        "app download karo", "apk link", "free apk", "install karo",
    ],
    "Sextortion": [
        "nude video", "obscene call", "blackmail", "video viral", "nude photo",
        "sex extortion", "sextortion", "video call blackmail", "compromise video",
        "intimate video", "leak karunga", "video share kar dunga",
    ],
    "Fake Government Scheme": [
        "pm yojana", "government scheme", "free ration", "subsidy scheme",
        "sarkar yojana", "free laptop scheme", "scholarship fraud", "gov scheme",
        "pm kisan fraud", "ration card update", "government lottery",
    ],
    "Courier Parcel Scam": [
        "parcel blocked", "customs clearance", "fedex scam", "dhl fraud",
        "parcel seize", "narcotics parcel", "customs officer", "delivery held",
        "parcel scam", "courier fraud", "package seized",
    ],
    "Electricity Utility Scam": [
        "electricity bill", "bijli bill", "power cut", "meter disconnect",
        "bijli kategi", "electricity disconnection", "bill payment scam",
        "dhbvn", "bescom", "msedcl", "uppcl", "tpddl",
    ],
    "Bank Impersonation": [
        "bank officer", "rbi official", "reserve bank", "bank manager call",
        "bank fraud alert", "bank ka call", "rbi call", "banking official",
        "branch manager", "bank account freeze", "account hold",
    ],
    "Romance Scam": [
        "dating app", "love scam", "marriage fraud", "girlfriend scam",
        "meet karein", "foreign girl", "army officer dating", "love money",
        "pyar ka dhoka", "instagram girl", "romance fraud",
    ],
    "Digital Arrest Scam": [
        "digital arrest", "narcotics bureau", "cbi officer call", "ed officer",
        "cyber crime branch call", "arrest warrant", "fir filed against you",
        "police station call", "digital fir", "cbdt notice",
        "enforcement directorate", "money laundering notice",
    ],
}

# High-confidence labels: if keyword count >= threshold, skip NLI model
_FAST_PATH_THRESHOLD = 2


class ScamClassifier:
    """
    Two-stage scam classification for maximum accuracy and speed:
      Stage 1 (fast): Keyword heuristics with Hinglish support → if high confidence, return immediately
      Stage 2 (slow): DistilBERT MNLI zero-shot classification → for ambiguous cases

    Text chunking: handles texts > 512 tokens by sliding-window averaging.
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
    # Stage 1: Keyword heuristics (fast, Hinglish-aware)
    # ------------------------------------------------------------------

    def _keyword_classify(self, text: str) -> tuple[str, float]:
        """
        Fast keyword-based classification with Hinglish keyword support.
        Returns (label, confidence). Confidence = min(matches * 0.18, 0.92).
        """
        text_lower = text.lower()
        best_label = "Safe / Non-Scam"
        best_count = 0

        for label, keywords in _KEYWORD_MAP.items():
            count = sum(1 for kw in keywords if kw in text_lower)
            if count > best_count:
                best_count = count
                best_label = label

        confidence = min(best_count * 0.18, 0.92) if best_count > 0 else 0.0
        return best_label, confidence

    # ------------------------------------------------------------------
    # Stage 2: Transformer NLI (slow, accurate)
    # ------------------------------------------------------------------

    def _chunk_text(self, text: str, chunk_size: int = 450) -> list[str]:
        """
        Split long text into overlapping chunks of ~chunk_size words.
        Overlap of 50 words ensures context isn't lost at boundaries.
        """
        words = text.split()
        if len(words) <= chunk_size:
            return [text]
        
        chunks = []
        overlap = 50
        step = chunk_size - overlap
        for i in range(0, len(words), step):
            chunk = words[i:i + chunk_size]
            chunks.append(" ".join(chunk))
            if i + chunk_size >= len(words):
                break
        return chunks

    def _nli_classify(self, text: str) -> tuple[str, float]:
        """
        Zero-shot NLI classification with sliding window for long texts.
        Averages scores across all chunks.
        """
        chunks = self._chunk_text(text)
        label_score_sums: dict[str, float] = {}
        num_chunks = 0

        for chunk in chunks:
            if len(chunk.split()) < 3:
                continue
            try:
                result = self._model(chunk, candidate_labels=self.candidate_labels)
                for label, score in zip(result["labels"], result["scores"]):
                    label_score_sums[label] = label_score_sums.get(label, 0.0) + score
                num_chunks += 1
            except Exception as exc:
                logger.error("[ScamClassifier] Chunk inference error: %s", exc)

        if not label_score_sums or num_chunks == 0:
            return "Safe / Non-Scam", 0.0

        # Average scores across chunks
        label_avg = {label: total / num_chunks for label, total in label_score_sums.items()}
        top_label = max(label_avg, key=label_avg.get)
        top_score = label_avg[top_label]

        return top_label, top_score

    # ------------------------------------------------------------------
    # Public API — two-stage classification
    # ------------------------------------------------------------------

    def classify_text(self, text: str) -> tuple[str, float]:
        """
        Two-stage classification:
          1. Fast keyword check — if high confidence, return immediately.
          2. Slow NLI model — for borderline cases only.

        Returns (label, confidence_score) where confidence ∈ [0, 1].
        """
        words = [w for w in text.split() if w.strip()]

        # Bare URL with no context → not actionable
        if len(words) == 1 and (words[0].startswith("http://") or words[0].startswith("https://")):
            return "Safe / Non-Scam", 0.0

        # Stage 1: Keyword classification
        kw_label, kw_conf = self._keyword_classify(text)

        # Fast path: high-confidence keyword match — skip expensive NLI
        if kw_label != "Safe / Non-Scam" and kw_conf >= 0.55:
            logger.debug("[ScamClassifier] Fast path: %s (%.2f)", kw_label, kw_conf)
            return kw_label, kw_conf

        # Very short text → only keyword classification is reliable
        if len(words) < 6:
            return kw_label, kw_conf

        # Stage 2: NLI model for ambiguous/longer texts
        if self._model is not None:
            try:
                nli_label, nli_score = self._nli_classify(text)

                # NLI returned below threshold → try blending with keyword result
                if nli_score < settings.CLASSIFIER_CONFIDENCE_THRESHOLD:
                    # If keyword found something, trust keyword over low-confidence NLI
                    if kw_label != "Safe / Non-Scam" and kw_conf > 0.2:
                        return kw_label, kw_conf
                    return "Safe / Non-Scam", nli_score

                return nli_label, nli_score

            except Exception as exc:
                logger.error("[ScamClassifier] NLI stage error: %s. Using keyword result.", exc)

        # Final fallback: keyword only
        return kw_label, kw_conf