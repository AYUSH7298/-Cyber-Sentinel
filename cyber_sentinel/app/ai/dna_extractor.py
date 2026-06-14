from urllib.parse import urlparse
import re
import logging

logger = logging.getLogger(__name__)

# Geographic reference patterns for Indian cities/districts/states
_GEO_PATTERNS = [
    r"\b(gurugram|gurgaon|delhi|ncr|noida|faridabad|rohtak|panipat|hisar|karnal)\b",
    r"\b(haryana|rajasthan|uttar pradesh|madhya pradesh|maharashtra|gujarat|punjab)\b",
    r"\b(mumbai|bangalore|bengaluru|hyderabad|ahmedabad|kolkata|chennai|pune)\b",
    r"\b(sector\s+\d+|phase\s+\d+|district|tehsil|block)\b",
]

_GEO_REGEX = re.compile("|".join(_GEO_PATTERNS), re.IGNORECASE)

# Psychological trigger patterns used by scammers
_PSYCH_TRIGGERS = [
    "urgent", "limited time", "act now", "immediately", "last chance",
    "verify now", "suspended", "blocked", "arrested", "penalty", "prize",
    "winner", "congratulations", "free", "guaranteed", "100%",
]

# Payment vector indicators
_PAYMENT_INDICATORS = [
    "upi", "paytm", "phonepe", "gpay", "bhim", "neft", "rtgs", "imps",
    "bitcoin", "usdt", "crypto", "wallet", "transfer", "deposit", "qr code",
    "gift card", "amazon pay", "google pay",
]


class DNAExtractor:
    """
    Extracts a structured ScamDNA fingerprint from raw threat text.
    The DNA captures all observable threat indicators for campaign correlation.
    """

    def __init__(self):
        self.url_pattern = re.compile(
            r"https?://(?:[a-zA-Z0-9$\-_.+!*\'(),]|(?:%[0-9a-fA-F]{2}))+"
        )
        self.phone_pattern = re.compile(
            r"(?:\+91[-\s]?)?[6-9]\d{9}"
        )
        self.upi_pattern = re.compile(
            r"[\w.\-]+@(?:okicici|okhdfcbank|okaxis|oksbi|ybl|paytm|upi|icici|sbi|axisbank|hdfc)"
        )

        # High-risk threat indicator keywords
        self.risk_keywords = [
            "part-time", "earn money", "whatsapp", "telegram task", "deposit",
            "crypto", "bonus", "kyc update", "suspend", "tmart", "gift card",
            "customs", "parcel", "arrest", "fir", "police notice", "link aadhaar",
            "sbi alert", "hdfc alert", "account blocked", "paytm kyc",
            "work from home", "daily earning", "investment", "profit guaranteed",
        ]

        # Benign domains to exclude from threat URLs
        self.safe_domains = {
            "google.com", "google.co.in", "wikipedia.org", "w3.org", "github.com",
            "youtube.com", "apple.com", "microsoft.com", "linkedin.com",
            "cert-in.org.in", "cisa.gov", "bleepingcomputer.com",
            "indiatoday.in", "ndtv.com", "timesofindia.com",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _filter_urls(self, urls: list[str]) -> list[str]:
        """Remove known-safe domains from URL list."""
        result = []
        for url in urls:
            try:
                netloc = urlparse(url).netloc.lower().lstrip("www.")
                if not any(netloc == sd or netloc.endswith("." + sd) for sd in self.safe_domains):
                    result.append(url)
            except Exception:
                result.append(url)
        return result

    def _extract_geo(self, text: str) -> list[str]:
        """Extract Indian geographic references from text."""
        matches = _GEO_REGEX.findall(text)
        # findall with groups returns tuples; flatten and deduplicate
        refs = []
        for m in matches:
            val = m if isinstance(m, str) else next((x for x in m if x), "")
            if val:
                refs.append(val.strip().title())
        return list(dict.fromkeys(refs))   # preserve order, remove dups

    def _extract_psych_triggers(self, text: str) -> list[str]:
        lower = text.lower()
        return [t for t in _PSYCH_TRIGGERS if t in lower]

    def _extract_payment_indicators(self, text: str) -> list[str]:
        lower = text.lower()
        found = [p for p in _PAYMENT_INDICATORS if p in lower]
        # Also extract UPI IDs
        upi_ids = self.upi_pattern.findall(text)
        return list(set(found + upi_ids))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_dna(self, text: str) -> dict:
        """
        Full ScamDNA extraction.

        Returns a dict with all extracted threat indicators.
        """
        text_lower = text.lower()

        raw_urls = self.url_pattern.findall(text)
        filtered_urls = self._filter_urls(list(set(raw_urls)))

        found_keywords = [kw for kw in self.risk_keywords if kw in text_lower]
        phone_numbers = list(set(self.phone_pattern.findall(text)))
        geo_refs = self._extract_geo(text)
        psych_triggers = self._extract_psych_triggers(text)
        payment_indicators = self._extract_payment_indicators(text)

        return {
            "urls": filtered_urls,
            "keywords": found_keywords,
            "phone_numbers": phone_numbers,
            "geo_references": geo_refs,
            "psychological_triggers": psych_triggers,
            "payment_indicators": payment_indicators,
        }

    def compute_risk(
        self,
        scam_type: str,
        url_count: int,
        kw_count: int,
        phone_count: int = 0,
        psych_count: int = 0,
        confidence: float = 0.5,
    ) -> float:
        """
        Multi-factor risk scoring formula.

        Weights:
          - Scam Type Severity : 35%
          - AI Confidence      : 20%
          - URLs detected      : 20%
          - Keywords found     : 15%
          - Phone numbers      : 5%
          - Psych triggers     : 5%

        Returns float in [0, 100].
        """
        severity_map = {
            "Phishing": 1.0,
            "KYC Scam": 1.0,
            "Sextortion": 1.0,
            "Courier Parcel Scam": 0.9,
            "Fake Government Scheme": 0.9,
            "Investment Scam": 0.85,
            "Crypto Scam": 0.85,
            "UPI Fraud": 0.80,
            "Loan Scam": 0.70,
            "Job Scam": 0.65,
        }

        s_type = severity_map.get(scam_type, 0.50)
        n_urls = min(url_count, 5) / 5.0
        n_kw = min(kw_count, 8) / 8.0
        n_ph = min(phone_count, 3) / 3.0
        n_ps = min(psych_count, 5) / 5.0
        conf = max(0.0, min(confidence, 1.0))

        score = (
            35.0 * s_type
            + 20.0 * conf
            + 20.0 * n_urls
            + 15.0 * n_kw
            + 5.0 * n_ph
            + 5.0 * n_ps
        )
        return round(min(score, 100.0), 1)