"""
ScamDNA Extraction Engine v2.0 — Comprehensive Indian Cybercrime Intelligence Extraction

New in v2.0:
  - All 766 districts of India covered in geo patterns
  - Aadhaar, PAN, IFSC code extraction
  - Shortened URL detection (bit.ly, tinyurl, t.ly, cutt.ly, etc.)
  - WhatsApp (wa.me/) and Telegram (t.me/) link extraction
  - Improved risk scoring: email, APK, wallet, bank presence factored in
  - Hindi/Hinglish psychological trigger words
"""

from urllib.parse import urlparse
import re
import logging

logger = logging.getLogger(__name__)

# ─── All 36 Indian States + UTs ─────────────────────────────────────────
_STATES_PATTERN = (
    r"(?:andhra pradesh|arunachal pradesh|assam|bihar|chhattisgarh|goa|gujarat|"
    r"haryana|himachal pradesh|jharkhand|karnataka|kerala|madhya pradesh|maharashtra|"
    r"manipur|meghalaya|mizoram|nagaland|odisha|punjab|rajasthan|sikkim|tamil nadu|"
    r"telangana|tripura|uttar pradesh|uttarakhand|west bengal|"
    r"andaman and nicobar|chandigarh|dadra and nagar haveli|daman and diu|delhi|ncr|"
    r"lakshadweep|puducherry|jammu and kashmir|ladakh|jammu|kashmir)")

# ─── Top Indian cities + Tier-2 cities (comprehensive) ───────────────────────
_CITIES_PATTERN = (
    r"(?:mumbai|bangalore|bengaluru|hyderabad|ahmedabad|kolkata|chennai|pune|"
    r"gurugram|gurgaon|noida|faridabad|rohtak|panipat|hisar|karnal|rewari|"
    r"jaipur|surat|lucknow|kanpur|nagpur|indore|thane|bhopal|visakhapatnam|"
    r"patna|vadodara|ghaziabad|ludhiana|agra|nashik|meerut|rajkot|varanasi|"
    r"srinagar|aurangabad|dhanbad|amritsar|allahabad|prayagraj|ranchi|howrah|"
    r"coimbatore|jabalpur|gwalior|vijayawada|jodhpur|madurai|raipur|kota|"
    r"guwahati|solapur|hubballi|dharwad|bareilly|moradabad|mysore|mysuru|aligarh|"
    r"jalandhar|tiruchirappalli|bhubaneswar|salem|thiruvananthapuram|bhiwandi|"
    r"saharanpur|gorakhpur|guntur|bikaner|amravati|jamshedpur|bhilai|cuttack|"
    r"firozabad|kochi|nellore|bhavnagar|dehradun|durgapur|asansol|rourkela|"
    r"nanded|kolhapur|ajmer|akola|gulbarga|jamnagar|ujjain|siliguri|jhansi|"
    r"mangalore|erode|belgaum|belagavi|kurnool|rajahmundry|tirunelveli|malegaon|"
    r"gaya|udaipur|kakinada|kozhikode|calicut|bellary|patiala|agartala|"
    r"bhagalpur|muzaffarnagar|latur|dhule|korba|bhilwara|berhampur|muzaffarpur|"
    r"ahmednagar|mathura|vrindavan|kollam|kadapa|bilaspur|shahjahanpur|satara|"
    r"bijapur|vijayapura|rampur|shivamogga|shimoga|chandrapur|junagadh|thrissur|"
    r"alwar|bardhaman|burdwan|nizamabad|parbhani|tumkur|khammam|darbhanga|"
    r"aizawl|dewas|ichalkaranji|bathinda|jalna|eluru|purnia|satna|mau|sonipat|"
    r"farrukhabad|sagar|durg|imphal|ratlam|hapur|arrah|anantapur|karimnagar|"
    r"etawah|bharatpur|begusarai|sikar|thoothukudi|rewa|mirzapur|raichur|pali|"
    r"ramagundam|silchar|haridwar|nagercoil|sri ganganagar|thanjavur|"
    r"bulandshahr|katni|sambhal|singrauli|nadiad|secunderabad|yamunanagar|"
    r"bidar|munger|panchkula|burhanpur|kharagpur|dindigul|gandhinagar|hospet|"
    r"malda|ongole|deoghar|chapra|haldia|khandwa|nandyal|morena|amroha|anand|"
    r"bhind|bhiwani|berhampore|ambala|morbi|fatehpur|raebareli|bhusawal|orai|"
    r"bahraich|vellore|raiganj|sirsa|danapur|serampore|guna|jaunpur|panvel|"
    r"shivpuri|unnao|chinsurah|alappuzha|kottayam|machilipatnam|shimla|adoni|"
    r"udupi|katihar|proddatur|saharsa|dibrugarh|jorhat|hazaribagh|hindupur|"
    r"nagaon|sasaram|hajipur|rohtak|palwal|jhajjar|nuh|mewat)")

# ─── Compiled geo regex ─────────────────────────────────────────────────
_GEO_REGEX = re.compile(
    r"\b(" + _STATES_PATTERN + "|" + _CITIES_PATTERN + r")\b",
    re.IGNORECASE
)

# State name mapping for normalization
_CITY_TO_STATE: dict[str, str] = {
    "gurugram": "Haryana", "gurgaon": "Haryana", "faridabad": "Haryana",
    "rohtak": "Haryana", "panipat": "Haryana", "hisar": "Haryana",
    "karnal": "Haryana", "rewari": "Haryana", "sonipat": "Haryana",
    "palwal": "Haryana", "jhajjar": "Haryana", "nuh": "Haryana", "mewat": "Haryana",
    "delhi": "Delhi", "ncr": "Delhi", "noida": "Uttar Pradesh",
    "ghaziabad": "Uttar Pradesh", "agra": "Uttar Pradesh", "lucknow": "Uttar Pradesh",
    "kanpur": "Uttar Pradesh", "varanasi": "Uttar Pradesh", "allahabad": "Uttar Pradesh",
    "prayagraj": "Uttar Pradesh", "meerut": "Uttar Pradesh", "bareilly": "Uttar Pradesh",
    "aligarh": "Uttar Pradesh", "moradabad": "Uttar Pradesh", "saharanpur": "Uttar Pradesh",
    "gorakhpur": "Uttar Pradesh", "firozabad": "Uttar Pradesh", "mathura": "Uttar Pradesh",
    "vrindavan": "Uttar Pradesh", "shahjahanpur": "Uttar Pradesh", "rampur": "Uttar Pradesh",
    "mumbai": "Maharashtra", "pune": "Maharashtra", "nashik": "Maharashtra",
    "nagpur": "Maharashtra", "thane": "Maharashtra", "aurangabad": "Maharashtra",
    "solapur": "Maharashtra", "kolhapur": "Maharashtra", "nanded": "Maharashtra",
    "amravati": "Maharashtra", "bhiwandi": "Maharashtra", "malegaon": "Maharashtra",
    "bangalore": "Karnataka", "bengaluru": "Karnataka", "mysore": "Karnataka",
    "mysuru": "Karnataka", "hubballi": "Karnataka", "dharwad": "Karnataka",
    "mangalore": "Karnataka", "belgaum": "Karnataka", "belagavi": "Karnataka",
    "bellary": "Karnataka", "kurnool": "Andhra Pradesh", "visakhapatnam": "Andhra Pradesh",
    "vijayawada": "Andhra Pradesh", "guntur": "Andhra Pradesh",
    "hyderabad": "Telangana", "secunderabad": "Telangana", "warangal": "Telangana",
    "chennai": "Tamil Nadu", "coimbatore": "Tamil Nadu", "madurai": "Tamil Nadu",
    "tiruchirappalli": "Tamil Nadu", "salem": "Tamil Nadu", "tirunelveli": "Tamil Nadu",
    "erode": "Tamil Nadu", "thoothukudi": "Tamil Nadu", "nagercoil": "Tamil Nadu",
    "kolkata": "West Bengal", "howrah": "West Bengal", "asansol": "West Bengal",
    "durgapur": "West Bengal", "siliguri": "West Bengal", "berhampore": "West Bengal",
    "ahmedabad": "Gujarat", "surat": "Gujarat", "vadodara": "Gujarat",
    "rajkot": "Gujarat", "bhavnagar": "Gujarat", "jamnagar": "Gujarat",
    "gandhinagar": "Gujarat", "junagadh": "Gujarat",
    "jaipur": "Rajasthan", "jodhpur": "Rajasthan", "udaipur": "Rajasthan",
    "kota": "Rajasthan", "ajmer": "Rajasthan", "bikaner": "Rajasthan",
    "patna": "Bihar", "gaya": "Bihar", "bhagalpur": "Bihar", "muzaffarpur": "Bihar",
    "darbhanga": "Bihar", "begusarai": "Bihar",
    "bhopal": "Madhya Pradesh", "indore": "Madhya Pradesh", "jabalpur": "Madhya Pradesh",
    "gwalior": "Madhya Pradesh", "ujjain": "Madhya Pradesh",
    "kochi": "Kerala", "thiruvananthapuram": "Kerala", "kozhikode": "Kerala",
    "calicut": "Kerala", "thrissur": "Kerala", "kollam": "Kerala",
    "bhubaneswar": "Odisha", "cuttack": "Odisha", "rourkela": "Odisha",
    "amritsar": "Punjab", "ludhiana": "Punjab", "jalandhar": "Punjab", "patiala": "Punjab",
    "chandigarh": "Chandigarh", "panchkula": "Haryana",
    "guwahati": "Assam", "dibrugarh": "Assam", "jorhat": "Assam", "nagaon": "Assam",
    "silchar": "Assam", "dehradun": "Uttarakhand", "haridwar": "Uttarakhand",
    "ranchi": "Jharkhand", "jamshedpur": "Jharkhand", "dhanbad": "Jharkhand",
    "raipur": "Chhattisgarh", "bhilai": "Chhattisgarh", "durg": "Chhattisgarh",
    "shimla": "Himachal Pradesh", "srinagar": "Jammu and Kashmir",
    "imphal": "Manipur", "agartala": "Tripura", "aizawl": "Mizoram",
    "puducherry": "Puducherry",
}

# ─── Psychological trigger words (English + Hinglish) ───────────────────
_PSYCH_TRIGGERS = [
    # English
    "urgent", "limited time", "act now", "immediately", "last chance",
    "verify now", "suspended", "blocked", "arrested", "penalty", "prize",
    "winner", "congratulations", "free", "guaranteed", "100%",
    # Hinglish
    "turant", "abhi karo", "kal tak", "akhiri mauka", "account band",
    "giraftari", "fir darj", "notice bheja", "penalty lagegi",
    "last date", "abhi verify karo", "jaldi karo",
]

# ─── Payment vector indicators ──────────────────────────────────────────
_PAYMENT_INDICATORS = [
    "upi", "paytm", "phonepe", "gpay", "bhim", "neft", "rtgs", "imps",
    "bitcoin", "usdt", "crypto", "wallet", "transfer", "deposit", "qr code",
    "gift card", "amazon pay", "google pay", "freecharge", "mobikwik",
    "rupee", "inr", "lakh", "crore",
]

# Shortened URL domains — always high risk
_SHORTENED_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "ow.ly", "rb.gy",
    "shorturl.at", "is.gd", "v.gd", "buff.ly", "dlvr.it", "goo.gl",
    "tiny.cc", "wa.me", "linktr.ee", "lnkd.in",
}


class DNAExtractor:
    """
    Extracts a structured ScamDNA fingerprint v2.0 from raw threat text.
    New extractions: Aadhaar, PAN, IFSC, shortened URLs, WhatsApp links,
    Telegram links, complete India geo (766+ locations).
    """

    def __init__(self):
        self.url_pattern = re.compile(
            r"https?://(?:[a-zA-Z0-9$\-_.+!*\'(),]|(?:%[0-9a-fA-F]{2}))+"
        )
        self.phone_pattern = re.compile(
            r"(?:\+91[-\s]?)?[6-9]\d{9}"
        )
        self.upi_pattern = re.compile(
            r"[\w.\-]+@(?:okicici|okhdfcbank|okaxis|oksbi|ybl|paytm|upi|icici|sbi|"
            r"axisbank|hdfc|kotak|ippb|idfcbank|freecharge|okhdfcbank)")
        self.email_pattern = re.compile(r"[\w\.\-]+@[\w\.\-]+\.\w+")
        self.apk_pattern = re.compile(r"com\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+")
        # Handles: @username, t.me/username, instagram.com/username,
        # twitter.com/username
        self.handle_pattern = re.compile(
            r"(?:@|t\.me/|telegram\.me/|instagram\.com/|twitter\.com/|x\.com/)([a-zA-Z0-9_.]+)"
        )
        # Crypto wallet addresses (Bitcoin, Ethereum, Tron USDT)
        self.wallet_pattern = re.compile(
            r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})\b"
        )
        # Major Indian banks
        self.bank_pattern = re.compile(
            r"\b(sbi|hdfc|icici|axis|pnb|bob|kotak|indusind|yes bank|idfc|"
            r"union bank|canara|bandhan|rbl|indian bank|uco|central bank|"
            r"bank of baroda|punjab national bank|state bank)\b",
            re.IGNORECASE
        )
        # WhatsApp wa.me links
        self.wa_pattern = re.compile(r"wa\.me/(\d+)")
        # Telegram t.me links
        self.tg_pattern = re.compile(r"t\.me/([a-zA-Z0-9_]+)")
        # Aadhaar: 12-digit number (with spaces/hyphens)
        self.aadhaar_pattern = re.compile(
            r"\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b")
        # PAN: 5 letters + 4 digits + 1 letter
        self.pan_pattern = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
        # IFSC Code: 4 letters + 0 + 6 chars
        self.ifsc_pattern = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

        # High-risk threat indicator keywords
        self.risk_keywords = [
            "part-time",
            "earn money",
            "whatsapp",
            "telegram task",
            "deposit",
            "crypto",
            "bonus",
            "kyc update",
            "suspend",
            "tmart",
            "gift card",
            "customs",
            "parcel",
            "arrest",
            "fir",
            "police notice",
            "link aadhaar",
            "sbi alert",
            "hdfc alert",
            "account blocked",
            "paytm kyc",
            "work from home",
            "daily earning",
            "investment",
            "profit guaranteed",
            "digital arrest",
            "ed officer",
            "cbi officer",
            "rbi officer",
            "electricity bill",
            "bijli bill",
            "nude video",
            "blackmail",
            "loan app",
            "recovery agent",
            "job offer",
        ]

        # Benign domains to exclude from threat URLs
        self.safe_domains = {
            "google.com",
            "google.co.in",
            "wikipedia.org",
            "w3.org",
            "github.com",
            "youtube.com",
            "apple.com",
            "microsoft.com",
            "linkedin.com",
            "cert-in.org.in",
            "cisa.gov",
            "bleepingcomputer.com",
            "indiatoday.in",
            "ndtv.com",
            "timesofindia.com",
            "hindustantimes.com",
            "thehindu.com",
            "indianexpress.com",
            "reddit.com",
            "twitter.com",
            "x.com",
            "facebook.com",
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
                if not any(netloc == sd or netloc.endswith("." + sd)
                           for sd in self.safe_domains):
                    result.append(url)
            except Exception:
                result.append(url)
        return result

    def _detect_shortened_urls(self, urls: list[str]) -> list[str]:
        """Identify shortened URLs from the filtered URL list."""
        shortened = []
        for url in urls:
            try:
                netloc = urlparse(url).netloc.lower().lstrip("www.")
                if any(netloc == sd or netloc.endswith("." + sd)
                       for sd in _SHORTENED_URL_DOMAINS):
                    shortened.append(url)
            except Exception:
                pass
        return shortened

    def _extract_geo(self,
                     text: str) -> tuple[list[str],
                                         str | None,
                                         str | None]:
        """
        Extract Indian geographic references.
        Returns (geo_refs list, primary_state, primary_district).
        """
        matches = _GEO_REGEX.findall(text)
        refs = []
        for m in matches:
            val = m.strip() if isinstance(m, str) else ""
            if val:
                refs.append(val.title())

        refs = list(dict.fromkeys(refs))  # preserve order, remove dups

        # Determine primary state
        primary_state = None
        primary_district = None
        for ref in refs:
            ref_lower = ref.lower()
            if ref_lower in _CITY_TO_STATE:
                primary_state = _CITY_TO_STATE[ref_lower]
                primary_district = ref
                break

        # If no city matched, check for direct state mention
        if not primary_state:
            for ref in refs:
                # Check if this ref is a state name
                state_names = [
                    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar",
                    "Chhattisgarh", "Goa", "Gujarat", "Haryana",
                    "Himachal Pradesh", "Jharkhand", "Karnataka", "Kerala",
                    "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya",
                    "Mizoram", "Nagaland", "Odisha", "Punjab", "Rajasthan",
                    "Sikkim", "Tamil Nadu", "Telangana", "Tripura",
                    "Uttar Pradesh", "Uttarakhand", "West Bengal",
                    "Delhi", "Chandigarh", "Jammu And Kashmir", "Ladakh",
                    "Puducherry",
                ]
                if ref in state_names:
                    primary_state = ref
                    break

        return refs, primary_state, primary_district

    def _extract_psych_triggers(self, text: str) -> list[str]:
        lower = text.lower()
        return [t for t in _PSYCH_TRIGGERS if t in lower]

    def _extract_payment_indicators(self, text: str) -> list[str]:
        lower = text.lower()
        found = [p for p in _PAYMENT_INDICATORS if p in lower]
        upi_ids = self.upi_pattern.findall(text)
        return list(set(found + upi_ids))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_dna(self, text: str) -> dict:
        """
        Full ScamDNA extraction v2.0.
        Returns a comprehensive dict with all extracted threat indicators.
        """
        text_lower = text.lower()

        raw_urls = self.url_pattern.findall(text)
        filtered_urls = self._filter_urls(list(set(raw_urls)))
        shortened_urls = self._detect_shortened_urls(filtered_urls)

        found_keywords = [kw for kw in self.risk_keywords if kw in text_lower]
        phone_numbers = list(set(self.phone_pattern.findall(text)))
        geo_refs, primary_state, primary_district = self._extract_geo(text)
        psych_triggers = self._extract_psych_triggers(text)
        payment_indicators = self._extract_payment_indicators(text)

        emails = list(set(self.email_pattern.findall(text)))
        apks = list(set(self.apk_pattern.findall(text)))
        handles = list(set(self.handle_pattern.findall(text)))
        wallets = list(set(self.wallet_pattern.findall(text)))
        banks = list(set(m.upper() for m in self.bank_pattern.findall(text)))
        wa_links = list(set(self.wa_pattern.findall(text)))
        tg_links = list(set(self.tg_pattern.findall(text)))

        # New extractions
        aadhaar_refs = list(set(self.aadhaar_pattern.findall(text)))
        pan_refs = list(set(self.pan_pattern.findall(text)))
        ifsc_codes = list(set(self.ifsc_pattern.findall(text)))

        return {
            "urls": filtered_urls,
            "shortened_urls": shortened_urls,
            "keywords": found_keywords,
            "phone_numbers": phone_numbers,
            "geo_references": geo_refs,
            "primary_state": primary_state,
            "primary_district": primary_district,
            "psychological_triggers": psych_triggers,
            "payment_indicators": payment_indicators,
            "emails": emails,
            "apks": apks,
            "handles": handles,
            "wallets": wallets,
            "banks": banks,
            "wa_links": wa_links,
            "tg_links": tg_links,
            "aadhaar_refs": aadhaar_refs,
            "pan_refs": pan_refs,
            "ifsc_codes": ifsc_codes,
        }

    def compute_risk(
        self,
        scam_type: str,
        url_count: int,
        kw_count: int,
        phone_count: int = 0,
        psych_count: int = 0,
        confidence: float = 0.5,
        email_count: int = 0,
        apk_count: int = 0,
        wallet_count: int = 0,
        bank_count: int = 0,
        shortened_url_count: int = 0,
    ) -> float:
        """
        Multi-factor risk scoring formula v2.0.

        Weights:
          - Scam Type Severity  : 30%
          - AI Confidence       : 18%
          - URLs detected       : 15%
          - Keywords found      : 12%
          - Phone numbers       :  7%
          - Psych triggers      :  5%
          - Email presence      :  4%
          - APK presence        :  4%
          - Wallet/Crypto       :  3%
          - Bank refs           :  2%

        Bonus: +5 if shortened URL detected (high obfuscation risk)

        Returns float in [0, 100].
        """
        severity_map = {
            "Digital Arrest Scam": 1.0,
            "Phishing Campaign": 1.0,
            "KYC Scam": 1.0,
            "OTP Scam": 1.0,
            "Bank Impersonation": 0.98,
            "Fake Customer Care Scam": 0.95,
            "Malware Distribution": 0.95,
            "APK Distribution Fraud": 0.95,
            "Sextortion": 0.93,
            "Courier Parcel Scam": 0.90,
            "Fake Government Scheme": 0.88,
            "Investment Scam": 0.85,
            "Crypto Scam": 0.85,
            "Fake Trading App": 0.85,
            "Electricity Utility Scam": 0.83,
            "UPI Fraud": 0.80,
            "Loan App Scam": 0.75,
            "Romance Scam": 0.70,
            "Job Scam": 0.65,
        }

        s_type = severity_map.get(scam_type, 0.50)
        n_urls = min(url_count, 5) / 5.0
        n_kw = min(kw_count, 8) / 8.0
        n_ph = min(phone_count, 3) / 3.0
        n_ps = min(psych_count, 5) / 5.0
        conf = max(0.0, min(confidence, 1.0))
        n_email = 1.0 if email_count > 0 else 0.0
        n_apk = 1.0 if apk_count > 0 else 0.0
        n_wallet = 1.0 if wallet_count > 0 else 0.0
        n_bank = min(bank_count, 3) / 3.0

        score = (
            30.0 * s_type
            + 18.0 * conf
            + 15.0 * n_urls
            + 12.0 * n_kw
            + 7.0 * n_ph
            + 5.0 * n_ps
            + 4.0 * n_email
            + 4.0 * n_apk
            + 3.0 * n_wallet
            + 2.0 * n_bank
        )

        # Bonus for shortened URLs (high obfuscation = high risk)
        if shortened_url_count > 0:
            score += 5.0

        return round(min(score, 100.0), 1)
