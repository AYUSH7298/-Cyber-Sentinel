from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables or .env file.
    All secrets must be provided via environment variables in production.
    """

    PROJECT_NAME: str = "Cyber Sentinel"
    VERSION: str = "3.0.0"
    ENVIRONMENT: str = "development"  # development | staging | production

    # --- Database ---
    DATABASE_URL: str = "sqlite:///./cyber_sentinel.db"

    # --- Telegram OSINT Credentials ---
    # Obtain from: https://my.telegram.org/apps
    TELEGRAM_API_ID: int = 123456
    TELEGRAM_API_HASH: str = "your_api_hash_here"
    TELEGRAM_SESSION_NAME: str = "cyber_sentinel_session"

    # Public Telegram channels to monitor (comma-separated usernames)
    TELEGRAM_CHANNELS: str = (
        "cybercrimealerts_india,taskscams,fraud_alerts_news,cyberdost,indiancert,"
        "police_alerts,cyber_fraud_alerts_india,scam_alert_india,"
        "ncib_official,cybercrime_india_news,indiacybercops")

    # --- AI / ML Thresholds ---
    CAMPAIGN_SIMILARITY_THRESHOLD: float = 0.80   # Lowered for better clustering
    CLASSIFIER_CONFIDENCE_THRESHOLD: float = 0.40  # Lowered to catch more threats
    # Max cached embeddings in clusterer
    EMBEDDING_CACHE_SIZE: int = 1000

    # --- RSS Feed URLs (comma-separated) — covers all 28 states + 8 UTs ---
    RSS_FEED_URLS: str = (
        # Official Threat Intel Sources
        "https://www.cert-in.org.in/rss.xml,"
        "https://www.cisa.gov/cybersecurity-advisories/all.xml,"
        "https://feeds.feedburner.com/TheHackersNews,"
        # National cybercrime queries
        "https://news.google.com/rss/search?q=cybercrime+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=online+fraud+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=upi+fraud&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cyber+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=phishing+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=digital+arrest+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=online+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        # Major metros
        "https://news.google.com/rss/search?q=cybercrime+mumbai&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+delhi&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+bangalore&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+hyderabad&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+chennai&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+kolkata&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+pune&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+ahmedabad&hl=en-IN&gl=IN&ceid=IN:en,"
        # Northern India
        "https://news.google.com/rss/search?q=cyber+fraud+gurugram&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+noida&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+lucknow&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+jaipur&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+chandigarh&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cyber+fraud+haryana&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+uttar+pradesh&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+rajasthan&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+punjab&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+himachal+pradesh&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+uttarakhand&hl=en-IN&gl=IN&ceid=IN:en,"
        # Eastern India
        "https://news.google.com/rss/search?q=cybercrime+west+bengal&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+bihar&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+jharkhand&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+odisha&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+assam&hl=en-IN&gl=IN&ceid=IN:en,"
        # Southern India
        "https://news.google.com/rss/search?q=cybercrime+karnataka&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+kerala&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+andhra+pradesh&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+telangana&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+tamil+nadu&hl=en-IN&gl=IN&ceid=IN:en,"
        # Western India
        "https://news.google.com/rss/search?q=cybercrime+maharashtra&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+gujarat&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+goa&hl=en-IN&gl=IN&ceid=IN:en,"
        # Central India
        "https://news.google.com/rss/search?q=cybercrime+madhya+pradesh&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+chhattisgarh&hl=en-IN&gl=IN&ceid=IN:en,"
        # Northeast India
        "https://news.google.com/rss/search?q=cybercrime+manipur&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+meghalaya&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+nagaland&hl=en-IN&gl=IN&ceid=IN:en,"
        # Scam-type specific national queries
        "https://news.google.com/rss/search?q=loan+app+fraud+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=investment+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=kyc+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=part+time+job+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=digital+arrest+scam&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=sextortion+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=courier+parcel+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=fake+customer+care+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=trading+app+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=electricity+bill+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=fake+police+call+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=romance+scam+india&hl=en-IN&gl=IN&ceid=IN:en"
    )

    # --- Reddit OSINT Subreddits (comma-separated) ---
    REDDIT_SUBREDDITS: str = (
        "IsThisAScamIndia,LegalAdviceIndia,india,bangalore,mumbai,"
        "delhi,hyderabad,pune,Chennai,kolkata,ahmedabad,jaipur,"
        "scams,cybersecurity,IndiaInvestments"
    )
    REDDIT_POST_LIMIT: int = 25   # Posts per subreddit per cycle

    # --- URLhaus / Threat Intel Feeds ---
    URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    OPENPHISH_FEED_URL: str = "https://openphish.com/feed.txt"
    PHISHTANK_FEED_URL: str = "https://data.phishtank.com/data/online-valid.json"

    # --- Scheduler ---
    OSINT_POLL_INTERVAL_SECONDS: int = 300   # 5 minutes
    RSS_POLL_INTERVAL_SECONDS: int = 600     # 10 minutes
    MALWARE_POLL_INTERVAL_SECONDS: int = 900  # 15 minutes

    # --- Security ---
    SECRET_KEY: str = "CHANGE_THIS_IN_PRODUCTION_USE_256BIT_RANDOM_KEY"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    # --- External APIs (optional enrichment) ---
    VIRUSTOTAL_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    @field_validator("TELEGRAM_API_ID", mode="before")
    @classmethod
    def parse_telegram_api_id(cls, v):
        try:
            return int(v)
        except (ValueError, TypeError):
            return 123456

    @property
    def telegram_channels_list(self) -> list[str]:
        return [ch.strip()
                for ch in self.TELEGRAM_CHANNELS.split(",") if ch.strip()]

    @property
    def rss_feed_urls_list(self) -> list[str]:
        return [url.strip()
                for url in self.RSS_FEED_URLS.split(",") if url.strip()]

    @property
    def reddit_subreddits_list(self) -> list[str]:
        return [s.strip()
                for s in self.REDDIT_SUBREDDITS.split(",") if s.strip()]

    @property
    def is_telegram_configured(self) -> bool:
        return (
            self.TELEGRAM_API_HASH != "your_api_hash_here"
            and self.TELEGRAM_API_ID != 123456
        )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"}


settings = Settings()
