import os
from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables or .env file.
    All secrets must be provided via environment variables in production.
    """

    PROJECT_NAME: str = "Cyber Sentinel"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"  # development | staging | production

    # --- Database ---
    DATABASE_URL: str = "sqlite:///./cyber_sentinel.db"

    # --- Telegram OSINT Credentials ---
    # Obtain from: https://my.telegram.org/apps
    TELEGRAM_API_ID: int = 123456
    TELEGRAM_API_HASH: str = "your_api_hash_here"
    TELEGRAM_SESSION_NAME: str = "cyber_sentinel_session"

    # Public Telegram channels to monitor (comma-separated usernames)
    TELEGRAM_CHANNELS: str = "cybercrimealerts_india,taskscams,fraud_alerts_news,cyberdost,indiancert,police_alerts,cyber_fraud_alerts_india,scam_alert_india"

    # --- AI / ML Thresholds ---
    CAMPAIGN_SIMILARITY_THRESHOLD: float = 0.85
    CLASSIFIER_CONFIDENCE_THRESHOLD: float = 0.50

    # --- RSS Feed URLs (comma-separated) ---
    RSS_FEED_URLS: str = (
        "https://www.cert-in.org.in/rss.xml,"
        "https://www.cisa.gov/cybersecurity-advisories/all.xml,"
        "https://feeds.feedburner.com/TheHackersNews,"
        "https://news.google.com/rss/search?q=cybercrime+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=online+scam+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=upi+fraud+india&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+mumbai&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+delhi&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+bangalore&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+chennai&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+kolkata&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+hyderabad&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+pune&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+ahmedabad&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+jaipur&hl=en-IN&gl=IN&ceid=IN:en,"
        "https://news.google.com/rss/search?q=cybercrime+lucknow&hl=en-IN&gl=IN&ceid=IN:en"
    )

    # --- Scheduler ---
    OSINT_POLL_INTERVAL_SECONDS: int = 300   # 5 minutes

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
        return [ch.strip() for ch in self.TELEGRAM_CHANNELS.split(",") if ch.strip()]

    @property
    def rss_feed_urls_list(self) -> list[str]:
        return [url.strip() for url in self.RSS_FEED_URLS.split(",") if url.strip()]

    @property
    def is_telegram_configured(self) -> bool:
        return (
            self.TELEGRAM_API_HASH != "your_api_hash_here"
            and self.TELEGRAM_API_ID != 123456
        )

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()