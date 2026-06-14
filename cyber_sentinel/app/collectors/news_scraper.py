import feedparser
import urllib.request
from sqlalchemy.orm import Session
from app import models
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Fallback hardcoded feeds (overridden by settings)
DEFAULT_FEED_URLS = [
    "https://www.cert-in.org.in/rss.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://isc.sans.edu/rssfeed.xml",
]


class RSSCollector:
    """
    Collects public cybersecurity advisories and news from RSS/Atom feeds.
    Uses feedparser for robust multi-format parsing.
    """

    def __init__(self):
        self.feed_urls = settings.rss_feed_urls_list or DEFAULT_FEED_URLS

    def fetch_latest_alerts(self, db: Session) -> int:
        """
        Fetch entries from all configured RSS feeds and store new records.

        Returns the count of newly added raw intel records.
        """
        total_new = 0
        for url in self.feed_urls:
            count = self._fetch_single_feed(url, db)
            total_new += count
        db.commit()
        logger.info("[RSSCollector] Total new records ingested: %d", total_new)
        return total_new

    def _fetch_single_feed(self, url: str, db: Session) -> int:
        """Parse a single RSS/Atom feed and store unique entries."""
        logger.info("[RSSCollector] Fetching: %s", url)
        try:
            # feedparser handles HTTP, gzip, ETag caching, RSS & Atom
            feed = feedparser.parse(url, request_headers={"User-Agent": "CyberSentinel/2.0"})

            if feed.bozo and not feed.entries:
                logger.warning("[RSSCollector] Feed parse error for %s: %s", url, feed.bozo_exception)
                return 0

            count = 0
            for entry in feed.entries:
                title = getattr(entry, "title", "").strip()
                summary = getattr(entry, "summary", "").strip()
                link = getattr(entry, "link", "").strip()

                # Build combined text blob for AI processing
                combined = f"{title}. {summary}".strip(". ").strip()
                if not combined or len(combined) < 15:
                    continue

                # Append link if present and not already in text
                if link and link not in combined:
                    combined = f"{combined} [Source: {link}]"

                # Deduplication: check by exact text match
                exists = (
                    db.query(models.RawIntel)
                    .filter(models.RawIntel.raw_text == combined)
                    .first()
                )
                if not exists:
                    db.add(models.RawIntel(source="rss_news", raw_text=combined))
                    count += 1

            logger.info("[RSSCollector] %s → %d new records", url, count)
            return count

        except Exception as exc:
            logger.error("[RSSCollector] Failed to fetch %s: %s", url, exc)
            return 0