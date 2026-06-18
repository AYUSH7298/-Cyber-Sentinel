"""
Real portal scraper for official Indian cyber crime advisory sources:
  - CERT-In RSS (cert-in.org.in) — official vulnerability & advisory bulletins
  - NCIIPC advisories (nciipc.gov.in) — critical infrastructure alerts
  - PIB (Press Information Bureau) cybercrime press releases
  - MHA / I4C public advisories

All sources are public government websites — no authentication required.
Data is scraped for public awareness / law enforcement intelligence purposes.
"""

import hashlib
import logging
import time
from sqlalchemy.orm import Session
from backend import models

try:
    import requests as _requests_unused  # noqa: F401
    import feedparser
    _AVAILABLE = True
except ImportError:
    feedparser = None  # type: ignore[assignment]
    _AVAILABLE = False

logger = logging.getLogger(__name__)

# Official Indian government cyber advisories via RSS/JSON
_OFFICIAL_RSS_FEEDS = [
    # CERT-In official advisory RSS
    ("https://www.cert-in.org.in/rss.xml", "CERT-In"),
    # PIB search for cybercrime advisories (public RSS)
    ("https://pib.gov.in/RssMain.aspx?ModId=6&Lang=1&Regid=3", "PIB_MHA"),
    # Cyberdost / MHA official Twitter-equivalent public releases
    ("https://news.google.com/rss/search?q=site:cert-in.org.in&hl=en-IN&gl=IN&ceid=IN:en", "CERT_In_GNews"),
    ("https://news.google.com/rss/search?q=cybercrime.gov.in+advisory&hl=en-IN&gl=IN&ceid=IN:en", "I4C_Advisory"),
    ("https://news.google.com/rss/search?q=MHA+cyber+advisory+india&hl=en-IN&gl=IN&ceid=IN:en", "MHA_Advisory"),
    ("https://news.google.com/rss/search?q=NCIB+cybercrime+advisory&hl=en-IN&gl=IN&ceid=IN:en", "NCIB_Advisory"),
    # State police cyber cell advisories
    ("https://news.google.com/rss/search?q=haryana+police+cyber+advisory&hl=en-IN&gl=IN&ceid=IN:en", "Haryana_Cyber"),
    ("https://news.google.com/rss/search?q=delhi+police+cybercrime+advisory&hl=en-IN&gl=IN&ceid=IN:en", "Delhi_Cyber"),
    ("https://news.google.com/rss/search?q=maharashtra+police+cyber+scam&hl=en-IN&gl=IN&ceid=IN:en", "MH_Cyber"),
    ("https://news.google.com/rss/search?q=rajasthan+police+cyber+fraud&hl=en-IN&gl=IN&ceid=IN:en", "RJ_Cyber"),
    ("https://news.google.com/rss/search?q=UP+police+cyber+fraud&hl=en-IN&gl=IN&ceid=IN:en", "UP_Cyber"),
    ("https://news.google.com/rss/search?q=karnataka+police+cyber+crime+advisory&hl=en-IN&gl=IN&ceid=IN:en", "KA_Cyber"),
    ("https://news.google.com/rss/search?q=tamil+nadu+police+cyber+scam&hl=en-IN&gl=IN&ceid=IN:en", "TN_Cyber"),
    ("https://news.google.com/rss/search?q=telangana+police+cyber+fraud&hl=en-IN&gl=IN&ceid=IN:en", "TS_Cyber"),
]

# Cyber-relevant keywords to filter noise from advisory RSS
_CYBER_KEYWORDS = [
    "scam", "fraud", "cyber", "phish", "hack", "malware", "advisory",
    "alert", "ransomware", "upi", "otp", "fake", "cheating", "online",
    "arrested", "fir", "complaint", "investigation", "block",
]


def _compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _strip_html(text: str) -> str:
    import re
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _is_cyber_related(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in _CYBER_KEYWORDS)


class PortalScraper:
    """
    Collects real cyber-crime intelligence from official Indian government
    advisory portals and state police cyber cell announcements via RSS/Atom feeds.
    """

    _HEADERS = {
        "User-Agent": "CyberSentinelBot/3.0 (Public OSINT Research; Indian Cyber Police)"
    }
    _DELAY_BETWEEN_FEEDS = 1.0  # seconds

    def fetch_latest_intel(self, db: Session) -> int:
        """
        Fetch from all official portal RSS feeds.
        Returns count of newly added records.
        """
        if not _AVAILABLE:
            logger.error("[PortalScraper] feedparser or requests not installed.")
            return 0

        total = 0
        for feed_url, source_label in _OFFICIAL_RSS_FEEDS:
            try:
                feed = feedparser.parse(  # type: ignore[union-attr]
                    feed_url,
                    agent="CyberSentinelBot/3.0 (Public OSINT Research; Indian Cyber Police)",
                )

                for entry in feed.entries:
                    title = entry.get("title", "").strip()
                    summary = _strip_html(entry.get("summary", entry.get("description", ""))).strip()
                    link = entry.get("link", "")

                    intel_text = f"[{source_label}] {title}. {summary}" if summary else f"[{source_label}] {title}"

                    if len(intel_text.split()) < 8:
                        continue
                    if not _is_cyber_related(intel_text):
                        continue

                    content_hash = _compute_hash(intel_text)
                    exists = db.query(models.RawIntel).filter(
                        models.RawIntel.content_hash == content_hash
                    ).first()
                    if exists:
                        continue

                    db.add(models.RawIntel(
                        source=f"portal:{source_label}",
                        raw_text=intel_text,
                        content_hash=content_hash,
                        source_url=link[:512] if link else None,
                        language="en",
                    ))
                    total += 1

                db.commit()
                time.sleep(self._DELAY_BETWEEN_FEEDS)
                logger.info("[PortalScraper] %s: processed.", source_label)

            except Exception as exc:
                logger.error("[PortalScraper] Error on feed '%s' (%s): %s", source_label, feed_url, exc)
                try:
                    db.rollback()
                except Exception:
                    pass

        logger.info("[PortalScraper] Total portal intel ingested: %d", total)
        return total
