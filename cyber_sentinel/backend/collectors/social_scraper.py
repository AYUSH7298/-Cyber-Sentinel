"""
Real social media OSINT collector using Reddit's public JSON API.
No authentication or API keys required for reading public subreddits.

Targets India-focused subreddits where victims report cyber scams:
  - r/IsThisAScamIndia
  - r/LegalAdviceIndia
  - r/india
  - City subreddits (r/bangalore, r/mumbai, r/delhi, etc.)
"""

import hashlib
import logging
import time
from sqlalchemy.orm import Session
from backend import models
from backend.config import settings

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore[assignment]
    _REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Cyber-crime related keywords — filter posts that don't mention these
_CYBER_KEYWORDS = [
    "scam", "fraud", "cheat", "fake", "hack", "phish", "upi", "otp",
    "loan app", "investment", "trading app", "kyc", "block", "suspend",
    "arrest", "fir", "cyber", "online fraud", "money lost", "stolen",
    "impersonation", "sextortion", "extortion", "ransom", "malware",
    "apk", "link", "telegram", "whatsapp job", "earn money",
]


def _is_cyber_related(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in _CYBER_KEYWORDS)


def _compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class SocialScraper:
    """
    Scrapes public Reddit subreddits for real victim reports and
    scam awareness posts using Reddit's unauthenticated public JSON API.

    Legal note: Reddit's public .json endpoint is freely accessible
    without authentication for public subreddits (ToS allows crawling).
    """

    _REDDIT_BASE = "https://www.reddit.com/r/{subreddit}/new.json?limit={limit}&sort=new"
    _HEADERS = {
        "User-Agent": "CyberSentinelBot/3.0 (Public OSINT Research; Indian Cyber Police)"
    }
    _REQUEST_TIMEOUT = 15
    _DELAY_BETWEEN_SUBS = 2  # seconds — Reddit rate limit is ~1 req/sec

    def __init__(self):
        self.subreddits = settings.reddit_subreddits_list
        self.post_limit = settings.REDDIT_POST_LIMIT

    def _fetch_subreddit(self, subreddit: str, db: Session) -> int:
        """Fetch recent posts from a single subreddit and store cyber-related ones."""
        added = 0
        url = self._REDDIT_BASE.format(subreddit=subreddit, limit=self.post_limit)

        try:
            resp = requests.get(url, headers=self._HEADERS, timeout=self._REQUEST_TIMEOUT)  # type: ignore[union-attr]
            if resp.status_code == 429:
                logger.warning("[SocialScraper] Reddit rate limited on r/%s. Sleeping 30s.", subreddit)
                time.sleep(30)
                return 0
            if resp.status_code != 200:
                logger.warning("[SocialScraper] r/%s returned HTTP %d", subreddit, resp.status_code)
                return 0

            data = resp.json()
            posts = data.get("data", {}).get("children", [])

            for post_wrapper in posts:
                post = post_wrapper.get("data", {})
                title = post.get("title", "").strip()
                selftext = post.get("selftext", "").strip()
                permalink = "https://reddit.com" + post.get("permalink", "")

                # Build combined intel text
                if selftext and selftext not in ("[removed]", "[deleted]"):
                    intel_text = f"[Reddit r/{subreddit}] {title}. {selftext[:800]}"
                else:
                    intel_text = f"[Reddit r/{subreddit}] {title}"

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
                    source=f"reddit:r/{subreddit}",
                    raw_text=intel_text,
                    content_hash=content_hash,
                    source_url=permalink[:512],
                    language="en",
                ))
                added += 1

            db.commit()
            logger.info("[SocialScraper] r/%s → %d new cyber-related posts", subreddit, added)

        except Exception as exc:
            logger.error("[SocialScraper] Error on r/%s: %s", subreddit, exc)
            try:
                db.rollback()
            except Exception:
                pass

        return added

    def fetch_latest_intel(self, db: Session) -> int:
        """
        Fetch from all configured subreddits.
        Returns total count of newly added records.
        """
        if not _REQUESTS_AVAILABLE or requests is None:
            logger.error("[SocialScraper] requests library not available.")
            return 0

        total = 0
        for subreddit in self.subreddits:
            total += self._fetch_subreddit(subreddit, db)
            time.sleep(self._DELAY_BETWEEN_SUBS)

        logger.info("[SocialScraper] Total new social media intel: %d records", total)
        return total
