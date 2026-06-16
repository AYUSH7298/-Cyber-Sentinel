import logging
import random
from sqlalchemy.orm import Session
from app import models

logger = logging.getLogger(__name__)

class SocialScraper:
    """
    Simulated scraper for major social media platforms.
    Currently acts as a mock data generator since real scraping requires
    residential proxies and authentication.
    Targets: YouTube, Instagram, Facebook, X (Twitter).
    """

    def __init__(self):
        self.sources = ["YouTube", "Instagram", "Facebook", "X"]
        
        self.mock_templates = [
            "Part-time job offer! Earn Rs. 5000 daily. Just like YouTube videos. Message on WhatsApp: 9876543210 or click t.me/fake_job_bot.",
            "Double your crypto in 24 hours. Join my VIP binary options group. Send USDT to 0x1234567890abcdef1234567890abcdef12345678",
            "Urgent: Your HDFC bank account will be blocked. Click here to update KYC: http://kyc-update-hdfc.com",
            "Download the premium mod apk for free! Just install com.hacked.app and grant permissions.",
            "Customer support for SBI. Call toll free 1800-111-2222 for any payment refunds or UPI issues.",
        ]

    def fetch_latest_intel(self, db: Session) -> int:
        """Inject simulated social media intelligence into the database."""
        logger.info("[SocialScraper] Simulating scraping from %s", self.sources)
        
        added_count = 0
        # Generate 3-5 random pieces of intel
        for _ in range(random.randint(3, 5)):
            platform = random.choice(self.sources)
            text = random.choice(self.mock_templates)
            
            # Add a bit of noise to avoid exact deduplication blocks
            noisy_text = f"{text} [ID:{random.randint(1000, 9999)}]"
            
            # Check deduplication
            existing = db.query(models.RawIntel).filter(models.RawIntel.raw_text == noisy_text).first()
            if not existing:
                record = models.RawIntel(
                    source=platform,
                    raw_text=noisy_text
                )
                db.add(record)
                added_count += 1
                
        db.commit()
        logger.info("[SocialScraper] Successfully pulled %d new records.", added_count)
        return added_count
