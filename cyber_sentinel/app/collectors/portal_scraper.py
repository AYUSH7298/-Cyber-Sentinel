import logging
import random
from sqlalchemy.orm import Session
from app import models

logger = logging.getLogger(__name__)

class PortalScraper:
    """
    Simulated scraper for Public Scam Reporting Portals.
    """

    def __init__(self):
        self.sources = ["Scam_Reporting_Portal"]
        
        self.mock_templates = [
            "Victim reports losing 50000 INR to an OTP scam. The caller claimed to be from Paytm KYC update team.",
            "Report filed against investment scam promising guaranteed returns on Telegram group @WealthAdvisors.",
            "UPI Fraud reported: Victim transferred money to okicici via a fake payment link.",
            "Sextortion complaint: Victim blackmailed over video call by fake account on Instagram.",
        ]

    def fetch_latest_intel(self, db: Session) -> int:
        logger.info("[PortalScraper] Scraping public scam reporting portals...")
        
        added_count = 0
        for _ in range(random.randint(1, 3)):
            platform = random.choice(self.sources)
            text = random.choice(self.mock_templates)
            noisy_text = f"{text} [CaseID:{random.randint(10000, 99999)}]"
            
            existing = db.query(models.RawIntel).filter(models.RawIntel.raw_text == noisy_text).first()
            if not existing:
                record = models.RawIntel(source=platform, raw_text=noisy_text)
                db.add(record)
                added_count += 1
                
        db.commit()
        logger.info("[PortalScraper] Successfully pulled %d new records.", added_count)
        return added_count
