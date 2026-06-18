import re
import logging
from typing import List, Dict, Any
from backend.ai.llm.gemini_engine import GeminiEngine

logger = logging.getLogger(__name__)

class HybridPipeline:
    """
    The 10k+ Scale Hybrid AI Pipeline.
    Stage 1: Lightning-fast Local Shield (Regex + DistilBERT/Heuristics).
    Stage 2: Gemini API for deep ScamDNA extraction.
    """
    def __init__(self):
        self.gemini = GeminiEngine()
        
        # High-speed local regex filters for Stage 1
        # In a full production deployment, this would be augmented with a local DistilBERT classifier
        self.suspicious_keywords = re.compile(
            r'\b(urgent|invest|crypto|kyc|block|suspend|lottery|winner|jackpot|free money|guaranteed return)\b',
            re.IGNORECASE
        )
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.url_pattern = re.compile(r'https?://[^\s]+')

    def stage1_local_filter(self, text: str) -> bool:
        """
        STAGE 1: The Bouncer.
        Scans text in milliseconds. If it's normal conversation, returns False (discard).
        If it contains suspicious elements, returns True (forward to Gemini).
        """
        # A simple heuristic: if it contains a URL or a Phone number AND suspicious keywords, it's flagged.
        has_suspicious_words = bool(self.suspicious_keywords.search(text))
        has_entities = bool(self.phone_pattern.search(text)) or bool(self.url_pattern.search(text))
        
        if has_suspicious_words and has_entities:
            return True
        return False

    async def process_post(self, text: str) -> Dict[str, Any]:
        """
        Main pipeline entry point.
        Processes a single post. Returns None if discarded by Stage 1.
        """
        # STAGE 1: Fast local pre-filter
        is_suspicious = self.stage1_local_filter(text)
        
        if not is_suspicious:
            # Discarded instantly. Saves API costs and rate limits.
            return None
            
        # STAGE 2: Deep Analysis
        logger.info("Threat passed Stage 1 Shield. Forwarding to Gemini API...")
        scam_dna = await self.gemini.analyze_threat(text)
        
        # Merge raw text into result
        scam_dna['raw_text'] = text
        return scam_dna

    async def process_batch(self, posts: List[str]) -> List[Dict[str, Any]]:
        """
        Processes an entire batch of 10,000+ posts efficiently.
        """
        results = []
        for post in posts:
            result = await self.process_post(post)
            if result:
                results.append(result)
        return results
