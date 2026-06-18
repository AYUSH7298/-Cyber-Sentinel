import os
import json
import logging
import google.generativeai as genai
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GeminiEngine:
    """
    Stage 2 of the Hybrid AI Pipeline: The Brain.
    Processes only the highly suspicious text that survives the local pre-filter.
    """
    def __init__(self):
        # The user will need to add GEMINI_API_KEY to their .env file
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning("GEMINI_API_KEY not found in environment. Gemini Engine will run in simulation mode until configured.")
        else:
            genai.configure(api_key=api_key)
            
        # Using the recommended model for text processing
        self.model_name = 'gemini-1.5-flash'
        try:
            self.model = genai.GenerativeModel(self.model_name)
        except Exception as e:
            logger.error(f"Failed to initialize Gemini model: {e}")
            self.model = None

    async def analyze_threat(self, raw_text: str) -> Dict[str, Any]:
        """
        Sends the suspicious text to Gemini for deep ScamDNA extraction.
        """
        if not self.model or not os.getenv("GEMINI_API_KEY"):
            # Simulation Mode for local testing before API key is provided
            return {
                "scam_category": "Phishing",
                "risk_score": 85,
                "confidence": 0.92,
                "explanation": "[SIMULATED] Gemini API Key not found. This is a simulated high-risk phishing attempt.",
                "extracted_entities": {
                    "urls": ["http://fake-sbi-kyc.com"],
                    "phones": [],
                    "crypto_wallets": []
                }
            }

        prompt = f"""
        Act as an elite Cybersecurity Threat Analyst. Analyze the following social media post or message.
        Extract the "ScamDNA" and return ONLY a strict JSON object with the following schema:
        {{
            "scam_category": "String (e.g., Job Scam, Investment Scam, Phishing, Safe)",
            "risk_score": "Integer from 0 to 100",
            "confidence": "Float from 0.0 to 1.0",
            "explanation": "A 2-sentence explanation of the psychological manipulation or threat vector used",
            "extracted_entities": {{
                "urls": ["list of strings"],
                "phones": ["list of strings"],
                "crypto_wallets": ["list of strings"]
            }}
        }}

        Analyze this text:
        "{raw_text}"
        """

        try:
            response = self.model.generate_content(prompt)
            # Clean the markdown JSON formatting if Gemini wraps it
            result_text = response.text.strip().removeprefix('```json').removesuffix('```').strip()
            return json.loads(result_text)
        except Exception as e:
            logger.error(f"Gemini API Error: {e}")
            return {
                "scam_category": "Unknown",
                "risk_score": 50,
                "confidence": 0.0,
                "explanation": f"Failed to analyze via Gemini: {str(e)}",
                "extracted_entities": {"urls": [], "phones": [], "crypto_wallets": []}
            }
