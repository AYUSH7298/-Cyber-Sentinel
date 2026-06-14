from sentence_transformers import SentenceTransformer, util
import numpy as np
import logging

logger = logging.getLogger(__name__)


class CampaignClusterer:
    """
    Semantic similarity-based campaign clustering using sentence embeddings.

    Assigns incoming threat intelligence to existing campaigns when similarity
    exceeds the threshold, or creates a new campaign cluster otherwise.
    """

    MODEL_NAME = "all-MiniLM-L6-v2"
    CAMPAIGN_PREFIX = "CAMP"

    def __init__(self):
        self._model: SentenceTransformer | None = None
        self._load_model()

    def _load_model(self):
        """Lazy-load embedding model with graceful fallback."""
        try:
            self._model = SentenceTransformer(self.MODEL_NAME)
            logger.info("[CampaignClusterer] Sentence-transformer loaded: %s", self.MODEL_NAME)
        except Exception as exc:
            logger.warning(
                "[CampaignClusterer] Could not load sentence-transformer (%s). "
                "Falling back to keyword-based clustering.",
                exc,
            )
            self._model = None

    # ------------------------------------------------------------------
    # Embedding-based clustering
    # ------------------------------------------------------------------

    def generate_embedding(self, text: str) -> np.ndarray | None:
        """Generate a sentence embedding vector for the given text."""
        if self._model is None:
            return None
        try:
            return self._model.encode(text, convert_to_tensor=True)
        except Exception as exc:
            logger.error("[CampaignClusterer] Embedding generation failed: %s", exc)
            return None

    def _next_campaign_id(self, existing: list[dict]) -> str:
        """Generate the next sequential campaign ID."""
        max_id = 0
        for item in existing:
            cid = item.get("campaign_id", "")
            if cid and cid.startswith(f"{self.CAMPAIGN_PREFIX}_"):
                try:
                    num = int(cid.split("_")[1])
                    max_id = max(max_id, num)
                except (ValueError, IndexError):
                    pass
        return f"{self.CAMPAIGN_PREFIX}_{str(max_id + 1).zfill(3)}"

    def resolve_campaign(
        self,
        new_text: str,
        existing_artifacts: list[dict],
        threshold: float = 0.85,
    ) -> tuple[str, float]:
        """
        Determine which campaign this new observation belongs to.

        Args:
            new_text: The text of the new intelligence record.
            existing_artifacts: List of {"campaign_id": str, "text": str} dicts.
            threshold: Cosine similarity threshold for matching (default 0.85).

        Returns:
            Tuple of (campaign_id, similarity_score).
            similarity_score is 1.0 for a new campaign creation.
        """
        if not existing_artifacts:
            return f"{self.CAMPAIGN_PREFIX}_001", 1.0

        # --- Embedding path ---
        if self._model is not None:
            try:
                new_emb = self._model.encode(new_text, convert_to_tensor=True)
                hist_texts = [item["text"] for item in existing_artifacts]
                hist_embs = self._model.encode(hist_texts, convert_to_tensor=True)

                cos_scores = util.cos_sim(new_emb, hist_embs)[0]
                max_idx = int(cos_scores.argmax().item())
                max_score = float(cos_scores[max_idx].item())

                if max_score >= threshold:
                    matched_cid = existing_artifacts[max_idx]["campaign_id"]
                    logger.debug(
                        "[CampaignClusterer] Matched %s (score=%.3f)", matched_cid, max_score
                    )
                    return matched_cid, round(max_score, 3)

                # New cluster
                new_cid = self._next_campaign_id(existing_artifacts)
                logger.debug("[CampaignClusterer] New campaign created: %s", new_cid)
                return new_cid, round(max_score, 3)

            except Exception as exc:
                logger.error("[CampaignClusterer] Clustering error: %s. Using fallback.", exc)

        # --- Keyword fallback clustering ---
        return self._keyword_cluster(new_text, existing_artifacts, threshold)

    def _keyword_cluster(
        self,
        new_text: str,
        existing_artifacts: list[dict],
        threshold: float,
    ) -> tuple[str, float]:
        """Fallback: simple token overlap Jaccard similarity."""
        new_tokens = set(new_text.lower().split())
        best_score = 0.0
        best_cid = None

        for item in existing_artifacts:
            hist_tokens = set(item["text"].lower().split())
            if not new_tokens or not hist_tokens:
                continue
            intersection = new_tokens & hist_tokens
            union = new_tokens | hist_tokens
            jaccard = len(intersection) / len(union) if union else 0.0
            if jaccard > best_score:
                best_score = jaccard
                best_cid = item["campaign_id"]

        # Use a lower threshold for keyword matching (~0.3 equivalent)
        keyword_threshold = threshold * 0.35
        if best_cid and best_score >= keyword_threshold:
            return best_cid, round(best_score, 3)

        return self._next_campaign_id(existing_artifacts), round(best_score, 3)