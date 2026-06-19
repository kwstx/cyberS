import logging
import numpy as np
from typing import List, Dict, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger("GNNResolver")

class GNNEntityResolver:
    def __init__(self, threshold: float = 0.85):
        """
        Simulates a Graph Neural Network (GNN) entity resolver.
        Instead of full node2vec/GCN embeddings, we use character n-grams
        and cosine similarity to deduplicate identity nodes quickly.
        """
        self.threshold = threshold
        self.vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4))
        self.known_entities: List[str] = []
        self.embeddings = None

    def fit_entities(self, entities: List[str]):
        """Fits the underlying model with existing graph identities."""
        if not entities:
            return
        self.known_entities = list(set(entities))
        self.embeddings = self.vectorizer.fit_transform(self.known_entities)
        logger.info(f"GNN Entity Resolver fitted with {len(self.known_entities)} identities.")

    def resolve_identity(self, incoming_name: str) -> Tuple[str, bool]:
        """
        Resolves an incoming identity name against known entities.
        Returns a tuple: (resolved_name, is_merged)
        """
        if not self.known_entities or self.embeddings is None:
            # First entity
            self.known_entities.append(incoming_name)
            self.embeddings = self.vectorizer.fit_transform(self.known_entities)
            return incoming_name, False
            
        # Vectorize incoming
        try:
            incoming_vec = self.vectorizer.transform([incoming_name])
            sims = cosine_similarity(incoming_vec, self.embeddings)[0]
            
            best_idx = np.argmax(sims)
            best_score = sims[best_idx]
            
            if best_score >= self.threshold:
                resolved_name = self.known_entities[best_idx]
                logger.info(f"GNN Resolver merged '{incoming_name}' into '{resolved_name}' (Score: {best_score:.2f})")
                return resolved_name, True
            else:
                # No match found, add to known
                self.known_entities.append(incoming_name)
                # Re-fit is expensive in reality, but fine for simulation sizes
                self.embeddings = self.vectorizer.fit_transform(self.known_entities)
                return incoming_name, False
        except Exception as e:
            logger.error(f"GNN Resolver error: {e}")
            return incoming_name, False
