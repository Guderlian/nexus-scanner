"""EmbeddingCache - semantic similarity with graceful offline fallback."""
from __future__ import annotations

import hashlib
import math
import os
import pickle
import re
from collections import Counter
from typing import Optional

import numpy as np


class EmbeddingCache:
    """Semantic similarity for code snippets.

    Tries sentence-transformers first; falls back to a local TF-IDF
    character-n-gram vectorizer when the model is unavailable (offline).
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2",
                 cache_path: str = ".nexus_cache/embeddings.pkl",
                 similarity_threshold: float = 0.80):
        self.model_name = model_name
        self.cache_path = cache_path
        self.similarity_threshold = similarity_threshold
        self._model = None
        self._model_loaded = False
        self._use_fallback = False
        self._index: list[dict] = []
        self._vocab: dict[str, int] = {}

    def _get_model(self):
        """Try to load sentence-transformers; fall back to local vectorizer."""
        if self._model_loaded:
            return
        self._model_loaded = True
        # Skip model download if explicitly offline or forced fallback
        if os.environ.get("NEXUS_OFFLINE") or os.environ.get("NEXUS_NO_EMBEDDING_MODEL"):
            self._use_fallback = True
            return
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
        except Exception:
            self._use_fallback = True

    def encode(self, text: str) -> list[float]:
        """Generate an embedding vector for the given text."""
        self._get_model()
        if self._use_fallback:
            return self._fallback_encode(text)
        vec = self._model.encode(text, convert_to_numpy=True)
        return vec.tolist()

    def _fallback_encode(self, text: str, dim: int = 128) -> list[float]:
        """Deterministic character n-gram hashing vectorizer (offline)."""
        tokens = self._tokenize(text)
        vec = [0.0] * dim
        for token in tokens:
            h = int(hashlib.md5(token.encode()).hexdigest(), 16)
            idx = h % dim
            vec[idx] += 1.0
        # L2 normalize
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec

    def _tokenize(self, text: str) -> list[str]:
        """Extract meaningful tokens from code text."""
        # Split on non-alphanumeric, keep function calls and keywords
        tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_.]*', text.lower())
        # Also add character bigrams for finer granularity
        bigrams = [text[i:i+2].lower() for i in range(len(text) - 1)]
        return tokens + bigrams

    def similarity(self, v1: list[float], v2: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        a = np.array(v1)
        b = np.array(v2)
        dot = np.dot(a, b)
        norm = np.linalg.norm(a) * np.linalg.norm(b)
        if norm == 0:
            return 0.0
        return float(dot / norm)

    def find_similar(self, text: str, candidates: list[dict]) -> Optional[dict]:
        """Find the most similar candidate above threshold."""
        if not candidates:
            return None
        query_vec = self.encode(text)
        best = None
        best_sim = 0.0
        for c in candidates:
            if "embedding" in c:
                cand_vec = c["embedding"]
            elif "text" in c:
                cand_vec = self.encode(c["text"])
            else:
                continue
            sim = self.similarity(query_vec, cand_vec)
            if sim >= self.similarity_threshold and sim > best_sim:
                best_sim = sim
                best = {**c, "_similarity": sim}
        return best

    def save_index(self, entries: list[dict]) -> None:
        """Persist the vector index to disk."""
        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        with open(self.cache_path, "wb") as f:
            pickle.dump(entries, f)

    def load_index(self) -> list[dict]:
        """Load the vector index from disk."""
        if not os.path.exists(self.cache_path):
            self._index = []
            return []
        try:
            with open(self.cache_path, "rb") as f:
                self._index = pickle.load(f)
            return self._index
        except Exception:
            self._index = []
            return []
