"""Embedding cache tests."""
from __future__ import annotations

import os
import sys
import tempfile

# Force offline mode to avoid HuggingFace download timeout
os.environ["NEXUS_NO_EMBEDDING_MODEL"] = "1"

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cache.embedding_cache import EmbeddingCache


class TestEmbeddingCache:
    def test_similar_code_high_similarity(self):
        """Same semantic pattern → similarity > 0.4 (fallback) or > 0.7 (model)."""
        ec = EmbeddingCache()
        v1 = ec.encode("requests.get(user_supplied_url)")
        v2 = ec.encode("requests.post(external_url)")
        sim = ec.similarity(v1, v2)
        assert sim > 0.4, f"Expected > 0.4, got {sim}"

    def test_different_type_low_similarity(self):
        """Different vuln types → similarity < 0.7."""
        ec = EmbeddingCache()
        v1 = ec.encode("requests.get(user_supplied_url)")
        v3 = ec.encode("cursor.execute(sql_query)")
        sim = ec.similarity(v1, v3)
        assert sim < 0.7, f"Expected < 0.7, got {sim}"

    def test_vector_dimension(self):
        """Fallback vectorizer produces 128-dim vectors."""
        ec = EmbeddingCache()
        v = ec.encode("test code")
        assert len(v) == 128

    def test_persistence(self):
        """Save and load index."""
        ec = EmbeddingCache(cache_path=tempfile.mktemp(suffix=".pkl"))
        entries = [{"id": "a", "text": "test", "embedding": ec.encode("test"), "data": {}}]
        ec.save_index(entries)
        loaded = ec.load_index()
        assert len(loaded) == 1
        assert loaded[0]["id"] == "a"

    def test_find_similar(self):
        """Find similar candidate above threshold."""
        ec = EmbeddingCache(similarity_threshold=0.3)
        candidates = [
            {"id": "ssrf1", "text": "requests.get(url)", "data": {"type": "SSRF"}},
            {"id": "sqli1", "text": "cursor.execute(sql)", "data": {"type": "SQLI"}},
        ]
        result = ec.find_similar("requests.post(target_url)", candidates)
        assert result is not None
        assert result["id"] == "ssrf1"
