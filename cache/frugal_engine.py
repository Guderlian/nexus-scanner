"""FrugalEngine - experience cache that skips LLM calls for known patterns."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain


@dataclass
class CacheEntry:
    """A cached successful analysis path."""
    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    fact_signature: str = ""
    vuln_type: str = ""
    hypothesis_result: dict = field(default_factory=dict)
    evidence_result: dict = field(default_factory=dict)
    confidence: float = 0.0
    hit_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_used: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    expires_at: str = ""
    is_valid: bool = True

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "fact_signature": self.fact_signature,
            "vuln_type": self.vuln_type,
            "hypothesis_result": self.hypothesis_result,
            "evidence_result": self.evidence_result,
            "confidence": self.confidence,
            "hit_count": self.hit_count,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "expires_at": self.expires_at,
            "is_valid": self.is_valid,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CacheEntry:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class FrugalEngine:
    """Caches successful vulnerability analysis paths to skip redundant LLM calls."""

    def __init__(self, cache_path: str = ".nexus_cache/experience.json",
                 similarity_threshold: float = 0.85):
        self.cache_path = cache_path
        self.similarity_threshold = similarity_threshold
        self._entries: list[CacheEntry] = []
        self._hits = 0
        self._misses = 0
        self._llm_saved = 0

    def lookup(self, fact_card: FactCard, vuln_type: str) -> Optional[CacheEntry]:
        """Find a cached entry matching this FactCard and vuln type."""
        sig = self._compute_signature(fact_card)
        now = datetime.utcnow()
        best_entry = None
        best_sim = 0.0

        for entry in self._entries:
            if not entry.is_valid:
                continue
            if entry.vuln_type != vuln_type:
                continue
            # Check expiry
            if entry.expires_at:
                try:
                    exp = datetime.fromisoformat(entry.expires_at)
                    if now > exp:
                        continue
                except ValueError:
                    pass

            sim = self._compute_similarity(sig, entry.fact_signature)
            if sim >= self.similarity_threshold and sim > best_sim:
                best_sim = sim
                best_entry = entry

        if best_entry:
            best_entry.hit_count += 1
            best_entry.last_used = now.isoformat()
            self._hits += 1
            self._llm_saved += 1
            return best_entry

        self._misses += 1
        return None

    def store(self, fact_card: FactCard, vuln_type: str,
              hypothesis: HypothesisCard, evidence: EvidenceChain) -> None:
        """Store a successful analysis path in the cache."""
        # Only cache confirmed vulnerabilities
        if evidence.verdict != "confirmed":
            return

        sig = self._compute_signature(fact_card)
        now = datetime.utcnow()
        expires = now + timedelta(days=30)

        entry = CacheEntry(
            fact_signature=sig,
            vuln_type=vuln_type,
            hypothesis_result=hypothesis.to_dict(),
            evidence_result=evidence.to_dict(),
            confidence=evidence.final_confidence,
            expires_at=expires.isoformat(),
        )
        self._entries.append(entry)
        self._save()

    def invalidate(self, entry_id: str) -> None:
        """Mark a cache entry as invalid."""
        for entry in self._entries:
            if entry.entry_id == entry_id:
                entry.is_valid = False
                break
        self._save()

    def cleanup(self) -> int:
        """Remove expired and invalid entries. Returns count removed."""
        now = datetime.utcnow()
        before = len(self._entries)
        cleaned = []
        for entry in self._entries:
            if not entry.is_valid:
                continue
            if entry.expires_at:
                try:
                    exp = datetime.fromisoformat(entry.expires_at)
                    if now > exp:
                        continue
                except ValueError:
                    continue
            cleaned.append(entry)
        self._entries = cleaned
        removed = before - len(self._entries)
        if removed > 0:
            self._save()
        return removed

    def stats(self) -> dict:
        """Return cache statistics."""
        total_lookups = self._hits + self._misses
        return {
            "total_entries": len(self._entries),
            "valid_entries": len([e for e in self._entries if e.is_valid]),
            "total_hits": self._hits,
            "total_misses": self._misses,
            "hit_rate": self._hits / total_lookups if total_lookups > 0 else 0.0,
            "llm_calls_saved": self._llm_saved,
        }

    def _compute_signature(self, fact_card: FactCard) -> str:
        """Compute a path-independent signature of a FactCard."""
        # Normalize data_flow to abstract form
        abstract_flows = []
        for flow in fact_card.data_flow:
            # Keep the structure but abstract variable names
            parts = flow.split("->")
            if len(parts) == 2:
                abstract_flows.append(f"{_abstract(parts[0])}->{_abstract(parts[1])}")
            else:
                abstract_flows.append(flow)

        # Build signature components
        components = [
            fact_card.language,
            fact_card.sink or "unknown_sink",
            "|".join(sorted(abstract_flows)) if abstract_flows else "no_flow",
            "|".join(sorted(fact_card.heuristics)) if fact_card.heuristics else "no_heuristics",
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:64]

    def _compute_similarity(self, sig1: str, sig2: str) -> float:
        """Compute Jaccard similarity between two signatures."""
        # For hex hash signatures, compare character-level n-grams
        if sig1 == sig2:
            return 1.0
        # Use 4-gram Jaccard
        ngrams1 = set(sig1[i:i+4] for i in range(len(sig1) - 3))
        ngrams2 = set(sig2[i:i+4] for i in range(len(sig2) - 3))
        if not ngrams1 or not ngrams2:
            return 0.0
        intersection = ngrams1 & ngrams2
        union = ngrams1 | ngrams2
        return len(intersection) / len(union) if union else 0.0

    def _save(self) -> None:
        """Persist cache to disk."""
        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        data = [e.to_dict() for e in self._entries]
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self) -> None:
        """Load cache from disk."""
        if not os.path.exists(self.cache_path):
            self._entries = []
            return
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._entries = [CacheEntry.from_dict(d) for d in data]
        except (json.JSONDecodeError, IOError):
            self._entries = []


def _abstract(token: str) -> str:
    """Abstract a variable name to its category."""
    t = token.strip().lower()
    if t in ("url", "target", "target_url", "file_url", "endpoint"):
        return "ext_url"
    if t in ("request", "request.args", "request.form"):
        return "ext_input"
    return t
