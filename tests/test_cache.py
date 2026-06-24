"""Cache tests - FileHasher + FrugalEngine."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cache.file_hasher import FileHasher
from cache.frugal_engine import FrugalEngine, CacheEntry
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain, EvidenceItem


def _tmp_path(suffix=".json"):
    return tempfile.mktemp(suffix=suffix)


def _write_temp(code: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(code)
    return path


# =====================================================================
# FileHasher Tests
# =====================================================================

class TestFileHasher:
    def test_first_scan_detected_as_changed(self):
        """首次扫描应视为已变更."""
        fh = FileHasher(cache_path=_tmp_path())
        fname = _write_temp("print(1)")
        try:
            assert fh.has_changed(fname) is True
        finally:
            os.unlink(fname)

    def test_unchanged_file_detected(self):
        """未修改文件应视为未变更."""
        path = _tmp_path()
        fh = FileHasher(cache_path=path)
        fname = _write_temp("print(2)")
        try:
            fh.update(fname)
            fh.save()
            fh2 = FileHasher(cache_path=path)
            fh2.load()
            assert fh2.has_changed(fname) is False
        finally:
            os.unlink(fname)

    def test_changed_file_detected(self):
        """修改后文件应检测为已变更."""
        path = _tmp_path()
        fh = FileHasher(cache_path=path)
        fname = _write_temp("original")
        try:
            fh.update(fname)
            fh.save()
            with open(fname, "w") as f:
                f.write("modified")
            fh2 = FileHasher(cache_path=path)
            fh2.load()
            assert fh2.has_changed(fname) is True
        finally:
            os.unlink(fname)

    def test_persistence_across_instances(self):
        """缓存应持久化到磁盘."""
        path = _tmp_path()
        fh = FileHasher(cache_path=path)
        fname = _write_temp("persist_test")
        try:
            fh.update(fname)
            fh.save()
            fh2 = FileHasher(cache_path=path)
            fh2.load()
            assert fh2.has_changed(fname) is False
        finally:
            os.unlink(fname)


# =====================================================================
# FrugalEngine Tests
# =====================================================================

class TestFrugalEngine:
    def _make_fact(self, sink="requests.get", heuristics=None, flow=None) -> FactCard:
        return FactCard(
            file_path="test.py", line_start=1, line_end=5,
            code_snippet=f"{sink}(url)", language="python",
            data_flow=flow or ["url->requests.get"],
            heuristics=heuristics or ["外部可控URL", "无校验"],
            confidence=0.8, sink=sink,
        )

    def _make_hyp(self) -> HypothesisCard:
        return HypothesisCard(
            source_fact_id="test.py:1", is_vulnerable=True,
            confidence=0.85, attack_path="SSRF",
            file_path="test.py", line_start=1, line_end=5,
            code_snippet="requests.get(url)",
        )

    def _make_ev(self) -> EvidenceChain:
        return EvidenceChain(
            hypothesis_id="test.py:1", verdict="confirmed",
            final_confidence=0.85,
            evidence=[EvidenceItem(tool="semgrep", result="found")],
            file_path="test.py", line_start=1, line_end=5,
        )

    def test_empty_cache_miss(self):
        fe = FrugalEngine(cache_path=_tmp_path())
        assert fe.lookup(self._make_fact(), "SSRF") is None

    def test_store_and_lookup(self):
        fe = FrugalEngine(cache_path=_tmp_path())
        fc = self._make_fact()
        fe.store(fc, "SSRF", self._make_hyp(), self._make_ev())
        hit = fe.lookup(fc, "SSRF")
        assert hit is not None
        assert hit.hit_count == 1

    def test_similar_code_hits(self):
        fe = FrugalEngine(cache_path=_tmp_path())
        fc1 = self._make_fact(sink="requests.get", flow=["url->requests.get"])
        fe.store(fc1, "SSRF", self._make_hyp(), self._make_ev())
        # Same pattern, different file
        fc2 = FactCard(
            file_path="other.py", line_start=10, line_end=15,
            code_snippet="requests.get(target)", language="python",
            data_flow=["url->requests.get"], heuristics=["外部可控URL", "无校验"],
            confidence=0.7, sink="requests.get",
        )
        hit = fe.lookup(fc2, "SSRF")
        assert hit is not None

    def test_different_code_misses(self):
        fe = FrugalEngine(cache_path=_tmp_path())
        fc1 = self._make_fact(sink="requests.get")
        fe.store(fc1, "SSRF", self._make_hyp(), self._make_ev())
        # Completely different pattern
        fc2 = FactCard(
            file_path="other.py", line_start=1, line_end=5,
            code_snippet="cursor.execute(sql)", language="python",
            data_flow=["sql->cursor.execute"], heuristics=["SQL注入"],
            confidence=0.9, sink="cursor.execute",
        )
        hit = fe.lookup(fc2, "SSRF")
        assert hit is None

    def test_cleanup_removes_expired(self):
        path = _tmp_path()
        fe = FrugalEngine(cache_path=path)
        fc = self._make_fact()
        fe.store(fc, "SSRF", self._make_hyp(), self._make_ev())
        # Manually expire
        fe._entries[0].expires_at = "2020-01-01T00:00:00"
        removed = fe.cleanup()
        assert removed >= 1

    def test_stats_tracking(self):
        fe = FrugalEngine(cache_path=_tmp_path())
        fc = self._make_fact()
        fe.lookup(fc, "SSRF")  # miss
        fe.store(fc, "SSRF", self._make_hyp(), self._make_ev())
        fe.lookup(fc, "SSRF")  # hit
        stats = fe.stats()
        assert stats["total_hits"] == 1
        assert stats["total_misses"] == 1
        assert stats["llm_calls_saved"] == 1
