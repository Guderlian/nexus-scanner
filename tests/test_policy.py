"""Policy engine tests."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.engine import PolicyEngine, PolicyConfig
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain, EvidenceItem


def _engine(**overrides) -> PolicyEngine:
    config = PolicyConfig(**overrides)
    return PolicyEngine(config=config)


def _fact(confidence=0.8) -> FactCard:
    return FactCard(
        file_path="test.py", line_start=1, line_end=5,
        code_snippet="requests.get(url)", language="python",
        data_flow=["url->requests.get"], heuristics=["外部可控URL"],
        confidence=confidence,
    )


def _hyp(confidence=0.8) -> HypothesisCard:
    return HypothesisCard(
        source_fact_id="test.py:1", is_vulnerable=True,
        confidence=confidence, attack_path="SSRF",
        file_path="test.py", line_start=1, line_end=5,
    )


def _ev(confidence=0.8) -> EvidenceChain:
    return EvidenceChain(
        hypothesis_id="test.py:1", verdict="confirmed",
        final_confidence=confidence,
        evidence=[EvidenceItem(tool="semgrep", result="found")],
        file_path="test.py", line_start=1, line_end=5,
    )


class TestShouldSkipLLM:
    def test_cache_hit_skips(self):
        engine = _engine()
        skip, reason = engine.should_skip_llm(_fact(), cache_hit=True)
        assert skip is True
        assert reason == "cache_hit"

    def test_low_confidence_skips(self):
        engine = _engine()
        skip, reason = engine.should_skip_llm(_fact(confidence=0.1), cache_hit=False)
        assert skip is True
        assert reason == "low_confidence"

    def test_normal_proceeds(self):
        engine = _engine()
        skip, reason = engine.should_skip_llm(_fact(confidence=0.8), cache_hit=False)
        assert skip is False
        assert reason == "proceed"


class TestBudgetCheck:
    def test_within_budget(self):
        engine = _engine(max_llm_calls=100, max_fact_cards=50)
        ok, reason = engine.check_budget(10, 20)
        assert ok is True

    def test_llm_budget_exceeded(self):
        engine = _engine(max_llm_calls=5)
        ok, reason = engine.check_budget(5, 1)
        assert ok is False
        assert reason == "llm_budget_exceeded"


class TestSeverityFilter:
    def test_filters_low_severity(self):
        engine = _engine(severity_filter=["critical", "high", "medium"])
        evs = [_ev(confidence=0.9), _ev(confidence=0.2)]
        filtered = engine.apply_severity_filter(evs)
        assert len(filtered) == 1  # Only the 0.9 one

    def test_all_pass_with_low_included(self):
        engine = _engine(severity_filter=["critical", "high", "medium", "low"])
        evs = [_ev(confidence=0.9), _ev(confidence=0.2)]
        filtered = engine.apply_severity_filter(evs)
        assert len(filtered) == 2


class TestModelRouting:
    def test_routes_correctly(self):
        engine = _engine(fast_model="fast", smart_model="smart", verifier_model="verifier")
        assert engine.get_model_for_agent("planner") == "fast"
        assert engine.get_model_for_agent("semantic") == "smart"
        assert engine.get_model_for_agent("verifier") == "verifier"
