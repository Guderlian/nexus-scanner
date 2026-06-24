"""Self-healer tests."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from healing.self_healer import SelfHealer, HealingEvent
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain
from policy.engine import PolicyConfig


def _make_hyp() -> HypothesisCard:
    return HypothesisCard(
        source_fact_id="test.py:1", is_vulnerable=True,
        confidence=0.8, attack_path="SSRF",
        file_path="test.py", line_start=1, line_end=5,
        code_snippet="requests.get(url)",
    )


def _make_fact() -> FactCard:
    return FactCard(
        file_path="test.py", line_start=1, line_end=5,
        code_snippet="requests.get(url)", language="python",
        data_flow=["url->requests.get"], heuristics=["外部可控URL"],
        confidence=0.8,
    )


class TestToolFailure:
    def test_tool_unavailable_generates_placeholder(self):
        """工具不可用时应生成占位 EvidenceChain 不崩溃."""
        healer = SelfHealer()
        hyp = _make_hyp()
        chain = healer.handle_tool_failure(FileNotFoundError("semgrep not found"), hyp)
        assert isinstance(chain, EvidenceChain)
        assert chain.verdict == "unverified"
        assert "人工" in chain.manual_review_note or "工具" in chain.manual_review_note

    def test_healing_event_logged(self):
        healer = SelfHealer()
        healer.handle_tool_failure(RuntimeError("timeout"), _make_hyp())
        log = healer.get_healing_log()
        assert len(log) == 1
        assert log[0]["error_type"] == "tool_unavailable"


class TestLLMTimeout:
    def test_retry_returns_none(self):
        """重试次数未耗尽时应返回 None."""
        healer = SelfHealer()
        result = healer.handle_llm_timeout(_make_fact(), retry_count=0)
        assert result is None

    def test_exhausted_returns_placeholder(self):
        """重试耗尽时应返回低置信度占位."""
        config = PolicyConfig(max_tool_retries=2)
        healer = SelfHealer(policy=config)
        result = healer.handle_llm_timeout(_make_fact(), retry_count=2)
        assert result is not None
        assert result.confidence <= 0.2


class TestParseError:
    def test_salvage_json_from_markdown(self):
        healer = SelfHealer()
        raw = '```json\n{"is_vulnerable": true, "confidence": 0.8}\n```'
        result = healer.handle_parse_error(raw, _make_fact())
        assert result is not None
        assert result["is_vulnerable"] is True

    def test_salvage_json_from_messy_text(self):
        healer = SelfHealer()
        raw = 'Here is my analysis: {"is_vulnerable": false, "confidence": 0.1} hope that helps'
        result = healer.handle_parse_error(raw, _make_fact())
        assert result is not None

    def test_empty_returns_none(self):
        healer = SelfHealer()
        result = healer.handle_parse_error("", _make_fact())
        assert result is None


class TestHealingStats:
    def test_stats_aggregation(self):
        healer = SelfHealer()
        healer.handle_tool_failure(RuntimeError("e1"), _make_hyp())
        healer.handle_tool_failure(RuntimeError("e2"), _make_hyp())
        stats = healer.get_stats()
        assert stats["total_events"] == 2
        assert stats["by_error_type"]["tool_unavailable"] == 2
