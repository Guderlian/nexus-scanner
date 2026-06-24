"""Verifier protocol tests - probabilistic calibration."""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.adversarial_verifier import AdversarialVerifierAgent
from agents.tool_executor import ToolExecutorAgent
from tools.semgrep_runner import SemgrepRunner
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard


def _make_fact() -> FactCard:
    return FactCard('test.py', 1, 5, 'requests.get(url)', 'python',
                    ['url->requests.get'], ['外部可控URL'], 0.8)


def _make_hyp(conf=0.85) -> HypothesisCard:
    return HypothesisCard(
        source_fact_id='test.py:1', is_vulnerable=True,
        confidence=conf, attack_path='内网探测',
        preconditions=['URL外部可控'], reasoning='直接传参',
        file_path='test.py', line_start=1, line_end=5,
        code_snippet='requests.get(url)',
    )


def _make_verifier(llm_response: str) -> AdversarialVerifierAgent:
    verifier = AdversarialVerifierAgent.__new__(AdversarialVerifierAgent)
    verifier._call_llm = MagicMock(return_value=llm_response)
    verifier.retry_count = 0
    verifier.timeout = 30
    verifier.model = 'test'
    return verifier


class TestVerifierProtocol:
    def test_rejected_with_protective_code_blocks_executor(self):
        """有protective_code的rejected → ToolExecutor返回false_positive."""
        resp = '{"survived": false, "confidence_adjustment": -0.5, "evidence_found": "白名单", "protective_code": "if url not in ALLOWED: return 403"}'
        verifier = _make_verifier(resp)
        rejected = verifier.verify(_make_hyp(), {}, _make_fact())
        assert rejected.status == 'rejected'
        assert rejected.confidence == 0.0
        executor = ToolExecutorAgent(SemgrepRunner())
        result = executor.verify(rejected)
        assert result.verdict == 'false_positive'

    def test_confidence_zeroed_on_reject_with_evidence(self):
        """有protective_code时rejected置信度归零."""
        resp = '{"survived": false, "confidence_adjustment": -0.5, "evidence_found": "urlparse", "protective_code": "urlparse(url)"}'
        verifier = _make_verifier(resp)
        rejected = verifier.verify(_make_hyp(conf=0.9), {}, _make_fact())
        assert rejected.confidence == 0.0

    def test_survived_passes_to_executor(self):
        """survived=True时ToolExecutor正常处理."""
        verifier = _make_verifier('{"survived": true, "confidence_adjustment": 0.0, "evidence_found": "no protection", "protective_code": null}')
        survived = verifier.verify(_make_hyp(), {}, _make_fact())
        assert survived.status != 'rejected'
        assert survived.confidence > 0

    def test_confidence_adjustment_applied(self):
        """confidence_adjustment正确叠加."""
        verifier = _make_verifier('{"survived": true, "confidence_adjustment": -0.2, "evidence_found": "partial", "protective_code": null}')
        result = verifier.verify(_make_hyp(conf=0.8), {}, _make_fact())
        assert abs(result.confidence - 0.6) < 0.01

    def test_evidence_appended_to_reasoning(self):
        """evidence_found被追加到reasoning."""
        verifier = _make_verifier('{"survived": true, "confidence_adjustment": 0.0, "evidence_found": "无URL校验", "protective_code": null}')
        result = verifier.verify(_make_hyp(), {}, _make_fact())
        assert '无URL校验' in result.reasoning

    # --- New tests for probabilistic calibration ---

    def test_rejected_without_protective_code_downgrades(self):
        """survived=false但无protective_code时，不应rejected而是降级存活."""
        resp = '{"survived": false, "confidence_adjustment": -0.3, "evidence_found": "可能存在隐式校验", "protective_code": null}'
        verifier = _make_verifier(resp)
        result = verifier.verify(_make_hyp(conf=0.8), {}, _make_fact())
        # Should NOT be rejected — downgraded instead
        assert result.status != 'rejected', '无明确防护代码不应rejected'
        assert result.confidence > 0, '降级后置信度应>0'
        assert result.confidence < 0.8, '降级后置信度应降低'

    def test_parse_failure_survives(self):
        """LLM响应无法解析时，假设存活."""
        verifier = _make_verifier('这不是JSON，是LLM的自然语言回复。')
        result = verifier.verify(_make_hyp(conf=0.8), {}, _make_fact())
        assert result.status != 'rejected'
        assert result.confidence > 0

    def test_no_speculative_rejection(self):
        """包含推测词但无protective_code的响应，不触发rejected."""
        resp = '{"survived": false, "confidence_adjustment": -0.2, "evidence_found": "可能有middleware过滤", "protective_code": null}'
        verifier = _make_verifier(resp)
        result = verifier.verify(_make_hyp(conf=0.85), {}, _make_fact())
        assert result.status != 'rejected', '推测性理由不应rejected'
        assert '降级' in result.reasoning or '存活' in result.reasoning
