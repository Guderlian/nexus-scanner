"""ToolExecutorAgent - verifies hypotheses using Semgrep."""
from __future__ import annotations

import os
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain, EvidenceItem
from tools.semgrep_runner import SemgrepRunner


class ToolExecutorAgent:
    """Verifies vulnerability hypotheses using automated tools."""

    def __init__(self, min_confidence: float = 0.5, semgrep_timeout: int = 60):
        self.min_confidence = min_confidence
        self.semgrep_runner = SemgrepRunner(timeout=semgrep_timeout)

    def verify(self, hypothesis: HypothesisCard) -> EvidenceChain:
        """Verify a single hypothesis. Returns an EvidenceChain."""
        # Reject hypotheses that were rejected by AdversarialVerifier
        if getattr(hypothesis, 'status', 'pending') == 'rejected':
            return EvidenceChain(
                hypothesis_id=f"{hypothesis.file_path}:{hypothesis.line_start}",
                verdict="false_positive",
                final_confidence=0.0,
                file_path=hypothesis.file_path,
                line_start=hypothesis.line_start,
                line_end=hypothesis.line_end,
                code_snippet=hypothesis.code_snippet,
                reasoning=hypothesis.reasoning,
                manual_review_note="假设已被 AdversarialVerifier 拒绝",
            )

        if hypothesis.confidence < self.min_confidence:
            return EvidenceChain(
                hypothesis_id=f"{hypothesis.file_path}:{hypothesis.line_start}",
                verdict="unverified",
                final_confidence=hypothesis.confidence,
                file_path=hypothesis.file_path,
                line_start=hypothesis.line_start,
                line_end=hypothesis.line_end,
                code_snippet=hypothesis.code_snippet,
                attack_path=hypothesis.attack_path,
                preconditions=hypothesis.preconditions,
                reasoning=hypothesis.reasoning,
            )

        # Run Semgrep
        result = self.semgrep_runner.run(
            target_path=hypothesis.file_path,
            hypothesis_id=f"{hypothesis.file_path}:{hypothesis.line_start}",
            file_path=hypothesis.file_path,
            line_start=hypothesis.line_start,
            line_end=hypothesis.line_end,
            code_snippet=hypothesis.code_snippet,
            attack_path=hypothesis.attack_path,
            preconditions=hypothesis.preconditions,
            reasoning=hypothesis.reasoning,
        )

        if isinstance(result, dict) and "status" in result:
            # Tool unavailable or error
            status = result["status"]
            if status == "tool_unavailable":
                return EvidenceChain(
                    hypothesis_id=f"{hypothesis.file_path}:{hypothesis.line_start}",
                    verdict="unverified",
                    final_confidence=hypothesis.confidence,
                    file_path=hypothesis.file_path,
                    line_start=hypothesis.line_start,
                    line_end=hypothesis.line_end,
                    code_snippet=hypothesis.code_snippet,
                    attack_path=hypothesis.attack_path,
                    preconditions=hypothesis.preconditions,
                    reasoning=hypothesis.reasoning,
                    manual_review_note="Semgrep 不可用，需人工验证此 SSRF 漏洞",
                    evidence=[EvidenceItem(tool="system", result=f"Semgrep 状态: {status}")],
                )
            return EvidenceChain(
                hypothesis_id=f"{hypothesis.file_path}:{hypothesis.line_start}",
                verdict="unverified",
                final_confidence=hypothesis.confidence,
                file_path=hypothesis.file_path,
                line_start=hypothesis.line_start,
                line_end=hypothesis.line_end,
                code_snippet=hypothesis.code_snippet,
                attack_path=hypothesis.attack_path,
                preconditions=hypothesis.preconditions,
                reasoning=hypothesis.reasoning,
                manual_review_note=f"Semgrep 运行异常 ({status})，需人工验证",
                evidence=[EvidenceItem(tool="system", result=f"Semgrep 状态: {status}")],
            )

        # result is a dict from EvidenceChain.to_dict()
        if isinstance(result, dict):
            return EvidenceChain.from_dict(result)

        # Fallback
        return EvidenceChain(
            hypothesis_id=f"{hypothesis.file_path}:{hypothesis.line_start}",
            verdict="unverified",
            final_confidence=hypothesis.confidence,
            file_path=hypothesis.file_path,
            line_start=hypothesis.line_start,
            line_end=hypothesis.line_end,
            code_snippet=hypothesis.code_snippet,
        )

    def verify_batch(self, hypotheses: List[HypothesisCard]) -> List[EvidenceChain]:
        """Verify a batch of hypotheses."""
        results = []
        for h in hypotheses:
            results.append(self.verify(h))
        return results
