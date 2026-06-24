"""SelfHealer - graceful degradation and error recovery."""
from __future__ import annotations

import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain, EvidenceItem
from policy.engine import PolicyConfig


@dataclass
class HealingEvent:
    """Records a self-healing action."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    agent_type: str = ""
    error_type: str = ""
    error_message: str = ""
    action_taken: str = ""
    resolved: bool = False


class SelfHealer:
    """Handles tool failures, LLM timeouts, and parse errors gracefully."""

    def __init__(self, policy: Optional[PolicyConfig] = None):
        self.policy = policy or PolicyConfig()
        self._events: list[HealingEvent] = []

    def handle_tool_failure(self, error: Exception,
                             hypothesis: HypothesisCard) -> EvidenceChain:
        """Generate a placeholder EvidenceChain when a tool fails."""
        event = HealingEvent(
            agent_type="tool_executor",
            error_type="tool_unavailable",
            error_message=str(error)[:200],
            action_taken="degraded",
            resolved=False,
        )
        self._events.append(event)

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
            manual_review_note=f"工具不可用，需人工验证: {str(error)[:100]}",
            evidence=[EvidenceItem(
                tool="healer",
                result=f"Degraded: {str(error)[:100]}",
            )],
        )

    def handle_llm_timeout(self, fact_card: FactCard,
                            retry_count: int) -> Optional[HypothesisCard]:
        """Handle LLM timeout. Returns placeholder if retries exhausted."""
        if retry_count < self.policy.max_tool_retries:
            event = HealingEvent(
                agent_type="semantic_analyst",
                error_type="timeout",
                error_message=f"LLM timeout (attempt {retry_count + 1})",
                action_taken="retried",
                resolved=False,
            )
            self._events.append(event)
            return None  # Signal caller to retry

        # Retries exhausted — return low-confidence placeholder
        event = HealingEvent(
            agent_type="semantic_analyst",
            error_type="timeout",
            error_message="LLM timeout after retries",
            action_taken="manual_review",
            resolved=False,
        )
        self._events.append(event)

        return HypothesisCard(
            source_fact_id=f"{fact_card.file_path}:{fact_card.line_start}",
            is_vulnerable=True,
            confidence=0.1,
            attack_path="LLM 超时，需人工审查",
            preconditions=[],
            reasoning="LLM 分析超时，自动生成低置信度占位假设",
            file_path=fact_card.file_path,
            line_start=fact_card.line_start,
            line_end=fact_card.line_end,
            code_snippet=fact_card.code_snippet,
        )

    def handle_parse_error(self, raw_response: str,
                            fact_card: FactCard) -> Optional[dict]:
        """Try to salvage data from a malformed LLM response."""
        event = HealingEvent(
            agent_type="semantic_analyst",
            error_type="parse_error",
            error_message=raw_response[:200] if raw_response else "empty",
            action_taken="degraded",
        )

        # Try to extract JSON from markdown code blocks
        if raw_response:
            text = raw_response.strip()
            # Remove code fences
            if "```" in text:
                lines = text.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                text = "\n".join(lines)

            # Try direct JSON parse
            import json
            try:
                result = json.loads(text)
                event.resolved = True
                event.action_taken = "extracted_json"
                self._events.append(event)
                return result
            except json.JSONDecodeError:
                pass

            # Try regex extraction of JSON object
            match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
            if match:
                try:
                    result = json.loads(match.group())
                    event.resolved = True
                    event.action_taken = "extracted_json_regex"
                    self._events.append(event)
                    return result
                except json.JSONDecodeError:
                    pass

        event.action_taken = "failed"
        self._events.append(event)
        return None

    def handle_dag_node_failure(self, node, error: Exception) -> None:
        """Record a DAG node failure without crashing."""
        event = HealingEvent(
            agent_type=getattr(node, 'agent_type', 'unknown'),
            error_type="dag_node_failure",
            error_message=str(error)[:200],
            action_taken="skipped",
            resolved=False,
        )
        self._events.append(event)

    def get_healing_log(self) -> list[dict]:
        """Return all healing events as dicts."""
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "agent_type": e.agent_type,
                "error_type": e.error_type,
                "error_message": e.error_message,
                "action_taken": e.action_taken,
                "resolved": e.resolved,
            }
            for e in self._events
        ]

    def get_stats(self) -> dict:
        """Return healing statistics."""
        total = len(self._events)
        resolved = len([e for e in self._events if e.resolved])
        by_type = {}
        for e in self._events:
            by_type[e.error_type] = by_type.get(e.error_type, 0) + 1
        return {
            "total_events": total,
            "resolved": resolved,
            "unresolved": total - resolved,
            "by_error_type": by_type,
        }
