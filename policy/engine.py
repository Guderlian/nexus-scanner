"""PolicyEngine - model routing, budget control, severity filtering."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain


@dataclass
class PolicyConfig:
    """All tunable policy knobs."""
    # Model routing
    fast_model: str = "gpt-4o-mini"
    smart_model: str = "gpt-4o-mini"
    verifier_model: str = "gpt-4o-mini"

    # Budget control
    max_llm_calls: int = 100
    max_fact_cards: int = 50
    max_dag_depth: int = 5
    min_confidence_threshold: float = 0.4

    # Cache policy
    cache_enabled: bool = True
    cache_similarity_threshold: float = 0.85
    cache_ttl_days: int = 30

    # Healing policy
    tool_unavailable_action: str = "mark_manual"
    max_tool_retries: int = 2
    tool_timeout_seconds: int = 60

    # Output policy
    severity_filter: list[str] = field(
        default_factory=lambda: ["critical", "high", "medium"])
    include_reasoning: bool = False


class PolicyEngine:
    """Enforces policies: model routing, budget, severity filtering."""

    def __init__(self, config: Optional[PolicyConfig] = None,
                 config_path: str = "config/policy.yaml"):
        if config is not None:
            self.config = config
        else:
            self.config = self._load_from_yaml(config_path)

    def _load_from_yaml(self, path: str) -> PolicyConfig:
        """Load config from YAML, falling back to defaults."""
        try:
            import yaml
            if os.path.exists(path):
                with open(path, "r") as f:
                    data = yaml.safe_load(f) or {}
                # Map YAML keys to PolicyConfig fields
                model_data = data.get("model", {})
                perc_data = data.get("perception", {})
                ver_data = data.get("verification", {})
                return PolicyConfig(
                    max_llm_calls=data.get("budget", {}).get("max_llm_calls_per_run", 100),
                    max_fact_cards=data.get("budget", {}).get("max_fact_cards_per_run", 50),
                    min_confidence_threshold=perc_data.get("min_confidence", 0.4),
                    tool_timeout_seconds=ver_data.get("semgrep_timeout_seconds", 60),
                    tool_unavailable_action=ver_data.get("tool_unavailable_action", "mark_manual"),
                )
        except Exception:
            pass
        return PolicyConfig()

    def should_skip_llm(self, fact_card: FactCard,
                         cache_hit: bool) -> tuple[bool, str]:
        """Decide whether to skip LLM analysis for a FactCard."""
        if cache_hit:
            return True, "cache_hit"
        if fact_card.confidence < 0.3:
            return True, "low_confidence"
        return False, "proceed"

    def should_run_tool(self, hypothesis: HypothesisCard) -> tuple[bool, str]:
        """Decide whether to run verification tools on a hypothesis."""
        if hypothesis.confidence < self.config.min_confidence_threshold:
            return False, "low_confidence"
        return True, "proceed"

    def get_model_for_agent(self, agent_type: str) -> str:
        """Route to the appropriate model for an agent type."""
        routing = {
            "planner": self.config.fast_model,
            "pattern": self.config.fast_model,
            "semantic": self.config.smart_model,
            "verifier": self.config.verifier_model,
            "executor": self.config.fast_model,
        }
        return routing.get(agent_type, self.config.smart_model)

    def check_budget(self, llm_calls_used: int,
                     fact_cards_processed: int) -> tuple[bool, str]:
        """Check if we're within budget."""
        if llm_calls_used >= self.config.max_llm_calls:
            return False, "llm_budget_exceeded"
        if fact_cards_processed >= self.config.max_fact_cards:
            return False, "fact_card_budget_exceeded"
        return True, "within_budget"

    def apply_severity_filter(self,
                               evidences: list[EvidenceChain]) -> list[EvidenceChain]:
        """Filter evidences by severity."""
        filtered = []
        for ev in evidences:
            severity = self._classify_severity(ev.final_confidence)
            if severity in self.config.severity_filter:
                filtered.append(ev)
        return filtered

    def _classify_severity(self, confidence: float) -> str:
        """Map confidence to severity level."""
        if confidence >= 0.8:
            return "critical"
        if confidence >= 0.6:
            return "high"
        if confidence >= 0.4:
            return "medium"
        return "low"
