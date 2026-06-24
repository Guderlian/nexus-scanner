"""PatternMatcherAgent - fast pattern matching without LLM."""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard
from knowledge.vuln_patterns import get_pattern


class PatternMatcherAgent:
    """Fast pattern-based vulnerability detection. No LLM calls, < 10ms."""

    def __init__(self, knowledge_base: dict = None):
        self.knowledge_base = knowledge_base

    def match(self, fact_card: FactCard, vuln_type: str) -> dict:
        """Match a FactCard against known patterns for a vulnerability type."""
        pattern = get_pattern(vuln_type)
        if not pattern:
            return {"matched": False, "matched_patterns": [], "confidence_boost": 0.0}

        snippet = fact_card.code_snippet
        matched = []
        boost = 0.0

        # Check dangerous functions
        for func in pattern.get("dangerous_functions", []):
            if func in snippet:
                matched.append(f"dangerous_function:{func}")
                boost += 0.15

        # Check dangerous patterns
        for dp in pattern.get("dangerous_patterns", []):
            if dp in snippet:
                matched.append(f"dangerous_pattern:{dp}")
                boost += 0.15

        # Check dangerous operations (IDOR)
        for dop in pattern.get("dangerous_operations", []):
            if dop in snippet:
                matched.append(f"dangerous_operation:{dop}")
                boost += 0.15

        # Check external sources in heuristics or snippet
        for src in pattern.get("external_sources", []):
            if src in snippet or src in str(fact_card.heuristics):
                matched.append(f"external_source:{src}")
                boost += 0.1

        # Check for missing checks (IDOR)
        for check in pattern.get("missing_checks", []):
            if check not in snippet:
                matched.append(f"missing_check:{check}")

        # Check safe patterns — reduce confidence
        safe_hit = 0
        for sp in pattern.get("safe_patterns", []):
            if sp in snippet:
                safe_hit += 1
                matched.append(f"safe_pattern:{sp}")

        if safe_hit > 0:
            boost -= 0.2 * safe_hit

        return {
            "matched": len([m for m in matched if not m.startswith("safe_")]) > 0,
            "matched_patterns": matched,
            "confidence_boost": round(boost, 2),
        }
