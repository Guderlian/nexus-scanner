"""HypothesisCard - reasoning layer output unit."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional
import json


@dataclass
class HypothesisCard:
    """Represents a vulnerability hypothesis produced by the semantic analyst."""
    source_fact_id: str
    is_vulnerable: bool = False
    confidence: float = 0.0
    attack_path: str = ""
    preconditions: List[str] = field(default_factory=list)
    reasoning: str = ""
    false_positive_risk: str = "medium"
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    status: str = "pending"  # pending / rejected / confirmed

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> HypothesisCard:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_llm_json(cls, raw: str, source_fact_id: str, file_path: str = "",
                       line_start: int = 0, line_end: int = 0, code_snippet: str = "") -> Optional[HypothesisCard]:
        """Parse LLM output, handling markdown code blocks."""
        text = raw.strip()
        # Strip markdown code fences
        if text.startswith("```"):
            lines = text.split("\n")
            # remove first and last fence lines
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return cls(
            source_fact_id=source_fact_id,
            is_vulnerable=data.get("is_vulnerable", False),
            confidence=float(data.get("confidence", 0.0)),
            attack_path=data.get("attack_path", ""),
            preconditions=data.get("preconditions", []),
            reasoning=data.get("reasoning", ""),
            false_positive_risk=data.get("false_positive_risk", "medium"),
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
        )

    def __repr__(self) -> str:
        return (
            f"HypothesisCard(vuln={self.is_vulnerable}, conf={self.confidence:.2f}, "
            f"risk={self.false_positive_risk})"
        )
