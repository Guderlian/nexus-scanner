"""EvidenceChain - verification layer output unit."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime


@dataclass
class EvidenceItem:
    """Single piece of evidence."""
    tool: str
    result: str
    confidence_delta: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> EvidenceItem:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class EvidenceChain:
    """Represents a verified vulnerability with supporting evidence."""
    hypothesis_id: str
    verdict: str = "unverified"  # "confirmed", "unverified", "false_positive"
    final_confidence: float = 0.0
    evidence: List[EvidenceItem] = field(default_factory=list)
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    attack_path: str = ""
    preconditions: List[str] = field(default_factory=list)
    reasoning: str = ""
    manual_review_note: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> EvidenceChain:
        items = data.pop("evidence", [])
        chain = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        chain.evidence = [EvidenceItem.from_dict(e) for e in items]
        return chain

    def to_report(self) -> str:
        """Generate a Markdown vulnerability report."""
        severity = "🔴 HIGH" if self.final_confidence >= 0.7 else "🟡 MEDIUM" if self.final_confidence >= 0.4 else "🟢 LOW"
        lines = [
            f"# SSRF Vulnerability Report",
            f"",
            f"**Verdict:** {self.verdict}  ",
            f"**Severity:** {severity} (confidence: {self.final_confidence:.0%})  ",
            f"**File:** `{self.file_path}` (lines {self.line_start}-{self.line_end})  ",
            f"**Detected:** {self.timestamp}  ",
            f"",
            f"## Affected Code",
            f"```",
            self.code_snippet,
            f"```",
            f"",
            f"## Attack Path",
            self.attack_path or "N/A",
            f"",
            f"## Preconditions",
        ]
        for p in self.preconditions:
            lines.append(f"- {p}")
        if not self.preconditions:
            lines.append("- None identified")
        lines.extend([
            f"",
            f"## Analysis",
            self.reasoning or "N/A",
            f"",
            f"## Evidence",
        ])
        for ev in self.evidence:
            lines.append(f"- **{ev.tool}**: {ev.result}")
        if not self.evidence:
            lines.append("- No automated evidence collected")
        if self.manual_review_note:
            lines.extend([f"", f"## ⚠️ Manual Review Required", self.manual_review_note])
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"EvidenceChain(verdict={self.verdict!r}, conf={self.final_confidence:.2f}, "
            f"evidence={len(self.evidence)} items)"
        )
