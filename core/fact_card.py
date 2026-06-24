"""FactCard - perception layer output unit."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class FactCard:
    """Represents a single suspicious code fragment detected by the perception layer."""
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    language: str
    data_flow: List[str] = field(default_factory=list)
    heuristics: List[str] = field(default_factory=list)
    confidence: float = 0.0
    function_name: Optional[str] = None
    sink: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> FactCard:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def __repr__(self) -> str:
        return (
            f"FactCard(file={self.file_path!r}, lines={self.line_start}-{self.line_end}, "
            f"confidence={self.confidence:.2f}, heuristics={self.heuristics})"
        )
