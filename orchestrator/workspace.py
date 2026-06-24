"""GlobalWorkspace - shared structured memory for all agents."""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain


@dataclass
class WorkspaceState:
    """All intermediate state for the current analysis task."""
    fact_cards: list[FactCard] = field(default_factory=list)
    hypotheses: list[HypothesisCard] = field(default_factory=list)
    evidences: list[EvidenceChain] = field(default_factory=list)
    agent_notes: dict[str, list[str]] = field(default_factory=dict)
    dag_metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class GlobalWorkspace:
    """Thread-safe shared workspace for all agents."""

    def __init__(self):
        self.state = WorkspaceState()
        self._lock = threading.Lock()

    # ---- Fact Cards ----

    def add_fact(self, fact: FactCard) -> None:
        with self._lock:
            self.state.fact_cards.append(fact)

    def add_facts(self, facts: list[FactCard]) -> None:
        with self._lock:
            self.state.fact_cards.extend(facts)

    # ---- Hypotheses ----

    def add_hypothesis(self, h: HypothesisCard) -> None:
        with self._lock:
            self.state.hypotheses.append(h)

    def get_pending_hypotheses(self) -> list[HypothesisCard]:
        with self._lock:
            return [h for h in self.state.hypotheses
                    if getattr(h, 'status', 'pending') == 'pending']

    # ---- Evidences ----

    def add_evidence(self, e: EvidenceChain) -> None:
        with self._lock:
            self.state.evidences.append(e)

    def get_verified_evidences(self) -> list[EvidenceChain]:
        with self._lock:
            return [e for e in self.state.evidences if e.verdict == "confirmed"]

    # ---- Notes ----

    def add_note(self, agent_name: str, note: str) -> None:
        with self._lock:
            if agent_name not in self.state.agent_notes:
                self.state.agent_notes[agent_name] = []
            self.state.agent_notes[agent_name].append(note)

    # ---- DAG metadata ----

    def set_dag_metadata(self, key: str, value: Any) -> None:
        with self._lock:
            self.state.dag_metadata[key] = value

    # ---- Snapshot ----

    def snapshot(self) -> dict:
        """Serialize full state for logging."""
        with self._lock:
            return {
                "task_id": self.state.task_id,
                "created_at": self.state.created_at.isoformat(),
                "fact_cards_count": len(self.state.fact_cards),
                "hypotheses_count": len(self.state.hypotheses),
                "evidences_count": len(self.state.evidences),
                "verified_count": len([e for e in self.state.evidences if e.verdict == "confirmed"]),
                "agent_notes": dict(self.state.agent_notes),
                "dag_metadata": dict(self.state.dag_metadata),
            }
