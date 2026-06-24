"""GraphDesigner - generates task DAGs from FactCards."""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestrator.dag import DAGNode
from orchestrator.workspace import GlobalWorkspace
from core.fact_card import FactCard


class GraphDesigner:
    """Generates execution DAGs for vulnerability analysis."""

    def __init__(self, workspace: GlobalWorkspace):
        self.workspace = workspace

    def design(self, fact_cards: list[FactCard], vuln_types: list[str]) -> list[DAGNode]:
        """Generate a DAG for analyzing the given fact cards."""
        all_nodes: list[DAGNode] = []
        for i, fact in enumerate(fact_cards):
            fid = f"fact-{i:03d}"
            for vtype in vuln_types:
                sub = self._create_analysis_subgraph(fact, vtype, fid, i)
                all_nodes.extend(sub)
        return self._optimize_dag(all_nodes)

    def _create_analysis_subgraph(self, fact: FactCard, vuln_type: str,
                                   fact_id: str, idx: int) -> list[DAGNode]:
        """Create the standard 4-node sub-graph for one fact+type pair."""
        prefix = f"{fact_id}-{vuln_type}"
        fact_data = {
            "fact": fact.to_dict(),
            "vuln_type": vuln_type,
            "file_path": fact.file_path,
            "line_start": fact.line_start,
            "line_end": fact.line_end,
            "code_snippet": fact.code_snippet,
            "confidence": fact.confidence,
        }

        # PatternMatcher and SemanticAnalyst run in parallel
        n_pattern = DAGNode(
            node_id=f"PatternMatcher-{prefix}",
            agent_type="pattern",
            dependencies=[],
            input_data={**fact_data, "idx": idx},
        )
        n_semantic = DAGNode(
            node_id=f"SemanticAnalyst-{prefix}",
            agent_type="semantic",
            dependencies=[],
            input_data={**fact_data, "idx": idx},
        )
        # AdversarialVerifier depends on both
        n_verifier = DAGNode(
            node_id=f"Verifier-{prefix}",
            agent_type="verifier",
            dependencies=[n_pattern.node_id, n_semantic.node_id],
            input_data={**fact_data, "idx": idx},
        )
        # ToolExecutor depends on verifier
        n_executor = DAGNode(
            node_id=f"ToolExecutor-{prefix}",
            agent_type="executor",
            dependencies=[n_verifier.node_id],
            input_data={**fact_data, "idx": idx},
        )
        return [n_pattern, n_semantic, n_verifier, n_executor]

    def _optimize_dag(self, nodes: list[DAGNode]) -> list[DAGNode]:
        """Remove duplicate nodes (same node_id)."""
        seen = set()
        unique = []
        for n in nodes:
            if n.node_id not in seen:
                seen.add(n.node_id)
                unique.append(n)
        return unique
