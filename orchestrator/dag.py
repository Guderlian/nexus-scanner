"""DAG execution engine - parallel agent orchestration."""
from __future__ import annotations

import time
import concurrent.futures
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestrator.workspace import GlobalWorkspace


@dataclass
class DAGNode:
    """A single node in the execution DAG."""
    node_id: str
    agent_type: str        # "planner"/"semantic"/"pattern"/"verifier"/"executor"
    dependencies: list[str]  # node_ids this node depends on
    input_data: dict
    output_data: dict = None
    status: str = "pending"  # pending/running/done/failed
    started_at: datetime = None
    finished_at: datetime = None

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds() * 1000
        return None


class DAGExecutor:
    """Executes a DAG of agent nodes using thread-pool parallelism."""

    def __init__(self, workspace: GlobalWorkspace, max_workers: int = 3):
        self.workspace = workspace
        self.max_workers = max_workers
        self._agent_registry: dict[str, Callable] = {}

    def register_agent(self, agent_type: str, handler: Callable) -> None:
        """Register an agent handler: handler(node: DAGNode, workspace: GlobalWorkspace) -> None"""
        self._agent_registry[agent_type] = handler

    def execute(self, nodes: list[DAGNode]) -> dict:
        """Execute all nodes respecting dependencies. Returns execution summary."""
        node_map = {n.node_id: n for n in nodes}
        total_start = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            while True:
                ready = self._get_ready_nodes(nodes)
                if not ready:
                    # Check if all done or stuck
                    if all(n.status in ("done", "failed") for n in nodes):
                        break
                    # Deadlock detection
                    pending = [n for n in nodes if n.status == "pending"]
                    if pending:
                        for n in pending:
                            n.status = "failed"
                            n.output_data = {"error": "dependency deadlock"}
                        break
                    break

                futures = {}
                for node in ready:
                    node.status = "running"
                    node.started_at = datetime.utcnow()
                    futures[pool.submit(self._execute_node, node)] = node

                for future in concurrent.futures.as_completed(futures):
                    node = futures[future]
                    try:
                        future.result()
                    except Exception as exc:
                        node.status = "failed"
                        node.output_data = {"error": str(exc)}
                    finally:
                        node.finished_at = datetime.utcnow()

        total_ms = (time.time() - total_start) * 1000
        return self._build_execution_summary(nodes, total_ms)

    def _get_ready_nodes(self, nodes: list[DAGNode]) -> list[DAGNode]:
        """Find nodes whose dependencies are all done."""
        status_map = {n.node_id: n.status for n in nodes}
        ready = []
        for node in nodes:
            if node.status != "pending":
                continue
            deps_met = all(status_map.get(dep) == "done" for dep in node.dependencies)
            if deps_met:
                ready.append(node)
        return ready

    def _execute_node(self, node: DAGNode) -> None:
        """Execute a single node by dispatching to its registered agent."""
        handler = self._agent_registry.get(node.agent_type)
        if handler is None:
            node.status = "failed"
            node.output_data = {"error": f"No handler registered for agent type '{node.agent_type}'"}
            return
        try:
            handler(node, self.workspace)
            if node.status != "failed":
                node.status = "done"
        except Exception as exc:
            node.status = "failed"
            node.output_data = {"error": str(exc)}

    def _build_execution_summary(self, nodes: list[DAGNode], total_ms: float) -> dict:
        """Build a summary of the execution."""
        done = [n for n in nodes if n.status == "done"]
        failed = [n for n in nodes if n.status == "failed"]

        # Sequential estimate: sum of all node durations
        seq_ms = sum((n.duration_ms or 0) for n in nodes)
        speedup = seq_ms / total_ms if total_ms > 0 else 1.0

        node_details = []
        for n in nodes:
            node_details.append({
                "node_id": n.node_id,
                "agent_type": n.agent_type,
                "status": n.status,
                "duration_ms": n.duration_ms,
            })

        return {
            "total_nodes": len(nodes),
            "completed": len(done),
            "failed": len(failed),
            "total_ms": round(total_ms, 1),
            "sequential_estimate_ms": round(seq_ms, 1),
            "speedup": round(speedup, 2),
            "nodes": node_details,
        }
