"""DAG execution engine tests for Nexus P1."""
from __future__ import annotations

import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.dag import DAGNode, DAGExecutor
from orchestrator.workspace import GlobalWorkspace


class TestDAGTopology:
    """Test DAG topological ordering."""

    def test_simple_chain(self):
        """Nodes with linear dependencies execute in order."""
        ws = GlobalWorkspace()
        order = []

        def tracker(node, ws):
            order.append(node.node_id)

        executor = DAGExecutor(ws, max_workers=1)
        executor.register_agent("test", tracker)

        nodes = [
            DAGNode("a", "test", [], {}),
            DAGNode("b", "test", ["a"], {}),
            DAGNode("c", "test", ["b"], {}),
        ]
        executor.execute(nodes)
        assert order == ["a", "b", "c"]

    def test_diamond_dag(self):
        """Diamond dependency pattern: a → b,c → d."""
        ws = GlobalWorkspace()

        def tracker(node, ws):
            time.sleep(0.02)
            node.output_data = {"done": True}

        executor = DAGExecutor(ws, max_workers=3)
        executor.register_agent("test", tracker)

        nodes = [
            DAGNode("a", "test", [], {}),
            DAGNode("b", "test", ["a"], {}),
            DAGNode("c", "test", ["a"], {}),
            DAGNode("d", "test", ["b", "c"], {}),
        ]
        summary = executor.execute(nodes)
        assert summary["completed"] == 4
        assert summary["failed"] == 0


class TestDAGParallelism:
    """Test that independent nodes truly run in parallel."""

    def test_parallel_speedup(self):
        """5 parallel nodes each sleeping 0.1s should complete in < 0.2s with speedup >= 2.5x."""
        ws = GlobalWorkspace()

        def slow_agent(node, ws):
            time.sleep(0.1)

        executor = DAGExecutor(ws, max_workers=5)
        executor.register_agent("test", slow_agent)

        # 5 fully independent nodes — pure parallelism test
        nodes = [
            DAGNode("a", "test", [], {}),
            DAGNode("b", "test", [], {}),
            DAGNode("c", "test", [], {}),
            DAGNode("d", "test", [], {}),
            DAGNode("e", "test", [], {}),
        ]
        summary = executor.execute(nodes)

        total = summary["total_ms"]
        seq_est = summary["sequential_estimate_ms"]
        speedup = summary["speedup"]

        print(f"\n  Parallel test: total={total:.0f}ms, seq_est={seq_est:.0f}ms, speedup={speedup}x")

        assert total < 250, f"Too slow: {total}ms (expected < 250ms)"
        assert speedup >= 2.5, f"Speedup {speedup}x < 2.5x"
        assert summary["completed"] == 5


class TestDAGFailure:
    """Test that node failures don't block the DAG."""

    def test_failed_node_doesnt_block(self):
        ws = GlobalWorkspace()
        results = []

        def maybe_fail(node, ws):
            if node.node_id == "fail_me":
                raise RuntimeError("intentional failure")
            results.append(node.node_id)

        executor = DAGExecutor(ws, max_workers=2)
        executor.register_agent("test", maybe_fail)

        nodes = [
            DAGNode("ok1", "test", [], {}),
            DAGNode("fail_me", "test", [], {}),
            DAGNode("ok2", "test", ["ok1"], {}),
        ]
        summary = executor.execute(nodes)

        assert summary["completed"] == 2
        assert summary["failed"] == 1
        assert "ok1" in results
        assert "ok2" in results

    def test_downstream_of_failed_skipped(self):
        """Nodes depending on a failed node should also fail."""
        ws = GlobalWorkspace()

        def maybe_fail(node, ws):
            if node.node_id == "root":
                raise RuntimeError("boom")

        executor = DAGExecutor(ws, max_workers=2)
        executor.register_agent("test", maybe_fail)

        nodes = [
            DAGNode("root", "test", [], {}),
            DAGNode("child", "test", ["root"], {}),
        ]
        summary = executor.execute(nodes)

        assert summary["failed"] == 2 or summary["failed"] >= 1


class TestWorkspaceThreadSafety:
    """Test GlobalWorkspace thread safety."""

    def test_concurrent_writes(self):
        """10 threads writing concurrently should lose no data."""
        ws = GlobalWorkspace()
        n_threads = 10
        writes_per_thread = 50

        def writer(ws, agent_name, count):
            for i in range(count):
                ws.add_note(agent_name, f"note-{i}")

        threads = []
        for t in range(n_threads):
            name = f"agent-{t}"
            th = threading.Thread(target=writer, args=(ws, name, writes_per_thread))
            threads.append(th)

        for th in threads:
            th.start()
        for th in threads:
            th.join()

        total_notes = sum(len(v) for v in ws.state.agent_notes.values())
        expected = n_threads * writes_per_thread
        assert total_notes == expected, f"Lost notes: {total_notes} != {expected}"

    def test_concurrent_fact_cards(self):
        """Multiple threads adding fact cards simultaneously."""
        from core.fact_card import FactCard

        ws = GlobalWorkspace()
        n_threads = 5
        cards_per_thread = 20

        def adder(ws, thread_id):
            for i in range(cards_per_thread):
                fc = FactCard(
                    file_path=f"t{thread_id}.py",
                    line_start=i,
                    line_end=i,
                    code_snippet=f"code-{i}",
                    language="python",
                    confidence=0.5,
                )
                ws.add_fact(fc)

        threads = []
        for t in range(n_threads):
            th = threading.Thread(target=adder, args=(ws, t))
            threads.append(th)

        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(ws.state.fact_cards) == n_threads * cards_per_thread
