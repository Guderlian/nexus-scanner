#!/usr/bin/env python3
"""Nexus P1 - Multi-Agent DAG Orchestration for Vulnerability Detection."""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain, EvidenceItem
from perception.encoder import PerceptionEncoder
from orchestrator.workspace import GlobalWorkspace
from orchestrator.dag import DAGNode, DAGExecutor
from orchestrator.graph_designer import GraphDesigner
from agents.pattern_matcher import PatternMatcherAgent
from agents.semantic_analyst import SemanticAnalystAgent
from agents.adversarial_verifier import AdversarialVerifierAgent
from agents.tool_executor import ToolExecutorAgent
from agents.planner import PlannerAgent
from knowledge.vuln_patterns import list_vuln_types


class NexusPipelineV2:
    """P1 pipeline: multi-agent DAG-orchestrated vulnerability analysis."""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", min_confidence: float = 0.5,
                 max_workers: int = 3, vuln_types: Optional[list[str]] = None):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.min_confidence = min_confidence
        self.max_workers = max_workers
        self.vuln_types = vuln_types or ["SSRF"]

        # Agents
        self.pattern_matcher = PatternMatcherAgent()
        self.semantic_analyst = SemanticAnalystAgent(
            api_key=api_key, base_url=base_url, model=model, min_confidence=min_confidence,
        )
        self.adversarial_verifier = AdversarialVerifierAgent(
            api_key=api_key, base_url=base_url, model=model,
        )
        self.tool_executor = ToolExecutorAgent(min_confidence=min_confidence)
        self.planner = PlannerAgent(
            api_key=api_key, base_url=base_url, model=model,
        )

    def run(self, target_path: str, output_path: str = "report_p1.md") -> dict:
        """Run the full P1 pipeline. Returns execution report."""
        workspace = GlobalWorkspace()
        total_start = time.time()

        # Phase 1: Perception
        print(f"[Nexus P1] 开始分析：{target_path}")
        encoder = PerceptionEncoder()
        if os.path.isfile(target_path):
            facts = encoder.encode_file(target_path)
        else:
            facts = encoder.encode_directory(target_path)
        workspace.add_facts(facts)

        # Count by type hint
        ssrf_count = sum(1 for f in facts if any(h in str(f.heuristics) for h in ["外部可控URL", "无URL校验"]) or (f.sink and "requests" in f.sink))
        sqli_count = sum(1 for f in facts if f.sink and ("execute" in f.sink or "raw" in f.sink))
        idor_count = sum(1 for f in facts if "ID参数" in str(f.heuristics))
        print(f"[感知层] 发现 {len(facts)} 个片段（SSRF:{ssrf_count} SQLi:{sqli_count} IDOR:{idor_count}）")

        if not facts:
            print("[结果] 未发现可疑代码片段。")
            return {"facts": 0, "vulnerabilities": 0}

        # Phase 2: Planner
        plan = self.planner.plan(facts, self.vuln_types)
        high_priority = [p for p in plan if p.get("priority", 0) >= 4]
        print(f"[规划层] Planner 生成分析计划，{len(high_priority)} 个高优先级任务")

        # Phase 3: Design DAG
        designer = GraphDesigner(workspace)
        nodes = designer.design(facts, self.vuln_types)
        print(f"[DAG] 生成 {len(nodes)} 个节点，开始并行执行...")

        # Phase 4: Register agents and execute
        executor = DAGExecutor(workspace, max_workers=self.max_workers)
        self._register_agents(executor, workspace)
        summary = executor.execute(nodes)

        # Print node results
        for nd in summary.get("nodes", []):
            status_icon = "✅" if nd["status"] == "done" else "❌"
            dur = f"{nd['duration_ms']:.0f}ms" if nd["duration_ms"] else "N/A"
            print(f"[DAG] 节点 {nd['node_id']} {status_icon} ({dur})")

        # Phase 5: Collect evidences from workspace
        evidences = workspace.state.evidences
        confirmed = [e for e in evidences if e.verdict == "confirmed"]
        unverified = [e for e in evidences if e.verdict != "confirmed" and e.verdict != "false_positive"]

        # Phase 6: Generate report
        total_ms = (time.time() - total_start) * 1000
        speedup = summary.get("speedup", 1.0)

        report = self._generate_report(target_path, facts, evidences, summary)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"[报告] 发现 {len(evidences)} 个漏洞（SSRF/SQLi/IDOR 混合）")
        print(f"[性能] 总耗时 {total_ms/1000:.1f}s，并行加速比 {speedup}x（对比串行估算）")

        return {
            "facts": len(facts),
            "vulnerabilities": len(evidences),
            "confirmed": len(confirmed),
            "unverified": len(unverified),
            "total_ms": total_ms,
            "speedup": speedup,
            "report_path": output_path,
        }

    def _register_agents(self, executor: DAGExecutor, workspace: GlobalWorkspace) -> None:
        """Register all agent handlers with the DAG executor."""

        def pattern_handler(node: DAGNode, ws: GlobalWorkspace):
            fact_data = node.input_data
            fact = FactCard.from_dict(fact_data["fact"])
            vuln_type = fact_data["vuln_type"]
            result = self.pattern_matcher.match(fact, vuln_type)
            node.output_data = result
            ws.add_note("PatternMatcher", f"{fact.file_path}:{fact.line_start} → {result['matched']}")

        def semantic_handler(node: DAGNode, ws: GlobalWorkspace):
            fact_data = node.input_data
            fact = FactCard.from_dict(fact_data["fact"])
            card = self.semantic_analyst.analyze(fact)
            if card:
                node.output_data = card.to_dict()
                ws.add_hypothesis(card)
            else:
                node.output_data = {"is_vulnerable": False}
            ws.add_note("SemanticAnalyst", f"{fact.file_path}:{fact.line_start} → analyzed")

        def verifier_handler(node: DAGNode, ws: GlobalWorkspace):
            fact_data = node.input_data
            fact = FactCard.from_dict(fact_data["fact"])

            # Find the hypothesis from workspace
            hypotheses = ws.state.hypotheses
            hyp = None
            for h in hypotheses:
                if h.file_path == fact.file_path and h.line_start == fact.line_start:
                    hyp = h
                    break

            if hyp is None:
                # Create a basic hypothesis from the fact
                hyp = HypothesisCard(
                    source_fact_id=f"{fact.file_path}:{fact.line_start}",
                    is_vulnerable=True,
                    confidence=fact.confidence,
                    file_path=fact.file_path,
                    line_start=fact.line_start,
                    line_end=fact.line_end,
                    code_snippet=fact.code_snippet,
                )

            # Get pattern result from sibling node
            pattern_result = {}
            for dep_id in node.dependencies:
                for n_all in []:  # we'll get from output_data
                    pass
            # Use the pattern matcher directly
            pattern_result = self.pattern_matcher.match(fact, fact_data["vuln_type"])

            updated = self.adversarial_verifier.verify(hyp, pattern_result, fact)
            node.output_data = updated.to_dict()
            ws.add_note("AdversarialVerifier",
                        f"{fact.file_path}:{fact.line_start} → survived={updated.status != 'rejected'}, conf={updated.confidence:.2f}")

        def executor_handler(node: DAGNode, ws: GlobalWorkspace):
            fact_data = node.input_data
            fact = FactCard.from_dict(fact_data["fact"])

            # Find hypothesis
            hyp = None
            for h in ws.state.hypotheses:
                if h.file_path == fact.file_path and h.line_start == fact.line_start:
                    hyp = h
                    break

            if hyp is None:
                node.output_data = {"status": "no_hypothesis"}
                return

            if hyp.status == "rejected":
                node.output_data = {"status": "rejected"}
                return

            chain = self.tool_executor.verify(hyp)
            ws.add_evidence(chain)
            node.output_data = chain.to_dict()
            ws.add_note("ToolExecutor",
                        f"{fact.file_path}:{fact.line_start} → {chain.verdict}")

        executor.register_agent("pattern", pattern_handler)
        executor.register_agent("semantic", semantic_handler)
        executor.register_agent("verifier", verifier_handler)
        executor.register_agent("executor", executor_handler)

    def _generate_report(self, target: str, facts: list[FactCard],
                         evidences: list[EvidenceChain], summary: dict) -> str:
        """Generate the final markdown report."""
        parts = [
            "# Nexus P1 - Vulnerability Analysis Report\n",
            f"**Target:** `{target}`  ",
            f"**Fragments scanned:** {len(facts)}  ",
            f"**DAG nodes:** {summary.get('total_nodes', 0)}  ",
            f"**Speedup:** {summary.get('speedup', 1.0)}x  ",
            f"**Total time:** {summary.get('total_ms', 0):.0f}ms\n",
            "---\n",
        ]

        if not evidences:
            parts.append("No vulnerabilities confirmed.\n")
        else:
            for chain in evidences:
                parts.append(chain.to_report())
                parts.append("\n---\n")

        return "\n".join(parts)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Nexus P1 - Multi-Agent DAG Vulnerability Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="Target directory or file to scan")
    parser.add_argument("--api-key", default=None, help="LLM API Key (or NEXUS_API_KEY env)")
    parser.add_argument("--base-url", default="https://api.openai.com/v1", help="LLM API base URL")
    parser.add_argument("--model", default="gpt-4o-mini", help="LLM model name")
    parser.add_argument("--output", default="report_p1.md", help="Output report path")
    parser.add_argument("--min-confidence", type=float, default=0.5, help="Min confidence threshold")
    parser.add_argument("--vuln-types", default="SSRF,SQLI,IDOR", help="Comma-separated vuln types")
    parser.add_argument("--max-workers", type=int, default=3, help="Max parallel DAG workers")
    return parser.parse_args()


def main():
    args = parse_args()

    api_key = args.api_key or os.environ.get("NEXUS_API_KEY", "")
    if not api_key:
        print("❌ 请通过 --api-key 或 NEXUS_API_KEY 提供 API Key")
        sys.exit(1)

    if not os.path.exists(args.target):
        print(f"❌ 目标不存在: {args.target}")
        sys.exit(1)

    vuln_types = [vt.strip().upper() for vt in args.vuln_types.split(",")]

    pipeline = NexusPipelineV2(
        api_key=api_key,
        base_url=args.base_url,
        model=args.model,
        min_confidence=args.min_confidence,
        max_workers=args.max_workers,
        vuln_types=vuln_types,
    )

    result = pipeline.run(args.target, args.output)
    print(f"\n✅ 分析完成，报告已保存至 {args.output}")


if __name__ == "__main__":
    main()
