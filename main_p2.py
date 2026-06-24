#!/usr/bin/env python3
"""Nexus P2 - Self-improving vulnerability detection with caching and healing."""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain
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
from cache.file_hasher import FileHasher
from cache.frugal_engine import FrugalEngine
from policy.engine import PolicyEngine, PolicyConfig
from healing.self_healer import SelfHealer
from storage.workspace_store import WorkspaceStore


class NexusPipelineV3:
    """P2 pipeline: cached, self-healing, policy-driven vulnerability analysis."""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", min_confidence: float = 0.5,
                 max_workers: int = 3, vuln_types: list[str] = None,
                 incremental: bool = False):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.min_confidence = min_confidence
        self.max_workers = max_workers
        self.vuln_types = vuln_types or ["SSRF", "SQLI", "IDOR"]
        self.incremental = incremental

        # P2 components
        self.file_hasher = FileHasher()
        self.frugal_engine = FrugalEngine()
        self.frugal_engine.load()
        self.policy_engine = PolicyEngine()
        self.self_healer = SelfHealer(self.policy_engine.config)
        self.workspace_store = WorkspaceStore()

        # Agents
        self.pattern_matcher = PatternMatcherAgent()
        self.semantic_analyst = SemanticAnalystAgent(
            api_key=api_key, base_url=base_url, model=model,
            min_confidence=min_confidence,
        )
        self.adversarial_verifier = AdversarialVerifierAgent(
            api_key=api_key, base_url=base_url, model=model,
        )
        self.tool_executor = ToolExecutorAgent(min_confidence=min_confidence)
        self.planner = PlannerAgent(api_key=api_key, base_url=base_url, model=model)

    def run(self, target_path: str, output_path: str = "report_p2.md") -> dict:
        """Run the full P2 pipeline."""
        workspace = GlobalWorkspace()
        total_start = time.time()
        llm_calls = 0
        cache_hits = 0
        cache_misses = 0

        print(f"[Nexus P2] 开始分析：{target_path}")

        # Load cache stats
        cache_stats = self.frugal_engine.stats()
        print(f"[缓存] 加载历史经验缓存（{cache_stats['total_entries']} 条记录）")

        # Phase 1: File hashing
        if os.path.isfile(target_path):
            files_to_scan = [target_path]
        else:
            if self.incremental:
                files_to_scan = self.file_hasher.get_changed_files(target_path)
                total_files = sum(1 for _ in os.walk(target_path)
                                  for f in _[2] if f.endswith((".py", ".java")))
                print(f"[哈希] 检测文件变更...{len(files_to_scan)}/{total_files} 个文件需重新分析")
            else:
                files_to_scan = None  # Scan all

        # Phase 2: Perception
        encoder = PerceptionEncoder()
        if files_to_scan is not None:
            facts = []
            for f in files_to_scan:
                facts.extend(encoder.encode_file(f))
        elif os.path.isfile(target_path):
            facts = encoder.encode_file(target_path)
        else:
            facts = encoder.encode_directory(target_path)
        workspace.add_facts(facts)

        # Update hashes
        if self.incremental:
            for f in (files_to_scan or []):
                self.file_hasher.update(f)
            self.file_hasher.save()

        print(f"[感知层] 扫描 {len(files_to_scan or [])} 个文件...发现 {len(facts)} 个片段")

        if not facts:
            print("[结果] 未发现可疑代码片段。")
            return {"facts": 0, "vulnerabilities": 0}

        # Budget check
        within_budget, reason = self.policy_engine.check_budget(llm_calls, len(facts))
        print(f"[策略层] 预算检查：剩余 LLM 调用 {self.policy_engine.config.max_llm_calls - llm_calls}")

        # Phase 3: Cache lookup
        cached_results = []
        uncached_facts = []
        for fact in facts:
            for vt in self.vuln_types:
                hit = self.frugal_engine.lookup(fact, vt)
                if hit:
                    cache_hits += 1
                    cached_results.append(hit)
                else:
                    cache_misses += 1
                    uncached_facts.append(fact)

        print(f"[缓存] 查询经验缓存...{cache_hits} 命中，{cache_misses} 需 LLM 分析")

        # Phase 4: Planner (only for uncached)
        if uncached_facts:
            plan = self.planner.plan(uncached_facts, self.vuln_types)
            llm_calls += 1
            high_priority = [p for p in plan if p.get("priority", 0) >= 4]
            print(f"[规划层] Planner 生成分析计划，{len(high_priority)} 个高优先级任务")

        # Phase 5: Design and execute DAG
        designer = GraphDesigner(workspace)
        nodes = designer.design(uncached_facts or facts[:1], self.vuln_types)
        print(f"[DAG] 并行执行 {len(nodes)} 个节点...")

        executor = DAGExecutor(workspace, max_workers=self.max_workers)
        self._register_agents(executor, workspace)
        summary = executor.execute(nodes)

        for nd in summary.get("nodes", []):
            icon = "✅" if nd["status"] == "done" else "❌"
            dur = f"{nd['duration_ms']:.0f}ms" if nd["duration_ms"] else "N/A"
            print(f"[DAG] 节点 {nd['node_id']} {icon} ({dur})")

        # Phase 6: Store new cache entries
        stored = 0
        for ev in workspace.state.evidences:
            if ev.verdict == "confirmed":
                # Find matching hypothesis
                for hyp in workspace.state.hypotheses:
                    if hyp.file_path == ev.file_path and hyp.line_start == ev.line_start:
                        # Find matching fact
                        for fact in workspace.state.fact_cards:
                            if fact.file_path == ev.file_path and fact.line_start == ev.line_start:
                                for vt in self.vuln_types:
                                    self.frugal_engine.store(fact, vt, hyp, ev)
                                    stored += 1
                                break
                        break
        if stored:
            print(f"[缓存] 存储 {stored} 条新经验")

        # Phase 7: Save session
        session_id = self.workspace_store.save_session(workspace, target_path)
        self.workspace_store.complete_session(session_id)

        # Phase 8: Report
        evidences = workspace.state.evidences
        total_ms = (time.time() - total_start) * 1000
        speedup = summary.get("speedup", 1.0)
        saved_pct = (cache_hits / (cache_hits + cache_misses) * 100) if (cache_hits + cache_misses) > 0 else 0

        report = self._generate_report(target_path, facts, evidences, summary, cache_stats)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

        confirmed = [e for e in evidences if e.verdict == "confirmed"]
        print(f"[报告] 发现 {len(evidences)} 个漏洞，节省 {cache_hits} 次 LLM 调用")
        print(f"[性能] 总耗时 {total_ms/1000:.1f}s，缓存节省 {saved_pct:.0f}% 时间")

        return {
            "facts": len(facts),
            "vulnerabilities": len(evidences),
            "confirmed": len(confirmed),
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "llm_calls": llm_calls,
            "total_ms": total_ms,
            "speedup": speedup,
            "session_id": session_id,
            "report_path": output_path,
        }

    def _register_agents(self, executor: DAGExecutor, workspace: GlobalWorkspace) -> None:
        """Register agent handlers with the DAG executor."""
        healer = self.self_healer

        def pattern_handler(node: DAGNode, ws: GlobalWorkspace):
            fact = FactCard.from_dict(node.input_data["fact"])
            vuln_type = node.input_data["vuln_type"]
            result = self.pattern_matcher.match(fact, vuln_type)
            node.output_data = result

        def semantic_handler(node: DAGNode, ws: GlobalWorkspace):
            fact = FactCard.from_dict(node.input_data["fact"])
            try:
                card = self.semantic_analyst.analyze(fact)
                if card:
                    node.output_data = card.to_dict()
                    ws.add_hypothesis(card)
                else:
                    node.output_data = {"is_vulnerable": False}
            except Exception as e:
                node.output_data = {"is_vulnerable": False, "error": str(e)}

        def verifier_handler(node: DAGNode, ws: GlobalWorkspace):
            fact = FactCard.from_dict(node.input_data["fact"])
            vuln_type = node.input_data["vuln_type"]
            hyp = None
            for h in ws.state.hypotheses:
                if h.file_path == fact.file_path and h.line_start == fact.line_start:
                    hyp = h
                    break
            if hyp is None:
                node.output_data = {"status": "no_hypothesis"}
                return
            pattern_result = self.pattern_matcher.match(fact, vuln_type)
            try:
                updated = self.adversarial_verifier.verify(hyp, pattern_result, fact)
                node.output_data = updated.to_dict()
            except Exception as e:
                healer.handle_dag_node_failure(node, e)
                node.output_data = hyp.to_dict()

        def executor_handler(node: DAGNode, ws: GlobalWorkspace):
            fact = FactCard.from_dict(node.input_data["fact"])
            hyp = None
            for h in ws.state.hypotheses:
                if h.file_path == fact.file_path and h.line_start == fact.line_start:
                    hyp = h
                    break
            if hyp is None or hyp.status == "rejected":
                node.output_data = {"status": "skipped"}
                return
            try:
                chain = self.tool_executor.verify(hyp)
                ws.add_evidence(chain)
                node.output_data = chain.to_dict()
            except Exception as e:
                chain = healer.handle_tool_failure(e, hyp)
                ws.add_evidence(chain)
                node.output_data = chain.to_dict()

        executor.register_agent("pattern", pattern_handler)
        executor.register_agent("semantic", semantic_handler)
        executor.register_agent("verifier", verifier_handler)
        executor.register_agent("executor", executor_handler)

    def _generate_report(self, target, facts, evidences, summary, cache_stats) -> str:
        parts = [
            "# Nexus P2 - Vulnerability Analysis Report\n",
            f"**Target:** `{target}`  ",
            f"**Fragments:** {len(facts)}  ",
            f"**DAG nodes:** {summary.get('total_nodes', 0)}  ",
            f"**Speedup:** {summary.get('speedup', 1.0)}x  ",
            f"**Cache entries:** {cache_stats.get('total_entries', 0)}  ",
            f"**Cache hit rate:** {cache_stats.get('hit_rate', 0):.0%}\n",
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
        description="Nexus P2 - Self-improving vulnerability detection",
    )
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument("--api-key", default=None, help="LLM API Key (or NEXUS_API_KEY)")
    parser.add_argument("--base-url", default="https://api.openai.com/v1")
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--output", default="report_p2.md")
    parser.add_argument("--min-confidence", type=float, default=0.5)
    parser.add_argument("--vuln-types", default="SSRF,SQLI,IDOR")
    parser.add_argument("--max-workers", type=int, default=3)
    parser.add_argument("--incremental", action="store_true", help="Only scan changed files")
    parser.add_argument("--dashboard", action="store_true", help="Start web dashboard")
    parser.add_argument("--resume", default=None, help="Resume from session ID")
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

    pipeline = NexusPipelineV3(
        api_key=api_key,
        base_url=args.base_url,
        model=args.model,
        min_confidence=args.min_confidence,
        max_workers=args.max_workers,
        vuln_types=vuln_types,
        incremental=args.incremental,
    )

    if args.dashboard:
        from dashboard.server import create_app, set_store, set_cache
        set_store(pipeline.workspace_store)
        set_cache(pipeline.frugal_engine)
        app = create_app()
        print(f"[Dashboard] 启动 http://localhost:5000")
        app.run(host="0.0.0.0", port=5000, debug=False)
        return

    result = pipeline.run(args.target, args.output)
    print(f"\n✅ 分析完成，报告已保存至 {args.output}")


if __name__ == "__main__":
    main()
