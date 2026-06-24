#!/usr/bin/env python3
"""Nexus P3 - Production vulnerability detection with semantic cache, 8 vuln types, CI/CD."""
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
from cache.embedding_cache import EmbeddingCache
from policy.engine import PolicyEngine
from healing.self_healer import SelfHealer
from storage.workspace_store import WorkspaceStore
from reporting.pdf_reporter import PDFReporter
from vcs.git_differ import GitDiffer


ALL_VULN_TYPES = ["SSRF", "SQLI", "IDOR", "XSS", "SSTI", "XXE", "PATH_TRAVERSAL", "DESERIALIZATION"]


class NexusPipelineV4:
    """P3 production pipeline."""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", min_confidence: float = 0.5,
                 max_workers: int = 3, vuln_types: list[str] = None,
                 incremental: bool = False, diff_base: str = "HEAD~1",
                 use_embedding: bool = False, ci_mode: str = "none"):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.min_confidence = min_confidence
        self.max_workers = max_workers
        self.vuln_types = vuln_types or ALL_VULN_TYPES
        self.incremental = incremental
        self.diff_base = diff_base
        self.use_embedding = use_embedding
        self.ci_mode = ci_mode

        self.file_hasher = FileHasher()
        self.frugal_engine = FrugalEngine()
        self.frugal_engine.load()
        self.embedding_cache = EmbeddingCache() if use_embedding else None
        self.policy_engine = PolicyEngine()
        self.self_healer = SelfHealer(self.policy_engine.config)
        self.workspace_store = WorkspaceStore()
        self.git_differ = GitDiffer(".")

        self.pattern_matcher = PatternMatcherAgent()
        self.semantic_analyst = SemanticAnalystAgent(api_key=api_key, base_url=base_url, model=model, min_confidence=min_confidence)
        self.adversarial_verifier = AdversarialVerifierAgent(api_key=api_key, base_url=base_url, model=model)
        self.tool_executor = ToolExecutorAgent(min_confidence=min_confidence)
        self.planner = PlannerAgent(api_key=api_key, base_url=base_url, model=model)

    def run(self, target_path: str, output_prefix: str = "report") -> dict:
        workspace = GlobalWorkspace()
        total_start = time.time()
        llm_calls = 0
        cache_hits = 0
        cache_misses = 0

        print(f"[Nexus P3] 目标：{target_path}")

        # VCS
        is_git = self.git_differ.is_git_repo()
        diff_files = None
        if is_git and self.incremental:
            diff = self.git_differ.get_diff(base=self.diff_base)
            diff = self.git_differ.filter_by_extension(diff, [".py", ".java", ".js"])
            diff_files = diff.changed_files
            print(f"[VCS]      Git Diff 检测变更...{len(diff_files)}个文件有变更（基于 {self.diff_base}..HEAD）")
        elif self.incremental:
            diff_files = self.file_hasher.get_changed_files(target_path)
            print(f"[哈希]     检测文件变更...{len(diff_files)}个文件需重新分析")

        # Cache
        if self.use_embedding:
            print(f"[缓存]     加载 Embedding 缓存（模型：all-MiniLM-L6-v2）")
        else:
            cache_stats = self.frugal_engine.stats()
            print(f"[缓存]     加载经验缓存（{cache_stats['total_entries']}条记录）")

        # Perception
        encoder = PerceptionEncoder()
        if diff_files is not None:
            facts = []
            for f in diff_files:
                if os.path.isfile(f):
                    facts.extend(encoder.encode_file(f))
        elif os.path.isfile(target_path):
            facts = encoder.encode_file(target_path)
        else:
            facts = encoder.encode_directory(target_path)
        workspace.add_facts(facts)

        # Update hashes
        if self.incremental and diff_files:
            for f in diff_files:
                self.file_hasher.update(f)
            self.file_hasher.save()

        print(f"[感知层]   扫描{len(diff_files or [])}个文件，覆盖{len(self.vuln_types)}类漏洞...发现{len(facts)}个片段")

        if not facts:
            print("[结果] 未发现可疑代码片段。")
            return {"facts": 0, "vulnerabilities": 0}

        within_budget, reason = self.policy_engine.check_budget(llm_calls, len(facts))
        print(f"[策略层]   预算：{self.policy_engine.config.max_llm_calls - llm_calls}次LLM调用")

        # Cache lookup
        uncached_facts = []
        for fact in facts:
            hit = False
            for vt in self.vuln_types:
                if self.use_embedding and self.embedding_cache:
                    pass  # Embedding lookup would go here
                else:
                    cache_entry = self.frugal_engine.lookup(fact, vt)
                    if cache_entry:
                        cache_hits += 1
                        hit = True
                        break
            if not hit:
                cache_misses += 1
                uncached_facts.append(fact)

        print(f"[缓存]     语义查询：{cache_hits}命中（跳过LLM），{cache_misses}需分析")

        # Planner
        if uncached_facts:
            plan = self.planner.plan(uncached_facts, self.vuln_types)
            llm_calls += 1
            high = [p for p in plan if p.get("priority", 0) >= 4]
            print(f"[规划层]   Planner 分配优先级，{len(high)}个高优先级任务")

        # DAG
        designer = GraphDesigner(workspace)
        nodes = designer.design(uncached_facts or facts[:1], self.vuln_types)
        print(f"[DAG]      并行执行{len(nodes)}个节点（{self.max_workers}线程）")

        executor = DAGExecutor(workspace, max_workers=self.max_workers)
        self._register_agents(executor, workspace)
        summary = executor.execute(nodes)

        for nd in summary.get("nodes", []):
            icon = "✅" if nd["status"] == "done" else "❌"
            dur = f"{nd['duration_ms']:.0f}ms" if nd["duration_ms"] else "N/A"
            print(f"           ├─ {nd['node_id']}: {icon} {dur}")

        # Store cache
        stored = 0
        for ev in workspace.state.evidences:
            if ev.verdict == "confirmed":
                for hyp in workspace.state.hypotheses:
                    if hyp.file_path == ev.file_path and hyp.line_start == ev.line_start:
                        for fact in workspace.state.fact_cards:
                            if fact.file_path == ev.file_path and fact.line_start == ev.line_start:
                                for vt in self.vuln_types:
                                    self.frugal_engine.store(fact, vt, hyp, ev)
                                    stored += 1
                                break
                        break
        if stored:
            print(f"[缓存]     存储{stored}条新经验")

        # Save session
        session_id = self.workspace_store.save_session(workspace, target_path)
        self.workspace_store.complete_session(session_id)

        # Report
        evidences = workspace.state.evidences
        total_ms = (time.time() - total_start) * 1000
        speedup = summary.get("speedup", 1.0)
        saved_pct = (cache_hits / (cache_hits + cache_misses) * 100) if (cache_hits + cache_misses) > 0 else 0

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for ev in evidences:
            if ev.final_confidence >= 0.8: counts["critical"] += 1
            elif ev.final_confidence >= 0.6: counts["high"] += 1
            elif ev.final_confidence >= 0.4: counts["medium"] += 1
            else: counts["low"] += 1

        print(f"[报告]     发现{len(evidences)}个漏洞（Critical:{counts['critical']} High:{counts['high']} Medium:{counts['medium']}）")

        # Markdown
        md_path = f"{output_prefix}.md"
        md_report = self._generate_md(target_path, facts, evidences, summary)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_report)

        # PDF
        pdf_path = f"{output_prefix}.pdf"
        try:
            reporter = PDFReporter(pdf_path)
            reporter.generate(evidences, {"target": target_path, "scan_time": time.strftime("%Y-%m-%d %H:%M")})
            print(f"[输出]     Markdown: {md_path} | PDF: {pdf_path}")
        except Exception as e:
            print(f"[输出]     Markdown: {md_path} | PDF生成失败: {e}")

        # CI/CD
        if self.ci_mode == "github":
            from cicd.github_action import GitHubActionReporter
            gh = GitHubActionReporter()
            gh.output_annotations(evidences)
            gh.set_output("vulnerability_count", str(len(evidences)))
            gh.set_output("exit_code", str(gh.exit_code(evidences)))
            print("[CI]       GitHub Annotations 已输出")
        elif self.ci_mode == "gitlab":
            from cicd.gitlab_ci import GitLabCIReporter
            gl = GitLabCIReporter()
            with open(f"{output_prefix}-sast.json", "w") as f:
                f.write(gl.generate_sast_report(evidences))
            print("[CI]       GitLab SAST 报告已输出")

        print(f"[性能]     总耗时{total_ms/1000:.1f}s | 缓存节省{saved_pct:.0f}% LLM调用 | 加速比{speedup}x")

        return {
            "facts": len(facts), "vulnerabilities": len(evidences),
            "confirmed": counts["critical"] + counts["high"],
            "cache_hits": cache_hits, "cache_misses": cache_misses,
            "total_ms": total_ms, "speedup": speedup, "session_id": session_id,
        }

    def _register_agents(self, executor, workspace):
        healer = self.self_healer
        def pattern_handler(node, ws):
            fact = FactCard.from_dict(node.input_data["fact"])
            node.output_data = self.pattern_matcher.match(fact, node.input_data["vuln_type"])
        def semantic_handler(node, ws):
            fact = FactCard.from_dict(node.input_data["fact"])
            try:
                card = self.semantic_analyst.analyze(fact)
                if card:
                    node.output_data = card.to_dict()
                    ws.add_hypothesis(card)
                else:
                    node.output_data = {"is_vulnerable": False}
            except Exception:
                node.output_data = {"is_vulnerable": False}
        def verifier_handler(node, ws):
            fact = FactCard.from_dict(node.input_data["fact"])
            hyp = next((h for h in ws.state.hypotheses if h.file_path == fact.file_path and h.line_start == fact.line_start), None)
            if not hyp:
                node.output_data = {"status": "no_hypothesis"}
                return
            pattern_result = self.pattern_matcher.match(fact, node.input_data["vuln_type"])
            try:
                updated = self.adversarial_verifier.verify(hyp, pattern_result, fact)
                node.output_data = updated.to_dict()
            except Exception as e:
                healer.handle_dag_node_failure(node, e)
                node.output_data = hyp.to_dict()
        def executor_handler(node, ws):
            fact = FactCard.from_dict(node.input_data["fact"])
            hyp = next((h for h in ws.state.hypotheses if h.file_path == fact.file_path and h.line_start == fact.line_start), None)
            if not hyp or hyp.status == "rejected":
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

    def _generate_md(self, target, facts, evidences, summary):
        parts = [f"# Nexus P3 Report\n\n**Target:** `{target}` | **Fragments:** {len(facts)} | **Findings:** {len(evidences)}\n\n---\n"]
        for ev in evidences:
            parts.append(ev.to_report())
            parts.append("\n---\n")
        return "\n".join(parts)


def parse_args():
    p = argparse.ArgumentParser(description="Nexus P3 - Production vulnerability detection")
    p.add_argument("--target", required=True)
    p.add_argument("--api-key", default=None)
    p.add_argument("--base-url", default="https://api.openai.com/v1")
    p.add_argument("--model", default="gpt-4o-mini")
    p.add_argument("--output", default="report")
    p.add_argument("--min-confidence", type=float, default=0.5)
    p.add_argument("--vuln-types", default="ALL")
    p.add_argument("--max-workers", type=int, default=3)
    p.add_argument("--incremental", action="store_true")
    p.add_argument("--diff", default="HEAD~1")
    p.add_argument("--dashboard", action="store_true")
    p.add_argument("--ci", default="none", choices=["none", "github", "gitlab"])
    p.add_argument("--use-embedding", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    api_key = args.api_key or os.environ.get("NEXUS_API_KEY", "")
    if not api_key:
        print("❌ 请提供 API Key")
        sys.exit(1)
    if not os.path.exists(args.target):
        print(f"❌ 目标不存在: {args.target}")
        sys.exit(1)

    vuln_types = ALL_VULN_TYPES if args.vuln_types == "ALL" else [v.strip().upper() for v in args.vuln_types.split(",")]

    pipeline = NexusPipelineV4(
        api_key=api_key, base_url=args.base_url, model=args.model,
        min_confidence=args.min_confidence, max_workers=args.max_workers,
        vuln_types=vuln_types, incremental=args.incremental,
        diff_base=args.diff, use_embedding=args.use_embedding, ci_mode=args.ci,
    )

    if args.dashboard:
        from dashboard.server import create_app, set_store, set_cache
        set_store(pipeline.workspace_store)
        set_cache(pipeline.frugal_engine)
        app = create_app()
        print("[Dashboard] http://localhost:5000")
        app.run(host="0.0.0.0", port=5000, debug=False)
        return

    pipeline.run(args.target, args.output)
    print(f"\n✅ 分析完成")


if __name__ == "__main__":
    main()
