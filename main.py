#!/usr/bin/env python3
"""Nexus P0 - AI-driven SSRF vulnerability auto-detection system."""
from __future__ import annotations

import argparse
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from perception.encoder import PerceptionEncoder
from agents.semantic_analyst import SemanticAnalystAgent
from agents.tool_executor import ToolExecutorAgent
from core.evidence_chain import EvidenceChain


def parse_args():
    parser = argparse.ArgumentParser(
        description="Nexus P0 - AI-driven SSRF vulnerability auto-detection system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --target ./code --api-key sk-xxx --model gpt-4o-mini
  python main.py --target ./app --base-url https://api.deepseek.com/v1 --model deepseek-chat
        """,
    )
    parser.add_argument("--target", required=True, help="要扫描的目标目录或文件路径")
    parser.add_argument("--api-key", default=None, help="LLM API Key (或设置 NEXUS_API_KEY 环境变量)")
    parser.add_argument("--base-url", default="https://api.openai.com/v1", help="LLM API base URL")
    parser.add_argument("--model", default="gpt-4o-mini", help="LLM 模型名称")
    parser.add_argument("--output", default="report.md", help="输出报告文件路径 (默认 report.md)")
    parser.add_argument("--min-confidence", type=float, default=0.5, help="最低置信度阈值 (默认 0.5)")
    return parser.parse_args()


def main():
    args = parse_args()

    api_key = args.api_key or os.environ.get("NEXUS_API_KEY", "")
    if not api_key:
        print("❌ 错误：请通过 --api-key 或 NEXUS_API_KEY 环境变量提供 API Key")
        sys.exit(1)

    target = args.target
    if not os.path.exists(target):
        print(f"❌ 错误：目标路径不存在: {target}")
        sys.exit(1)

    # === Phase 1: Perception ===
    print("[感知层] 扫描中...", end="", flush=True)
    encoder = PerceptionEncoder()
    if os.path.isfile(target):
        facts = encoder.encode_file(target)
    else:
        facts = encoder.encode_directory(target)
    print(f"发现 {len(facts)} 个片段")

    if not facts:
        print("[结果] 未发现可疑代码片段，扫描结束。")
        return

    # === Phase 2: Semantic Analysis ===
    analyst = SemanticAnalystAgent(
        api_key=api_key,
        base_url=args.base_url,
        model=args.model,
    )
    hypotheses = []
    for i, fact in enumerate(facts):
        print(f"\r[分析层] Semantic Analyst 分析 {i+1}/{len(facts)}...", end="", flush=True)
        card = analyst.analyze(fact)
        if card is not None:
            hypotheses.append(card)
    print(f"\n[分析层] 完成，发现 {len(hypotheses)} 个假设")

    if not hypotheses:
        print("[结果] 未发现高置信度 SSRF 假设，扫描结束。")
        return

    # === Phase 3: Verification ===
    executor = ToolExecutorAgent(min_confidence=args.min_confidence)
    chains = []
    for i, hyp in enumerate(hypotheses):
        print(f"\r[验证层] Tool Executor 验证假设 {i+1}/{len(hypotheses)}...", end="", flush=True)
        chain = executor.verify(hyp)
        chains.append(chain)
    print()

    # === Phase 4: Report ===
    confirmed = [c for c in chains if c.verdict == "confirmed"]
    unverified = [c for c in chains if c.verdict == "unverified"]

    report_parts = ["# Nexus P0 - SSRF 漏洞扫描报告\n"]
    report_parts.append(f"扫描目标: `{target}`\n")
    report_parts.append(f"发现片段: {len(facts)} | 假设: {len(hypotheses)} | 确认: {len(confirmed)} | 待验证: {len(unverified)}\n")
    report_parts.append("---\n")

    for chain in chains:
        report_parts.append(chain.to_report())
        report_parts.append("\n---\n")

    report_text = "\n".join(report_parts)

    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"[报告] 发现 {len(chains)} 个漏洞，保存至 {output_path}")

    # Exit code: 0 if no confirmed, 1 if confirmed found
    if confirmed:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
