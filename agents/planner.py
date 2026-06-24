"""PlannerAgent - task decomposition and prioritization."""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard

PLANNER_SYSTEM_PROMPT = """你是安全分析任务的调度员。

给定一批代码片段的 Fact Cards，你需要决定：
1. 哪些片段最值得深入分析（优先级 1-5，5 最高）
2. 针对每个片段应该重点检测哪种漏洞类型
3. 理由是什么

输出严格 JSON 数组（不含任何额外文字）：
[
  {"fact_id": "xxx", "vuln_type": "SSRF", "priority": 5, "reason": "..."},
  ...
]

优先级规则：
- confidence > 0.7 且 heuristics >= 3 → 优先级 5
- confidence > 0.5 → 优先级 3-4
- confidence < 0.3 → 优先级 1（可跳过）

可选漏洞类型：SSRF, SQLI, IDOR"""


class PlannerAgent:
    """Decomposes analysis tasks and assigns priorities."""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", timeout: int = 30, retry_count: int = 2):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self.retry_count = retry_count

    def plan(self, fact_cards: list[FactCard], vuln_types: list[str]) -> list[dict]:
        """Generate an analysis plan for the given fact cards."""
        if not fact_cards:
            return []

        user_msg = self._build_prompt(fact_cards, vuln_types)
        raw = self._call_llm(user_msg)
        if raw is None:
            return self._default_plan(fact_cards, vuln_types)

        plan = self._parse_response(raw)
        if plan is None:
            return self._default_plan(fact_cards, vuln_types)
        return plan

    def _build_prompt(self, facts: list[FactCard], vuln_types: list[str]) -> str:
        parts = [
            f"分析以下 {len(facts)} 个代码片段，为每个生成分析计划。",
            f"目标漏洞类型：{', '.join(vuln_types)}",
            "",
        ]
        for i, f in enumerate(facts):
            parts.append(f"--- FactCard {i} ---")
            parts.append(f"ID: {f.file_path}:{f.line_start}")
            parts.append(f"代码: {f.code_snippet[:200]}")
            parts.append(f"置信度: {f.confidence:.2f}")
            parts.append(f"启发式: {f.heuristics}")
            parts.append(f"数据流: {f.data_flow}")
            parts.append("")
        return "\n".join(parts)

    def _default_plan(self, facts: list[FactCard], vuln_types: list[str]) -> list[dict]:
        """Fallback plan when LLM is unavailable: assign based on confidence."""
        plan = []
        for i, f in enumerate(facts):
            fid = f"{f.file_path}:{f.line_start}"
            priority = 1
            if f.confidence > 0.7 and len(f.heuristics) >= 3:
                priority = 5
            elif f.confidence > 0.5:
                priority = 3
            elif f.confidence > 0.3:
                priority = 2

            for vt in vuln_types:
                plan.append({
                    "fact_id": fid,
                    "vuln_type": vt,
                    "priority": priority,
                    "reason": f"Auto-assigned (confidence={f.confidence:.2f})",
                })
        return plan

    def _parse_response(self, raw: str) -> Optional[list[dict]]:
        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            return None
        except json.JSONDecodeError:
            return None

    def _call_llm(self, user_msg: str) -> Optional[str]:
        try:
            from openai import OpenAI
        except ImportError:
            return None

        client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=self.timeout)
        for attempt in range(self.retry_count + 1):
            try:
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    temperature=0,
                    max_tokens=2000,
                )
                return response.choices[0].message.content
            except Exception:
                if attempt < self.retry_count:
                    time.sleep(1 * (attempt + 1))
                    continue
                return None
