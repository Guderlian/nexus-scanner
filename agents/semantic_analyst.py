"""SemanticAnalystAgent - LLM-based deep SSRF vulnerability reasoning."""
from __future__ import annotations

import json
import os
import time
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard


SYSTEM_PROMPT = """你是专注 SSRF 漏洞的顶级安全研究员。
分析框架：
1. 数据源：URL 是否外部可控？
2. 防护：是否有有效白名单校验？（仅 startswith 不算有效）
3. 攻击路径：内网探测/文件读取/云 metadata 等
4. 置信度：0.0-1.0

输出严格 JSON（不含任何额外文字）：
{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "attack_path": "...",
  "preconditions": ["..."],
  "reasoning": "...",
  "false_positive_risk": "low/medium/high"
}"""


class SemanticAnalystAgent:
    """Uses an LLM to perform deep semantic analysis on FactCards."""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", temperature: float = 0,
                 max_tokens: int = 1500, timeout: int = 30, retry_count: int = 2,
                 min_confidence: float = 0.4):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retry_count = retry_count
        self.min_confidence = min_confidence

    def analyze(self, fact: FactCard) -> Optional[HypothesisCard]:
        """Analyze a single FactCard. Returns HypothesisCard or None if not vulnerable."""
        user_msg = self._build_prompt(fact)
        raw = self._call_llm(user_msg)
        if raw is None:
            return None

        card = HypothesisCard.from_llm_json(
            raw=raw,
            source_fact_id=f"{fact.file_path}:{fact.line_start}",
            file_path=fact.file_path,
            line_start=fact.line_start,
            line_end=fact.line_end,
            code_snippet=fact.code_snippet,
        )

        if card is None:
            return None
        if not card.is_vulnerable or card.confidence < self.min_confidence:
            return None

        return card

    def analyze_batch(self, facts: list[FactCard]) -> list[HypothesisCard]:
        """Analyze a batch of FactCards, returning only those deemed vulnerable."""
        results = []
        for fact in facts:
            card = self.analyze(fact)
            if card is not None:
                results.append(card)
        return results

    def _infer_vuln_type(self, fact: FactCard) -> str:
        """Infer vulnerability type from heuristics and sink."""
        heur = " ".join(fact.heuristics).lower()
        sink = (fact.sink or "").lower()
        if "xss" in heur or "xss" in sink:
            return "XSS"
        if "ssti" in heur or "ssti" in sink:
            return "SSTI"
        if "xxe" in heur or "xxe" in sink or "fromstring" in sink:
            return "XXE"
        if "sql" in heur or "execute" in sink or "sql" in sink:
            return "SQL注入"
        if "idor" in heur or "路由参数" in heur or "id参数" in heur:
            return "IDOR"
        if "path" in heur or "traversal" in heur or "路径" in heur:
            return "路径遍历"
        if "deserialization" in heur or "pickle" in sink or "yaml" in sink:
            return "不安全反序列化"
        if "ssrf" in heur or "requests.get" in sink or "urlopen" in sink:
            return "SSRF"
        return "安全"

    def _build_prompt(self, fact: FactCard) -> str:
        """Build the user message from a FactCard."""
        vuln_type = self._infer_vuln_type(fact)
        parts = [
            f"分析以下代码片段是否存在 {vuln_type} 漏洞：",
            f"",
            f"文件：{fact.file_path}",
            f"行号：{fact.line_start}-{fact.line_end}",
            f"语言：{fact.language}",
            f"代码：",
            f"```{fact.language}",
            fact.code_snippet,
            f"```",
        ]
        if fact.data_flow:
            parts.append(f"数据流：{', '.join(fact.data_flow)}")
        if fact.heuristics:
            parts.append(f"启发式标记：{', '.join(fact.heuristics)}")
        if fact.sink:
            parts.append(f"危险函数：{fact.sink}")
        parts.append(f"当前置信度：{fact.confidence:.2f}")
        return "\n".join(parts)

    def _call_llm(self, user_msg: str) -> Optional[str]:
        """Call the OpenAI-compatible API with retries."""
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
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                content = response.choices[0].message.content
                return content
            except Exception:
                if attempt < self.retry_count:
                    time.sleep(1 * (attempt + 1))
                    continue
                return None
