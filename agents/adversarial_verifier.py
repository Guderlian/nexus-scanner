"""AdversarialVerifierAgent - probabilistic confidence calibration."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard

CALIBRATOR_SYSTEM_PROMPT = """你是一名安全漏洞审计员，负责校准漏洞假设的置信度。

## 你的工作原则

你只根据代码中**可见的、明确的**证据做判断。
你不能假设"可能存在"的防护措施——如果代码中没有，就视为不存在。
你不是否决者，你是校准者。

## 判断框架

对于给定的漏洞假设，在代码片段中寻找以下**明确可见**的防护证据：

**SSRF防护证据（代码中必须可见）：**
- urlparse() + 白名单域名列表的显式比对
- 正则表达式过滤URL的协议或主机
- 硬编码URL（非变量）

**SQLi防护证据（代码中必须可见）：**
- 参数化查询占位符（?, %s, :param）
- ORM的.filter()/.get()（非.raw()）

**XSS/SSTI防护证据（代码中必须可见）：**
- html.escape()、bleach.clean()的显式调用
- 使用render_template()而非render_template_string()

**通用降低置信度的情形：**
- 代码片段不完整，无法判断调用链
- 变量在片段外定义，来源不明

## 输出格式（严格JSON）

无防护时：
{"survived": true, "confidence_adjustment": 0.05, "evidence_found": "代码中未见任何URL校验", "protective_code": null}

有明确防护时：
{"survived": false, "confidence_adjustment": -0.5, "evidence_found": "第3行存在urlparse()+ALLOWED_HOSTS白名单比对", "protective_code": "if urlparse(url).netloc not in ALLOWED_HOSTS: return 403"}

## 关键规则

- survived=false 只在代码中**明确可见**防护措施时使用
- 无法判断 = survived=true，confidence_adjustment在-0.1到+0.1之间
- 有明确防护 = survived=false，confidence_adjustment为-0.3到-0.6
- 有部分防护（如只检查前缀）= survived=true，confidence_adjustment为-0.1到-0.2
- **禁止使用"可能"、"也许"、"推测"作为拒绝理由**"""


class AdversarialVerifierAgent:
    """Calibrates hypothesis confidence based on visible evidence."""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", timeout: int = 30, retry_count: int = 2):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self.retry_count = retry_count

    def verify(self, hypothesis: HypothesisCard, pattern_result: dict,
               fact_card: FactCard) -> HypothesisCard:
        """Calibrate hypothesis confidence. Returns updated hypothesis."""
        user_msg = self._build_prompt(hypothesis, pattern_result, fact_card)
        raw = self._call_llm(user_msg)
        if raw is None:
            return hypothesis  # LLM failure: keep as-is

        return self._apply_calibration(raw, hypothesis)

    def _apply_calibration(self, raw: str, hypothesis: HypothesisCard) -> HypothesisCard:
        """Apply LLM calibration response to hypothesis."""
        # Extract JSON from response
        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        match = re.search(r'\{.*\}', text, re.DOTALL)
        if not match:
            # Parse failure: treat as survived with small penalty
            hypothesis.confidence = max(0.1, hypothesis.confidence - 0.05)
            hypothesis.reasoning += "\n[Verifier] 响应解析失败，保守处理：假设存活"
            return hypothesis

        try:
            result = json.loads(match.group())
        except json.JSONDecodeError:
            hypothesis.confidence = max(0.1, hypothesis.confidence - 0.05)
            hypothesis.reasoning += "\n[Verifier] JSON解析失败，保守处理：假设存活"
            return hypothesis

        survived = result.get("survived", True)
        adjustment = float(result.get("confidence_adjustment", 0.0))
        evidence = result.get("evidence_found", "")
        protective_code = result.get("protective_code", None)

        if not survived and protective_code:
            # Explicit protective code found: allow rejection
            hypothesis.status = "rejected"
            hypothesis.confidence = 0.0
            hypothesis.reasoning += f"\n[Verifier拒绝] 发现防护代码: {protective_code}"
        elif not survived and not protective_code:
            # Claims rejection but no evidence: downgrade to survived
            hypothesis.confidence = max(0.1, hypothesis.confidence - 0.1)
            hypothesis.reasoning += f"\n[Verifier降级] 无明确防护证据，保守处理为存活: {evidence}"
        else:
            # survived=True: apply confidence adjustment
            hypothesis.confidence = max(0.0, min(1.0, hypothesis.confidence + adjustment))
            hypothesis.reasoning += f"\n[Verifier确认] {evidence}"

        return hypothesis

    def _build_prompt(self, h: HypothesisCard, pattern_result: dict, fact: FactCard) -> str:
        parts = [
            "请对以下漏洞假设进行置信度校准：",
            f"",
            f"假设：漏洞类型={h.attack_path}，当前置信度={h.confidence:.2f}",
            f"推理：{h.reasoning}",
            f"",
            f"代码片段：",
            f"```{fact.language}",
            fact.code_snippet,
            f"```",
            f"",
            f"模式匹配结果：{json.dumps(pattern_result, ensure_ascii=False)}",
            f"启发式标记：{fact.heuristics}",
            f"",
            f"请在代码中寻找明确可见的防护证据。如果找不到，应输出survived=true。",
        ]
        return "\n".join(parts)

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
                        {"role": "system", "content": CALIBRATOR_SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    temperature=0,
                    max_tokens=1000,
                )
                return response.choices[0].message.content
            except Exception:
                if attempt < self.retry_count:
                    time.sleep(1 * (attempt + 1))
                    continue
                return None
