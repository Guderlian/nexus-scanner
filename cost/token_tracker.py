"""Token cost tracker for LLM API calls."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class TokenUsage:
    """A single API call's token usage."""
    agent_name: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# Pricing per million tokens (USD)
MODEL_PRICING = {
    "mimo-v2.5-pro-max": {"input": 0.14, "output": 0.28},
    "mimo-v2.5-pro": {"input": 0.14, "output": 0.28},
    "deepseek-chat": {"input": 0.14, "output": 0.28},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "default": {"input": 0.50, "output": 1.50},
}


class TokenTracker:
    """Tracks token consumption and API costs."""

    def __init__(self, model: str = "mimo-v2.5-pro-max"):
        self.model = model
        self._usage: list[TokenUsage] = []

    def record(self, agent_name: str, prompt_tokens: int, completion_tokens: int) -> TokenUsage:
        """Record a token usage event."""
        pricing = MODEL_PRICING.get(self.model, MODEL_PRICING["default"])
        cost = (prompt_tokens * pricing["input"] + completion_tokens * pricing["output"]) / 1_000_000
        usage = TokenUsage(
            agent_name=agent_name,
            model=self.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            cost_usd=round(cost, 6),
        )
        self._usage.append(usage)
        return usage

    def total_cost(self) -> float:
        """Total cost in USD."""
        return sum(u.cost_usd for u in self._usage)

    def total_tokens(self) -> int:
        """Total tokens consumed."""
        return sum(u.total_tokens for u in self._usage)

    def by_agent(self) -> dict[str, dict]:
        """Per-agent token summary."""
        result = {}
        for u in self._usage:
            if u.agent_name not in result:
                result[u.agent_name] = {"calls": 0, "tokens": 0, "cost_usd": 0.0}
            result[u.agent_name]["calls"] += 1
            result[u.agent_name]["tokens"] += u.total_tokens
            result[u.agent_name]["cost_usd"] += u.cost_usd
        return result

    def summary(self) -> str:
        """Formatted cost report."""
        pricing = MODEL_PRICING.get(self.model, MODEL_PRICING["default"])
        lines = [
            f"=== Token Cost Report ===",
            f"Model: {self.model} (${pricing['input']}/${pricing['output']} per 1M tokens)",
            f"Total calls: {len(self._usage)}",
            f"Total tokens: {self.total_tokens()}",
            f"Total cost: ${self.total_cost():.4f}",
            "",
            f"{'Agent':<25} {'Calls':>6} {'Tokens':>8} {'Cost':>10}",
            "-" * 55,
        ]
        for name, data in self.by_agent().items():
            lines.append(f"{name:<25} {data['calls']:>6} {data['tokens']:>8} ${data['cost_usd']:>8.4f}")
        return "\n".join(lines)

    def save(self, path: str) -> None:
        """Persist usage to JSON."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        data = [
            {
                "agent_name": u.agent_name,
                "model": u.model,
                "prompt_tokens": u.prompt_tokens,
                "completion_tokens": u.completion_tokens,
                "total_tokens": u.total_tokens,
                "cost_usd": u.cost_usd,
                "timestamp": u.timestamp,
            }
            for u in self._usage
        ]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, path: str) -> None:
        """Load usage from JSON."""
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            for d in data:
                self._usage.append(TokenUsage(**d))
        except (json.JSONDecodeError, IOError):
            pass
