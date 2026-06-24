"""SemgrepRunner - automated SSRF pattern verification using Semgrep."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.evidence_chain import EvidenceChain, EvidenceItem


# Built-in SSRF Semgrep rules
SSRF_RULES = [
    {
        "id": "ssrf-requests-variable-url",
        "patterns": [
            {"pattern": "requests.$METHOD($URL)"},
            {"pattern-not": "requests.$METHOD(\"http://...\")"},
            {"pattern-not": "requests.$METHOD('http://...')"},
        ],
        "message": "requests library called with variable URL - potential SSRF",
        "languages": ["python"],
        "severity": "WARNING",
    },
    {
        "id": "ssrf-urllib-variable-url",
        "patterns": [
            {"pattern": "urllib.request.urlopen($URL)"},
            {"pattern-not": "urllib.request.urlopen(\"http://...\")"},
            {"pattern-not": "urllib.request.urlopen('http://...')"},
        ],
        "message": "urllib.request.urlopen called with variable URL - potential SSRF",
        "languages": ["python"],
        "severity": "WARNING",
    },
    {
        "id": "ssrf-httpx-variable-url",
        "patterns": [
            {"pattern": "httpx.$METHOD($URL)"},
            {"pattern-not": "httpx.$METHOD(\"http://...\")"},
            {"pattern-not": "httpx.$METHOD('http://...')"},
        ],
        "message": "httpx library called with variable URL - potential SSRF",
        "languages": ["python"],
        "severity": "WARNING",
    },
]


class SemgrepRunner:
    """Runs Semgrep SSRF rules against target files and produces EvidenceChains."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def run(self, target_path: str, hypothesis_id: str = "",
            file_path: str = "", line_start: int = 0, line_end: int = 0,
            code_snippet: str = "", attack_path: str = "",
            preconditions: list[str] | None = None,
            reasoning: str = "") -> Optional[dict]:
        """
        Run Semgrep against the target. Returns dict with status or an EvidenceChain dict.
        """
        rule_file = None
        try:
            rule_file = self._write_rules()
            result = subprocess.run(
                ["semgrep", "--config", rule_file, "--json", target_path],
                capture_output=True, text=True, timeout=self.timeout,
            )
        except FileNotFoundError:
            return {"status": "tool_unavailable"}
        except subprocess.TimeoutExpired:
            return {"status": "timeout"}
        except Exception:
            return {"status": "error"}
        finally:
            if rule_file and os.path.exists(rule_file):
                try:
                    os.unlink(rule_file)
                except OSError:
                    pass

        if result.returncode != 0:
            return {"status": "error", "stderr": result.stderr[:500]}

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"status": "parse_error"}

        findings = data.get("results", [])
        evidence_items = []
        for f in findings:
            evidence_items.append(EvidenceItem(
                tool="semgrep",
                result=f.get("extra", {}).get("message", f.get("check_id", "unknown")),
                confidence_delta=0.2 if findings else 0.0,
            ))

        chain = EvidenceChain(
            hypothesis_id=hypothesis_id,
            verdict="confirmed" if findings else "unverified",
            final_confidence=0.7 if findings else 0.3,
            evidence=evidence_items,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
            attack_path=attack_path,
            preconditions=preconditions or [],
            reasoning=reasoning,
        )
        return chain.to_dict()

    def _write_rules(self) -> str:
        """Write SSRF rules to a temporary YAML file."""
        import yaml
        rule_content = {"rules": SSRF_RULES}
        fd, path = tempfile.mkstemp(suffix=".yaml", prefix="nexus_ssrf_")
        with os.fdopen(fd, "w") as f:
            yaml.dump(rule_content, f, default_flow_style=False)
        return path
