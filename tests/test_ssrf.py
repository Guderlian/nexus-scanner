"""Benchmark test suite for Nexus P0 SSRF detection system."""
from __future__ import annotations

import os
import sys
import tempfile
from unittest import mock

import pytest

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from perception.encoder import PerceptionEncoder
from agents.semantic_analyst import SemanticAnalystAgent
from agents.tool_executor import ToolExecutorAgent
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain

# =====================================================================
# Vulnerable Samples
# =====================================================================

VULN_1_REQUESTS_DIRECT = """\
import requests

def fetch(url):
    response = requests.get(url)
    return response.text
"""

VULN_2_FLASK_REQUEST_ARGS = """\
from flask import request, Flask
import requests

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text
"""

VULN_3_STRING_CONCAT = """\
import requests

def fetch_resource(base_url, resource_id):
    target = base_url + '/api/' + resource_id
    return requests.get(target)
"""

VULN_4_URLLIB_URLOPEN = """\
import urllib.request

def download(file_url):
    data = urllib.request.urlopen(file_url)
    return data.read()
"""

VULN_5_HTTPX_ASYNC = """\
import httpx
import asyncio

async def fetch_async(target_url):
    async with httpx.AsyncClient() as client:
        resp = await client.get(target_url)
        return resp.text
"""

# =====================================================================
# Safe Samples
# =====================================================================

SAFE_1_HARDCODED = """\
import requests

def get_status():
    resp = requests.get("https://api.example.com/health")
    return resp.status_code
"""

SAFE_2_WHITELIST = """\
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = ["api.example.com", "cdn.example.com"]

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return requests.get(url)
"""

# =====================================================================
# LLM Mock Responses
# =====================================================================

LLM_VULN_RESPONSE = """\
{
    "is_vulnerable": true,
    "confidence": 0.85,
    "attack_path": "Attacker controls URL parameter, can target internal services",
    "preconditions": ["URL is user-controlled", "No whitelist validation"],
    "reasoning": "The URL comes from external input and is passed directly to requests.get without validation",
    "false_positive_risk": "low"
}"""

LLM_SAFE_RESPONSE = """\
{
    "is_vulnerable": false,
    "confidence": 0.15,
    "attack_path": "",
    "preconditions": [],
    "reasoning": "URL is hardcoded to a known safe endpoint",
    "false_positive_risk": "high"
}"""


def _write_temp(code: str, suffix: str = ".py") -> str:
    """Write code to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(code)
    return path


# =====================================================================
# TestPerceptionEncoder — per-sample recall and false-positive checks
# =====================================================================

class TestPerceptionEncoder:
    """Test the perception encoder against known vulnerable and safe samples."""

    def setup_method(self):
        self.encoder = PerceptionEncoder()

    def _detect(self, code: str) -> list[FactCard]:
        path = _write_temp(code)
        try:
            return self.encoder.encode_file(path)
        finally:
            os.unlink(path)

    # --- Vulnerable sample tests ---

    def test_vuln1_requests_direct(self):
        """VULN-1: requests.get(url) — direct parameter."""
        cards = self._detect(VULN_1_REQUESTS_DIRECT)
        assert len(cards) >= 1, f"VULN-1: expected >=1 FactCard, got {len(cards)}"
        assert any("requests" in (c.sink or "") for c in cards)

    def test_vuln2_flask_request_args(self):
        """VULN-2: Flask request.args → requests.get()."""
        cards = self._detect(VULN_2_FLASK_REQUEST_ARGS)
        assert len(cards) >= 1, f"VULN-2: expected >=1 FactCard, got {len(cards)}"

    def test_vuln3_string_concat(self):
        """VULN-3: URL string concatenation."""
        cards = self._detect(VULN_3_STRING_CONCAT)
        assert len(cards) >= 1, f"VULN-3: expected >=1 FactCard, got {len(cards)}"

    def test_vuln4_urllib_urlopen(self):
        """VULN-4: urllib.request.urlopen(file_url)."""
        cards = self._detect(VULN_4_URLLIB_URLOPEN)
        assert len(cards) >= 1, f"VULN-4: expected >=1 FactCard, got {len(cards)}"

    def test_vuln5_httpx_async(self):
        """VULN-5: httpx.AsyncClient.get(target_url)."""
        cards = self._detect(VULN_5_HTTPX_ASYNC)
        assert len(cards) >= 1, f"VULN-5: expected >=1 FactCard, got {len(cards)}"

    # --- Safe sample tests ---

    def test_safe1_hardcoded(self):
        """SAFE-1: Hardcoded URL should not trigger (or low confidence)."""
        cards = self._detect(SAFE_1_HARDCODED)
        # Hardcoded URL may still flag due to heuristic, but confidence should be low
        high_conf = [c for c in cards if c.confidence > 0.5]
        assert len(high_conf) == 0, f"SAFE-1: false positive with high confidence: {high_conf}"

    def test_safe2_whitelist(self):
        """SAFE-2: URL with urlparse + whitelist validation."""
        cards = self._detect(SAFE_2_WHITELIST)
        # Should have lower confidence due to validation
        high_conf = [c for c in cards if c.confidence >= 0.7]
        assert len(high_conf) == 0, f"SAFE-2: false positive with high confidence: {high_conf}"


# =====================================================================
# TestSemanticAnalyst — mock LLM calls
# =====================================================================

class TestSemanticAnalyst:
    """Test semantic analyst with mocked LLM responses."""

    def _make_fact(self, code: str, confidence: float = 0.8) -> FactCard:
        return FactCard(
            file_path="test.py", line_start=1, line_end=5,
            code_snippet=code, language="python",
            data_flow=["url->requests.get"], heuristics=["外部可控URL"],
            confidence=confidence, sink="requests.get",
        )

    @mock.patch.object(SemanticAnalystAgent, "_call_llm", return_value=LLM_VULN_RESPONSE)
    def test_vulnerable_detection(self, mock_llm):
        """Analyst should detect vulnerability with high confidence."""
        analyst = SemanticAnalystAgent(api_key="fake-key")
        fact = self._make_fact("requests.get(url)")
        card = analyst.analyze(fact)
        assert card is not None
        assert card.is_vulnerable is True
        assert card.confidence >= 0.5

    @mock.patch.object(SemanticAnalystAgent, "_call_llm", return_value=LLM_SAFE_RESPONSE)
    def test_safe_detection(self, mock_llm):
        """Analyst should return None for safe code."""
        analyst = SemanticAnalystAgent(api_key="fake-key")
        fact = self._make_fact("requests.get('https://example.com')")
        card = analyst.analyze(fact)
        assert card is None

    @mock.patch.object(SemanticAnalystAgent, "_call_llm", return_value=None)
    def test_llm_failure_graceful(self, mock_llm):
        """Analyst should return None on LLM failure."""
        analyst = SemanticAnalystAgent(api_key="fake-key")
        fact = self._make_fact("requests.get(url)")
        card = analyst.analyze(fact)
        assert card is None

    @mock.patch.object(SemanticAnalystAgent, "_call_llm")
    def test_markdown_stripping(self, mock_llm):
        """Analyst should handle markdown-wrapped JSON."""
        mock_llm.return_value = "```json\n" + LLM_VULN_RESPONSE + "\n```"
        analyst = SemanticAnalystAgent(api_key="fake-key")
        fact = self._make_fact("requests.get(url)")
        card = analyst.analyze(fact)
        assert card is not None
        assert card.is_vulnerable is True


# =====================================================================
# TestToolExecutor — mock Semgrep
# =====================================================================

class TestToolExecutor:
    """Test tool executor with mocked Semgrep."""

    def _make_hypothesis(self, confidence: float = 0.7) -> HypothesisCard:
        return HypothesisCard(
            source_fact_id="test.py:1",
            is_vulnerable=True,
            confidence=confidence,
            attack_path="SSRF via user-controlled URL",
            preconditions=["No validation"],
            reasoning="Direct parameter pass",
            file_path="test.py",
            line_start=1, line_end=5,
            code_snippet="requests.get(url)",
        )

    def test_low_confidence_skipped(self):
        """Hypotheses below threshold should be marked unverified."""
        executor = ToolExecutorAgent(min_confidence=0.5)
        hyp = self._make_hypothesis(confidence=0.3)
        chain = executor.verify(hyp)
        assert chain.verdict == "unverified"

    @mock.patch("tools.semgrep_runner.subprocess.run")
    def test_semgrep_tool_unavailable(self, mock_run):
        """Semgrep unavailable should produce manual review note."""
        mock_run.side_effect = FileNotFoundError("semgrep not found")
        executor = ToolExecutorAgent(min_confidence=0.5)
        hyp = self._make_hypothesis(confidence=0.7)
        chain = executor.verify(hyp)
        assert chain.verdict == "unverified"
        assert "人工" in chain.manual_review_note or "Semgrep" in chain.manual_review_note


# =====================================================================
# TestBenchmark — end-to-end recall and false-positive rates
# =====================================================================

class TestBenchmark:
    """End-to-end benchmark: measure recall and false-positive rate."""

    def setup_method(self):
        self.encoder = PerceptionEncoder()

    def _detect(self, code: str) -> list[FactCard]:
        path = _write_temp(code)
        try:
            return self.encoder.encode_file(path)
        finally:
            os.unlink(path)

    def test_recall_and_fp(self):
        """Measure recall on vulnerable samples and FP rate on safe samples."""
        vulnerable_samples = [
            ("VULN-1 requests_direct", VULN_1_REQUESTS_DIRECT),
            ("VULN-2 flask_request_args", VULN_2_FLASK_REQUEST_ARGS),
            ("VULN-3 string_concat", VULN_3_STRING_CONCAT),
            ("VULN-4 urllib_urlopen", VULN_4_URLLIB_URLOPEN),
            ("VULN-5 httpx_async", VULN_5_HTTPX_ASYNC),
        ]
        safe_samples = [
            ("SAFE-1 hardcoded", SAFE_1_HARDCODED),
            ("SAFE-2 whitelist", SAFE_2_WHITELIST),
        ]

        # Recall: how many vuln samples are detected (at least 1 FactCard)
        tp = 0
        recall_details = []
        for name, code in vulnerable_samples:
            cards = self._detect(code)
            detected = len(cards) >= 1
            if detected:
                tp += 1
            recall_details.append((name, len(cards), detected))

        recall_rate = tp / len(vulnerable_samples)

        # False positive: how many safe samples produce high-confidence cards
        fp = 0
        fp_details = []
        for name, code in safe_samples:
            cards = self._detect(code)
            high_conf = [c for c in cards if c.confidence > 0.5]
            is_fp = len(high_conf) >= 1
            if is_fp:
                fp += 1
            fp_details.append((name, len(cards), len(high_conf), is_fp))

        fp_rate = fp / len(safe_samples) if safe_samples else 0

        # Print summary table
        print("\n" + "=" * 70)
        print(f"{'NEXUS P0 BENCHMARK RESULTS':^70}")
        print("=" * 70)
        print(f"\n{'Sample':<30} {'Cards':>6} {'Detected':>10}")
        print("-" * 50)
        for name, count, detected in recall_details:
            print(f"{name:<30} {count:>6} {'✅' if detected else '❌':>10}")
        print(f"\n{'Safe Sample':<30} {'Cards':>6} {'FP(High)':>10}")
        print("-" * 50)
        for name, total, high, is_fp in fp_details:
            print(f"{name:<30} {total:>6} {high:>10} {'⚠️ FP' if is_fp else '✅':>10}")

        print(f"\n{'=' * 50}")
        print(f"Recall Rate:  {recall_rate:.0%} ({tp}/{len(vulnerable_samples)})")
        print(f"FP Rate:      {fp_rate:.0%} ({fp}/{len(safe_samples)})")
        print(f"{'=' * 50}")

        # Assertions
        assert recall_rate >= 0.8, f"Recall rate {recall_rate:.0%} < 80%"
        assert fp_rate <= 0.3, f"False positive rate {fp_rate:.0%} > 30%"

    def test_evidence_chain_report_generation(self):
        """Test that EvidenceChain.to_report() produces valid markdown."""
        chain = EvidenceChain(
            hypothesis_id="test.py:1",
            verdict="confirmed",
            final_confidence=0.85,
            file_path="test.py",
            line_start=1, line_end=5,
            code_snippet="requests.get(url)",
            attack_path="Internal network scan",
            preconditions=["User-controlled URL", "No validation"],
            reasoning="Direct parameter pass to requests.get",
        )
        report = chain.to_report()
        assert "# SSRF Vulnerability Report" in report
        assert "test.py" in report
        assert "requests.get(url)" in report
