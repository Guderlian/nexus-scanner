"""PoC generator tests."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exploit.poc_generator import PoCGenerator
from core.evidence_chain import EvidenceChain, EvidenceItem


def _ev(attack="SSRF via requests.get", snippet="requests.get(url)") -> EvidenceChain:
    return EvidenceChain(
        hypothesis_id="t:1", verdict="confirmed",
        final_confidence=0.85,
        evidence=[EvidenceItem(tool="semgrep", result="found")],
        file_path="app.py", line_start=10, line_end=15,
        code_snippet=snippet, attack_path=attack,
    )


class TestPoCGenerator:
    def test_ssrf_has_disclaimer(self):
        gen = PoCGenerator()
        poc = gen.generate(_ev(attack="SSRF via internal network"))
        assert "免责声明" in poc or "disclaimer" in poc.lower()

    def test_ssrf_has_metadata_test(self):
        gen = PoCGenerator()
        poc = gen.generate(_ev(attack="SSRF"))
        assert "169.254.169.254" in poc

    def test_sqli_has_boolean_blind(self):
        gen = PoCGenerator()
        poc = gen.generate(_ev(attack="SQL injection via f-string", snippet="cursor.execute(f\"SELECT...\")"))
        assert "1=1" in poc or "UNION" in poc or "盲注" in poc

    def test_xss_has_script_tag(self):
        gen = PoCGenerator()
        poc = gen.generate(_ev(attack="XSS via render_template_string", snippet="<script>alert</script>"))
        assert "script" in poc.lower()

    def test_path_traversal_has_dotdot(self):
        gen = PoCGenerator()
        poc = gen.generate(_ev(attack="Path Traversal via os.path.join", snippet="open(filepath)"))
        assert "../" in poc or "..%2F" in poc

    def test_generic_no_crash(self):
        gen = PoCGenerator()
        poc = gen.generate(_ev(attack="unknown vulnerability type"))
        assert isinstance(poc, str)
        assert len(poc) > 100
