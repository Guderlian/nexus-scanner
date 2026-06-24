"""Compliance mapping tests."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.owasp_mapper import OWASPMapper
from compliance.cwe_mapper import CWEMapper
from compliance.compliance_reporter import ComplianceReporter
from core.evidence_chain import EvidenceChain, EvidenceItem


def _ev(conf=0.8, attack="SSRF via requests.get") -> EvidenceChain:
    return EvidenceChain(
        hypothesis_id="t:1", verdict="confirmed",
        final_confidence=conf,
        evidence=[EvidenceItem(tool="semgrep", result="found")],
        file_path="app.py", line_start=10, line_end=15,
        code_snippet="requests.get(url)", attack_path=attack,
    )


class TestOWASPMapper:
    def test_all_vuln_types_mapped(self):
        """8类漏洞各自映射到正确的OWASP ID."""
        owasp = OWASPMapper()
        expected = {
            "SSRF": "A10", "SQLI": "A03", "XSS": "A03", "IDOR": "A01",
            "SSTI": "A03", "XXE": "A03", "PATH_TRAVERSAL": "A01",
            "DESERIALIZATION": "A06",
        }
        for vuln, expected_id in expected.items():
            assert owasp.get_owasp_id(vuln) == expected_id, f"{vuln} → {owasp.get_owasp_id(vuln)} != {expected_id}"

    def test_risk_rating(self):
        owasp = OWASPMapper()
        assert owasp.get_risk_rating("SSRF") in ("Critical", "High", "Medium")
        assert owasp.get_risk_rating("SQLI") in ("Critical", "High", "Medium")

    def test_unknown_returns_na(self):
        owasp = OWASPMapper()
        assert owasp.get_owasp_id("UNKNOWN") == "N/A"


class TestCWEMapper:
    def test_all_vuln_types_mapped(self):
        """8类漏洞各自映射到正确的CWE ID."""
        cwe = CWEMapper()
        expected = {
            "SSRF": "CWE-918", "SQLI": "CWE-89", "XSS": "CWE-79",
            "IDOR": "CWE-639", "SSTI": "CWE-94", "XXE": "CWE-611",
            "PATH_TRAVERSAL": "CWE-22", "DESERIALIZATION": "CWE-502",
        }
        for vuln, expected_id in expected.items():
            assert cwe.get_cwe_id(vuln) == expected_id, f"{vuln} → {cwe.get_cwe_id(vuln)} != {expected_id}"

    def test_cwe_url(self):
        cwe = CWEMapper()
        info = cwe.map("SSRF")
        assert "cwe.mitre.org" in info["url"]
        assert "918" in info["url"]

    def test_unknown_returns_na(self):
        cwe = CWEMapper()
        assert cwe.get_cwe_id("UNKNOWN") == "N/A"


class TestComplianceReporter:
    def test_owasp_report_structure(self):
        reporter = ComplianceReporter()
        report = reporter.generate_owasp_report([_ev()])
        assert "A10" in report  # SSRF → A10

    def test_cwe_report_structure(self):
        reporter = ComplianceReporter()
        report = reporter.generate_cwe_report([_ev()])
        assert any("CWE-918" in k for k in report.keys())

    def test_compliance_summary(self):
        reporter = ComplianceReporter()
        summary = reporter.generate_compliance_summary([_ev()])
        assert "OWASP" in summary
        assert "CWE" in summary
        assert "Risk" in summary

    def test_empty_evidences(self):
        reporter = ComplianceReporter()
        report = reporter.generate_owasp_report([])
        assert report == {}
        summary = reporter.generate_compliance_summary([])
        assert "OWASP" in summary
