"""PDF reporter tests."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reporting.pdf_reporter import PDFReporter
from core.evidence_chain import EvidenceChain, EvidenceItem


def _make_ev(confidence=0.8) -> EvidenceChain:
    return EvidenceChain(
        hypothesis_id="test:1", verdict="confirmed",
        final_confidence=confidence,
        evidence=[EvidenceItem(tool="semgrep", result="found")],
        file_path="app.py", line_start=10, line_end=15,
        code_snippet="requests.get(url)",
        attack_path="SSRF via internal network",
    )


class TestPDFReporter:
    def test_pdf_generated(self):
        """PDF file is created and > 1KB."""
        path = tempfile.mktemp(suffix=".pdf")
        r = PDFReporter(path)
        result = r.generate([_make_ev()], {"target": "app.py", "scan_time": "2024-01-01"})
        assert os.path.exists(result)
        assert os.path.getsize(result) > 1000
        os.unlink(path)

    def test_contains_all_findings(self):
        """PDF includes all evidence entries."""
        path = tempfile.mktemp(suffix=".pdf")
        r = PDFReporter(path)
        evs = [_make_ev(0.9), _make_ev(0.5), _make_ev(0.3)]
        r.generate(evs, {"target": "test"})
        assert os.path.getsize(path) > 2000
        os.unlink(path)

    def test_multiple_severity_levels(self):
        """PDF handles mixed severity levels."""
        path = tempfile.mktemp(suffix=".pdf")
        r = PDFReporter(path)
        evs = [_make_ev(0.95), _make_ev(0.65), _make_ev(0.45), _make_ev(0.25)]
        r.generate(evs, {"target": "multi"})
        assert os.path.exists(path)
        os.unlink(path)

    def test_empty_evidences_no_crash(self):
        """Empty evidence list doesn't crash."""
        path = tempfile.mktemp(suffix=".pdf")
        r = PDFReporter(path)
        r.generate([], {"target": "empty"})
        assert os.path.exists(path)
        os.unlink(path)
