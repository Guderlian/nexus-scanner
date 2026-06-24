"""CI/CD integration tests."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cicd.github_action import GitHubActionReporter
from cicd.gitlab_ci import GitLabCIReporter
from core.evidence_chain import EvidenceChain, EvidenceItem


def _ev(confidence=0.8) -> EvidenceChain:
    return EvidenceChain(
        hypothesis_id="t:1", verdict="confirmed",
        final_confidence=confidence,
        evidence=[EvidenceItem(tool="semgrep", result="found")],
        file_path="app.py", line_start=10, line_end=15,
        code_snippet="requests.get(url)", attack_path="SSRF",
    )


class TestGitHubAction:
    def test_annotation_format(self, capsys):
        """Annotations print correct format."""
        gh = GitHubActionReporter()
        gh.output_annotations([_ev(0.9)])
        captured = capsys.readouterr()
        assert "::error" in captured.out or "::warning" in captured.out
        assert "app.py" in captured.out

    def test_exit_code_critical(self):
        """Critical finding → exit_code=1."""
        gh = GitHubActionReporter()
        assert gh.exit_code([_ev(0.9)]) == 1

    def test_exit_code_low(self):
        """Low finding → exit_code=0."""
        gh = GitHubActionReporter()
        assert gh.exit_code([_ev(0.2)]) == 0

    def test_summary_markdown(self):
        """Summary is valid markdown."""
        gh = GitHubActionReporter()
        summary = gh.generate_summary([_ev(0.8)])
        assert "Nexus" in summary
        assert "Findings" in summary


class TestGitLabCI:
    def test_sast_json_valid(self):
        """SAST report is valid JSON with required fields."""
        gl = GitLabCIReporter()
        raw = gl.generate_sast_report([_ev(0.8)])
        data = json.loads(raw)
        assert "vulnerabilities" in data
        assert "scan" in data
        assert len(data["vulnerabilities"]) == 1

    def test_exit_code_high(self):
        gl = GitLabCIReporter()
        assert gl.exit_code([_ev(0.9)]) == 1

    def test_exit_code_low(self):
        gl = GitLabCIReporter()
        assert gl.exit_code([_ev(0.1)]) == 0
