"""GitLab CI integration."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.evidence_chain import EvidenceChain


class GitLabCIReporter:
    """Outputs results in GitLab CI format."""

    def generate_gl_code_quality(self, evidences: list) -> str:
        """Generate GitLab Code Quality JSON report."""
        issues = []
        for ev in evidences:
            if hasattr(ev, 'file_path'):
                fpath, line, conf = ev.file_path, ev.line_start, ev.final_confidence
                snippet = ev.code_snippet
                attack = ev.attack_path
            else:
                fpath = ev.get("file_path", "unknown")
                line = ev.get("line_start", 0)
                conf = ev.get("final_confidence", 0)
                snippet = ev.get("code_snippet", "")
                attack = ev.get("attack_path", "")

            sev = self._classify(conf)
            issues.append({
                "type": "issue",
                "check_name": f"nexus-{sev}",
                "description": f"[Nexus] {attack}" if attack else "[Nexus] Security finding",
                "content": {"body": snippet[:500]},
                "location": {
                    "path": fpath,
                    "lines": {"begin": line},
                },
                "severity": sev if sev in ("critical", "major", "minor", "info") else "major",
                "fingerprint": f"{fpath}:{line}:{conf:.2f}",
            })
        return json.dumps(issues, indent=2)

    def generate_sast_report(self, evidences: list) -> str:
        """Generate GitLab SAST JSON report."""
        vulnerabilities = []
        for ev in evidences:
            if hasattr(ev, 'file_path'):
                fpath, line, conf = ev.file_path, ev.line_start, ev.final_confidence
                snippet = ev.code_snippet
                attack = ev.attack_path
            else:
                fpath = ev.get("file_path", "unknown")
                line = ev.get("line_start", 0)
                conf = ev.get("final_confidence", 0)
                snippet = ev.get("code_snippet", "")
                attack = ev.get("attack_path", "")

            sev = self._classify(conf)
            vulnerabilities.append({
                "id": f"nexus-{fpath}-{line}",
                "category": "sast",
                "name": f"Security Finding - {sev.upper()}",
                "description": attack or "Security vulnerability detected",
                "severity": sev if sev in ("Critical", "High", "Medium", "Low") else sev.title(),
                "location": {
                    "file": fpath,
                    "start_line": line,
                    "end_line": line,
                },
                "identifiers": [{
                    "type": "nexus_scan",
                    "name": f"Nexus {sev.upper()}",
                    "value": f"{fpath}:{line}",
                }],
            })

        report = {
            "version": "15.0.0",
            "vulnerabilities": vulnerabilities,
            "scan": {
                "analyzer": {"id": "nexus", "name": "Nexus P3", "url": "https://nexus.dev"},
                "scanner": {"id": "nexus", "name": "Nexus P3"},
                "type": "sast",
                "start_time": datetime.utcnow().isoformat(),
                "end_time": datetime.utcnow().isoformat(),
                "status": "success",
            },
        }
        return json.dumps(report, indent=2)

    def exit_code(self, evidences: list,
                  fail_on: list[str] = None) -> int:
        """Return 1 if critical/high findings exist."""
        if fail_on is None:
            fail_on = ["critical", "high"]
        for ev in evidences:
            conf = ev.final_confidence if hasattr(ev, 'final_confidence') else ev.get('final_confidence', 0)
            if self._classify(conf) in fail_on:
                return 1
        return 0

    def _classify(self, confidence: float) -> str:
        if confidence >= 0.8:
            return "critical"
        if confidence >= 0.6:
            return "high"
        if confidence >= 0.4:
            return "medium"
        return "low"
