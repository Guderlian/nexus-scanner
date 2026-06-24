"""GitHub Actions integration."""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.evidence_chain import EvidenceChain


class GitHubActionReporter:
    """Outputs results in GitHub Actions format."""

    def output_annotations(self, evidences: list) -> None:
        """Print GitHub Actions annotations."""
        for ev in evidences:
            if hasattr(ev, 'file_path'):
                fpath, line, conf = ev.file_path, ev.line_start, ev.final_confidence
                attack = ev.attack_path
            else:
                fpath = ev.get("file_path", "unknown")
                line = ev.get("line_start", 0)
                conf = ev.get("final_confidence", 0)
                attack = ev.get("attack_path", "")

            sev = self._classify(conf)
            level = "error" if sev in ("critical", "high") else "warning"
            print(f"::{level} file={fpath},line={line}::Nexus: {sev.upper()} - {attack}")

    def set_output(self, key: str, value: str) -> None:
        """Set a GitHub Actions output variable."""
        gh_output = os.environ.get("GITHUB_OUTPUT", "")
        if gh_output:
            with open(gh_output, "a") as f:
                f.write(f"{key}={value}\n")
        else:
            print(f"::set-output name={key}::{value}")

    def generate_summary(self, evidences: list) -> str:
        """Generate GitHub Actions Job Summary (Markdown)."""
        lines = ["## 🛡️ Nexus Security Scan Results\n"]
        lines.append(f"**Total findings:** {len(evidences)}\n")

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for ev in evidences:
            conf = ev.final_confidence if hasattr(ev, 'final_confidence') else ev.get('final_confidence', 0)
            counts[self._classify(conf)] += 1

        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev, cnt in counts.items():
            lines.append(f"| {sev.upper()} | {cnt} |")

        lines.append("\n### Findings\n")
        for i, ev in enumerate(evidences[:20]):
            if hasattr(ev, 'file_path'):
                fpath, line, conf = ev.file_path, ev.line_start, ev.final_confidence
            else:
                fpath = ev.get("file_path", "N/A")
                line = ev.get("line_start", 0)
                conf = ev.get("final_confidence", 0)
            sev = self._classify(conf)
            lines.append(f"{i+1}. **[{sev.upper()}]** `{fpath}:{line}` (confidence: {conf:.0%})")

        return "\n".join(lines)

    def exit_code(self, evidences: list,
                  fail_on: list[str] = None) -> int:
        """Return 1 if critical/high findings exist, else 0."""
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
