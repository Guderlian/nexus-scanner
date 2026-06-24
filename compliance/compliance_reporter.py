"""Compliance reporter - generates OWASP/CWE compliance reports."""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from compliance.owasp_mapper import OWASPMapper
from compliance.cwe_mapper import CWEMapper
from core.evidence_chain import EvidenceChain


class ComplianceReporter:
    """Generates compliance reports in OWASP/CWE format."""

    def __init__(self, owasp: OWASPMapper = None, cwe: CWEMapper = None):
        self.owasp = owasp or OWASPMapper()
        self.cwe = cwe or CWEMapper()

    def generate_owasp_report(self, evidences: list) -> dict:
        """Group evidences by OWASP category."""
        categories = {}
        for ev in evidences:
            vuln_type = self._infer_vuln_type(ev)
            owasp_entries = self.owasp.map(vuln_type)
            for entry in owasp_entries:
                oid = entry["owasp_id"]
                if oid not in categories:
                    categories[oid] = {
                        "owasp_id": oid,
                        "name": entry["name"],
                        "description": entry["description"],
                        "findings": [],
                    }
                categories[oid]["findings"].append({
                    "file": getattr(ev, 'file_path', 'N/A'),
                    "line": getattr(ev, 'line_start', 0),
                    "confidence": getattr(ev, 'final_confidence', 0),
                })
        return categories

    def generate_cwe_report(self, evidences: list) -> dict:
        """Group evidences by CWE."""
        cwe_groups = {}
        for ev in evidences:
            vuln_type = self._infer_vuln_type(ev)
            cwe_info = self.cwe.map(vuln_type)
            cid = cwe_info["id"]
            if cid not in cwe_groups:
                cwe_groups[cid] = {**cwe_info, "findings": []}
            cwe_groups[cid]["findings"].append({
                "file": getattr(ev, 'file_path', 'N/A'),
                "line": getattr(ev, 'line_start', 0),
                "confidence": getattr(ev, 'final_confidence', 0),
            })
        return cwe_groups

    def generate_compliance_summary(self, evidences: list) -> str:
        """Generate a Markdown compliance summary."""
        owasp_report = self.generate_owasp_report(evidences)
        cwe_report = self.generate_cwe_report(evidences)

        lines = ["# Nexus P4 - Compliance Report\n"]

        # OWASP section
        lines.append("## OWASP Top 10 2021 Coverage\n")
        lines.append("| OWASP ID | Category | Findings | Risk |")
        lines.append("|----------|----------|----------|------|")
        for oid, data in sorted(owasp_report.items()):
            risk = self.owasp.get_risk_rating(
                data["findings"][0].get("vuln_type", "") if data["findings"] else ""
            )
            lines.append(f"| {oid} | {data['name']} | {len(data['findings'])} | {risk} |")

        # CWE section
        lines.append("\n## CWE Mapping\n")
        lines.append("| CWE ID | Weakness | Findings |")
        lines.append("|--------|----------|----------|")
        for cid, data in sorted(cwe_report.items()):
            lines.append(f"| {cid} | {data['name']} | {len(data['findings'])} |")

        # Risk score
        total = len(evidences)
        high_conf = len([e for e in evidences if getattr(e, 'final_confidence', 0) >= 0.7])
        risk_score = min(10, high_conf * 2 + total)
        lines.append(f"\n## Risk Assessment\n")
        lines.append(f"- **Total findings:** {total}")
        lines.append(f"- **High confidence (≥0.7):** {high_conf}")
        lines.append(f"- **Risk score:** {risk_score}/10")

        # Remediation priority
        lines.append(f"\n## Remediation Priority\n")
        for i, ev in enumerate(sorted(evidences, key=lambda e: getattr(e, 'final_confidence', 0), reverse=True)[:5]):
            conf = getattr(ev, 'final_confidence', 0)
            fpath = getattr(ev, 'file_path', 'N/A')
            line = getattr(ev, 'line_start', 0)
            lines.append(f"{i+1}. `{fpath}:{line}` (confidence: {conf:.0%})")

        return "\n".join(lines)

    def _infer_vuln_type(self, ev) -> str:
        """Infer vulnerability type from an EvidenceChain."""
        attack = getattr(ev, 'attack_path', '').lower()
        snippet = getattr(ev, 'code_snippet', '').lower()
        reasoning = getattr(ev, 'reasoning', '').lower()
        text = f"{attack} {snippet} {reasoning}"

        if 'ssrf' in text or 'requests.get' in text:
            return 'SSRF'
        if 'sql' in text or 'execute' in text:
            return 'SQLI'
        if 'xss' in text or 'script' in text or 'render_template' in text:
            return 'XSS'
        if 'idor' in text or 'route_param' in text:
            return 'IDOR'
        if 'ssti' in text or 'template' in text:
            return 'SSTI'
        if 'xxe' in text or 'xml' in text or 'fromstring' in text:
            return 'XXE'
        if 'path' in text or 'traversal' in text:
            return 'PATH_TRAVERSAL'
        if 'deserialization' in text or 'pickle' in text:
            return 'DESERIALIZATION'
        return 'UNKNOWN'
