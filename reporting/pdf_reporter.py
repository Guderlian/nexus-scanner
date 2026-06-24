"""PDFReporter - generates professional PDF security reports."""
from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.evidence_chain import EvidenceChain


class PDFReporter:
    """Generates PDF vulnerability reports using reportlab."""

    def __init__(self, output_path: str = "report.pdf"):
        self.output_path = output_path

    def generate(self, evidences: list, scan_metadata: dict) -> str:
        """Generate a PDF report. Returns the file path."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import inch, mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CustomTitle", parent=styles["Title"],
                                      fontSize=24, spaceAfter=20, textColor=colors.HexColor("#1a1a2e"))
        heading_style = ParagraphStyle("CustomHeading", parent=styles["Heading2"],
                                        fontSize=16, spaceAfter=12, textColor=colors.HexColor("#16213e"))
        body_style = ParagraphStyle("CustomBody", parent=styles["Normal"],
                                     fontSize=10, spaceAfter=6)
        code_style = ParagraphStyle("Code", parent=styles["Normal"],
                                     fontSize=8, fontName="Courier", spaceAfter=6,
                                     backColor=colors.HexColor("#f0f0f0"),
                                     leftIndent=10, rightIndent=10)

        os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)
        doc = SimpleDocTemplate(self.output_path, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        story = []

        # Cover page
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("🛡️ Nexus P3 Security Report", title_style))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"<b>Target:</b> {scan_metadata.get('target', 'N/A')}", body_style))
        story.append(Paragraph(f"<b>Scan Time:</b> {scan_metadata.get('scan_time', datetime.utcnow().isoformat())}", body_style))
        story.append(Paragraph(f"<b>Total Findings:</b> {len(evidences)}", body_style))
        story.append(PageBreak())

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for ev in evidences:
            sev = self._classify_severity(ev.final_confidence if hasattr(ev, 'final_confidence') else ev.get('final_confidence', 0.5))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary_data = [["Severity", "Count"]]
        for sev, count in severity_counts.items():
            summary_data.append([sev.upper(), str(count)])
        t = Table(summary_data, colWidths=[2*inch, 1*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(width="100%"))
        story.append(PageBreak())

        # Findings Detail
        story.append(Paragraph("Vulnerability Findings", heading_style))
        for i, ev in enumerate(evidences):
            if hasattr(ev, 'file_path'):
                fpath, lstart, lend = ev.file_path, ev.line_start, ev.line_end
                snippet = ev.code_snippet
                attack = ev.attack_path
                conf = ev.final_confidence
                verdict = ev.verdict
            else:
                fpath = ev.get("file_path", "N/A")
                lstart = ev.get("line_start", 0)
                lend = ev.get("line_end", 0)
                snippet = ev.get("code_snippet", "")
                attack = ev.get("attack_path", "")
                conf = ev.get("final_confidence", 0)
                verdict = ev.get("verdict", "unknown")

            sev = self._classify_severity(conf)
            story.append(Paragraph(f"<b>#{i+1} [{sev.upper()}]</b> {fpath}:{lstart}-{lend}", body_style))
            story.append(Paragraph(f"<b>Verdict:</b> {verdict} | <b>Confidence:</b> {conf:.0%}", body_style))
            if attack:
                story.append(Paragraph(f"<b>Attack Path:</b> {attack}", body_style))
            if snippet:
                story.append(Paragraph(f"<font face='Courier' size='8'>{snippet[:500]}</font>", code_style))
            story.append(HRFlowable(width="100%", thickness=0.5))
            story.append(Spacer(1, 0.2*inch))

        if not evidences:
            story.append(Paragraph("No vulnerabilities found.", body_style))

        # Appendix
        story.append(PageBreak())
        story.append(Paragraph("Appendix", heading_style))
        for k, v in scan_metadata.items():
            story.append(Paragraph(f"<b>{k}:</b> {v}", body_style))

        doc.build(story)
        return self.output_path

    def _classify_severity(self, confidence: float) -> str:
        if confidence >= 0.8:
            return "critical"
        if confidence >= 0.6:
            return "high"
        if confidence >= 0.4:
            return "medium"
        return "low"
