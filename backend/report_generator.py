"""
PDF report generator for Cyber Triage case records.

Uses ReportLab to produce a professional forensic triage report containing:
  1. Cover page with case ID and generation metadata
  2. Case summary (title, description, status, key facts)
  3. Threat assessment (score composition, artifact priorities)
  4. Priority findings table
  5. Recommended actions
  6. Evidence status
  7. Activity log

The generator accepts a case record dict (the same shape stored in MongoDB /
returned by the ``GET /api/cases/:caseId`` endpoint) and returns a PDF byte
stream ready to be served over HTTP.
"""

import io
from html import escape
import logging
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour palette (dark forensic theme mapped to PDF)
# ---------------------------------------------------------------------------
BRAND_ORANGE = colors.HexColor("#E8732A")
DARK_BG = colors.HexColor("#14161A")
CARD_BG = colors.HexColor("#1C1F26")
BORDER_COLOR = colors.HexColor("#2A2D35")
TEXT_PRIMARY = colors.HexColor("#E8E9EC")
TEXT_SECONDARY = colors.HexColor("#9CA0AB")
TEXT_MUTED = colors.HexColor("#6B7080")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#EF4444"),
    "HIGH": colors.HexColor("#F59E0B"),
    "MEDIUM": colors.HexColor("#3B82F6"),
    "LOW": colors.HexColor("#6B7280"),
    "INFO": colors.HexColor("#6B7280"),
}


def _severity_color(severity):
    return SEVERITY_COLORS.get(severity, TEXT_SECONDARY)


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontSize=28,
        leading=34,
        textColor=BRAND_ORANGE,
        alignment=TA_CENTER,
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        "CoverSub",
        parent=styles["Normal"],
        fontSize=14,
        leading=18,
        textColor=TEXT_SECONDARY,
        alignment=TA_CENTER,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        textColor=BRAND_ORANGE,
        spaceBefore=18,
        spaceAfter=8,
        borderWidth=0,
    ))
    styles.add(ParagraphStyle(
        "SubHeading",
        parent=styles["Heading3"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#555555"),
        spaceBefore=10,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#333333"),
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SmallMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555"),
    ))
    styles.add(ParagraphStyle(
        "FindingTitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1a1a1a"),
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "CellText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#333333"),
    ))

    return styles


# ---------------------------------------------------------------------------
# Page decoration
# ---------------------------------------------------------------------------

def _header_footer(canvas, doc):
    canvas.saveState()
    # Header line
    canvas.setStrokeColor(BRAND_ORANGE)
    canvas.setLineWidth(0.5)
    canvas.line(2 * cm, A4[1] - 1.5 * cm, A4[0] - 2 * cm, A4[1] - 1.5 * cm)

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(2 * cm, A4[1] - 1.3 * cm, "CYBER TRIAGE — Digital Forensic Investigation Report")
    canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.3 * cm, f"Page {doc.page}")

    # Footer
    canvas.setStrokeColor(colors.HexColor("#CCCCCC"))
    canvas.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)
    canvas.setFont("Helvetica", 6)
    canvas.drawString(2 * cm, 1.0 * cm, "CONFIDENTIAL — For authorised investigative use only")
    canvas.drawRightString(
        A4[0] - 2 * cm, 1.0 * cm,
        f"Generated {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}",
    )
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_cover(case, styles):
    """Cover page elements."""
    elements = [
        Spacer(1, 4 * cm),
        Paragraph("CYBER TRIAGE", styles["CoverTitle"]),
        Paragraph("Digital Forensic Investigation Report", styles["CoverSub"]),
        Spacer(1, 1.5 * cm),
        HRFlowable(width="60%", thickness=1, color=BRAND_ORANGE, spaceAfter=20),
        Paragraph(f"Case: <b>{case.get('id', 'N/A')}</b>", styles["CoverSub"]),
        Paragraph(case.get("title", ""), styles["CoverSub"]),
        Spacer(1, 1 * cm),
        Paragraph(f"Examiner: {case.get('examiner', 'N/A')}", styles["CoverSub"]),
        Paragraph(f"Status: {case.get('status', 'N/A')}", styles["CoverSub"]),
        Paragraph(f"Opened: {case.get('openedAt', 'N/A')}", styles["CoverSub"]),
        Paragraph(
            f"Report generated: {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}",
            styles["CoverSub"],
        ),
        Spacer(1, 2 * cm),
        Paragraph(
            "CONFIDENTIAL — For authorised investigative use only",
            ParagraphStyle("ConfNote", parent=styles["Normal"], fontSize=8, textColor=TEXT_MUTED, alignment=TA_CENTER),
        ),
        PageBreak(),
    ]
    return elements


def _build_summary(case, styles):
    """Case summary section."""
    elements = [
        Paragraph("1. Case Summary", styles["SectionHeading"]),
    ]

    # Title and description
    elements.append(Paragraph(f"<b>{case.get('title', '')}</b>", styles["BodyText2"]))
    elements.append(Paragraph(case.get("description", ""), styles["BodyText2"]))
    elements.append(Spacer(1, 6))

    # Metadata table
    summary = case.get("summary", {})
    facts = summary.get("facts", [])
    if facts:
        data = [["Field", "Value"]]
        for fact in facts:
            data.append([fact.get("label", ""), str(fact.get("value", ""))])

        t = Table(data, colWidths=[4 * cm, 12 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8732A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 12),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F9FAFB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8))

    # Narrative
    narrative = summary.get("narrative", "")
    if narrative:
        elements.append(Paragraph("<b>Investigation Narrative</b>", styles["SubHeading"]))
        elements.append(Paragraph(narrative, styles["BodyText2"]))

    return elements


def _build_threat_assessment(case, styles):
    """Threat assessment section."""
    assessment = case.get("assessment") or {}
    threat_score = case.get("threatScore")
    if threat_score is None and not assessment and not case.get("artifactPriorities"):
        return [
            Paragraph("2. Threat Assessment", styles["SectionHeading"]),
            Paragraph(
                "Assessment not available — the pipeline has not scored this case yet.",
                styles["BodyText2"],
            ),
        ]

    score_display = f"{threat_score}/100" if threat_score is not None else "0.0/100"
    severity_display = case.get("severity", "LOW")
    network_scored = any(f.get("artifactType") == "network" for f in case.get("findings", []))
    confidence_display = "Network anomaly model and evidence rules" if network_scored else "Evidence-specific rules"
    if any(s.get('disk_scan', {}).get('pe_ml', {}).get('files_classified', 0)
           for s in case.get('evidence', {}).get('sources', [])):
        confidence_display += ' and static PE malware classifier'
    elements = [
        Paragraph("2. Threat Assessment", styles["SectionHeading"]),
        Paragraph(
            f"<b>Threat Score: {score_display}</b> · "
            f"Severity: <b>{severity_display}</b> · "
            f"Scoring Engine: {confidence_display}",
            styles["BodyText2"],
        ),
    ]

    # Score composition
    composition = assessment.get("composition", [])
    if composition:
        elements.append(Paragraph("Score Composition", styles["SubHeading"]))
        data = [[
            Paragraph("Component", styles["CellText"]),
            Paragraph("Score", styles["CellText"]),
            Paragraph("Weight", styles["CellText"]),
            Paragraph("Contribution", styles["CellText"]),
        ]]
        for comp in composition:
            data.append([
                Paragraph(escape(comp.get("label", "")), styles["CellText"]),
                Paragraph(escape(str(comp.get("score", ""))), styles["CellText"]),
                Paragraph(f"{comp.get('weight', 0) * 100:.0f}%", styles["CellText"]),
                Paragraph(escape(str(comp.get("contribution", ""))), styles["CellText"]),
            ])
        t = Table(data, colWidths=[6 * cm, 3 * cm, 3 * cm, 4 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8732A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F9FAFB")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8))

    # Artifact priority breakdown
    priorities = case.get("artifactPriorities") or assessment.get("artifactPriorities", [])
    if priorities:
        elements.append(Paragraph("Artifact Priority Distribution", styles["SubHeading"]))
        data = [[Paragraph("Priority", styles["CellText"]), Paragraph("Count", styles["CellText"])]]
        for p in priorities:
            data.append([
                Paragraph(escape(str(p.get("severity", ""))), styles["CellText"]),
                Paragraph(f"{p.get('count', 0):,}", styles["CellText"]),
            ])
        t = Table(data, colWidths=[8 * cm, 8 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8732A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F9FAFB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8))

    # MITRE tactic coverage
    coverage = assessment.get("coverage", [])
    if coverage:
        elements.append(Paragraph("MITRE ATT&CK Tactic Coverage", styles["SubHeading"]))
        data = [[
            Paragraph("Tactic", styles["CellText"]),
            Paragraph("State", styles["CellText"]),
            Paragraph("Note", styles["CellText"]),
        ]]
        for c in coverage:
            state = c.get("state", "")
            state_display = state.upper()
            data.append([
                Paragraph(escape(c.get("tactic", "")), styles["CellText"]),
                Paragraph(escape(state_display), styles["CellText"]),
                Paragraph(escape(c.get("note", "")), styles["CellText"]),
            ])
        t = Table(data, colWidths=[4 * cm, 3 * cm, 9 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8732A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F9FAFB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)

    return elements



def _finding_label(finding):
    """Keep long evidence paths out of the compact summary; retain them in details."""
    title = finding.get("title") or "Untitled artifact"
    if finding.get("artifactType") == "file":
        path = title.split(": ", 1)[0].removesuffix(" (No rule match)")
        return path.replace("\\", "/").rsplit("/", 1)[-1] or title
    return title


def _build_findings(case, styles):
    findings = case.get("findings", [])
    elements = [Paragraph("3. Priority Findings", styles["SectionHeading"])]
    if not findings:
        return elements + [Paragraph("No findings recorded.", styles["BodyText2"])]
    elements.append(Paragraph(
        f"{len(findings)} stored artifacts, ranked by risk. For rules-only evidence, zero means no configured rule matched; "
        "it is not a clean bill of health. Network anomaly scores apply only to network flows. "
        "Unmapped ATT&amp;CK techniques are not inferred from filenames.", styles["BodyText2"]))

    def cell(value):
        return Paragraph(str(value if value is not None else "Not recorded"), styles["CellText"])

    data = [[cell(v) for v in ("#", "Artifact", "Rule result / finding", "Priority", "Risk /100")]]
    for i, finding in enumerate(findings, 1):
        title = finding.get("title") or ""
        rule_result = title.split(": ", 1)[-1] if ": " in title else title
        if "No rule match" in title or title == "Scored artifact; no rule match":
            rule_result = "No configured rules matched"
        elif finding.get("artifactType") == "file" and ": " not in title:
            rule_result = "See finding details"
        data.append([cell(i), cell(_finding_label(finding)), cell(rule_result),
                     cell(finding.get("severity")), cell(finding.get("riskScore"))])
    table = Table(data, colWidths=[0.7*cm, 4.8*cm, 6.2*cm, 2.4*cm, 1.9*cm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8732A")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.extend([table, Spacer(1, 10)])
    for i, finding in enumerate(findings, 1):
        technique = finding.get("technique") or {}
        technique_label = " ".join(str(technique.get(k) or "") for k in ("id", "name")).strip() or "Not mapped"
        rationale = finding.get("rationale") or "Scoring details unavailable."
        rationale = rationale.replace("anomaly score: None", "ML anomaly: not applicable to file/log/registry evidence")
        details = [
            Paragraph(f"{i}. {_finding_label(finding)} - {finding.get('severity', 'Not recorded')} "
                      f"(risk {finding.get('riskScore', 'Not recorded')}/100)", styles["FindingTitle"]),
            Paragraph(f"<b>Finding:</b> {finding.get('title', '')}", styles["BodyText2"]),
            Paragraph(f"<b>Artifact ID:</b> {finding.get('id', '')}", styles["BodyText2"]),
            Paragraph(f"<b>Source evidence:</b> {finding.get('source') or 'Not recorded'}", styles["BodyText2"]),
            Paragraph(rationale, styles["BodyText2"]),
            Paragraph(f"<b>ATT&amp;CK technique:</b> {technique_label}. "
                      f"<b>Confidence:</b> {finding.get('confidence') if finding.get('confidence') is not None else 'Not calibrated'}.", styles["BodyText2"]),
            Paragraph(f"<b>Host:</b> {finding.get('host') or 'Not recorded'} · "
                      f"<b>Recorded:</b> {finding.get('observedAt') or 'Not recorded'}", styles["BodyText2"]),
            Spacer(1, 10),
        ]
        if i == 1:
            details.insert(0, Paragraph("Finding Details", styles["SubHeading"]))
        elements.append(KeepTogether(details))
    return elements


def _build_recommendation(case, styles):
    """Recommended action section."""
    rec = case.get("recommendation")
    if not rec:
        return []

    elements = [
        Paragraph("4. Recommended Action", styles["SectionHeading"]),
        Paragraph(
            f"<b>Urgency:</b> {rec.get('urgency', 'N/A')} · "
            f"<b>Window:</b> {rec.get('window', 'N/A')} · "
            f"<b>Owner:</b> {rec.get('owner', 'N/A')}",
            styles["BodyText2"],
        ),
        Paragraph(f"<b>{rec.get('headline', '')}</b>", styles["BodyText2"]),
        Spacer(1, 4),
    ]

    steps = rec.get("steps", [])
    for i, step in enumerate(steps, 1):
        elements.append(Paragraph(f"{i}. {step}", styles["BodyText2"]))

    rationale = rec.get("rationale", "")
    if rationale:
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("<b>Rationale:</b>", styles["BodyText2"]))
        elements.append(Paragraph(rationale, styles["BodyText2"]))

    return elements


def _build_evidence(case, styles):
    """Evidence status section."""
    evidence = case.get("evidence", {})
    sources = evidence.get("sources", [])
    pending = evidence.get("pending", [])

    if not sources and not pending:
        return []

    elements = [
        Paragraph("5. Evidence Status", styles["SectionHeading"]),
    ]

    if sources:
        elements.append(Paragraph("Acquired Sources", styles["SubHeading"]))
        data = [[
            Paragraph("ID", styles["CellText"]),
            Paragraph("Label", styles["CellText"]),
            Paragraph("Kind", styles["CellText"]),
            Paragraph("Size", styles["CellText"]),
            Paragraph("Integrity", styles["CellText"]),
            Paragraph("State", styles["CellText"]),
        ]]
        for s in sources:
            if s.get('disk_scan'):
                scan = s['disk_scan']
                if scan.get('pe_ml'):
                    pe = scan['pe_ml']
                    elements.append(Paragraph(escape(
                        f"PE malware ML: {pe['files_classified']} classified; {pe['malicious']} malicious predictions; "
                        f"{pe['benign']} benign predictions; {pe['files_excluded']} excluded; {pe['classification_errors']} errors. "
                        f"Model: {pe['model']['model_id']}; version {pe['model']['model_version']}; "
                        f"SHA-256 {pe['model']['model_sha256']}; extractor {pe['model']['feature_extractor_version']}. "
                        "Static model scores are not calibrated confidence or per-file accuracy. Benign predictions do not establish safety."), styles['BodyText2']))
                elements.append(Paragraph(escape(
                    f"Disk scan {scan['scan_status']}: {scan['files_scanned']} scanned, "
                    f"{scan['files_skipped']} skipped, {scan['files_with_yara_matches']} matched; "
                    f"ruleset {scan.get('ruleset_id')}. " + '; '.join(scan.get('warnings', []))), styles['BodyText2']))
                elements.append(Paragraph(escape(
                    f"Evidence SHA-256: {s.get('sha256')}. "
                    f"Entries: {scan.get('entries_discovered')}; regular files: {scan.get('regular_files_discovered')}; "
                    f"eligible: {scan.get('total_eligible_files')}; excluded by limits: {scan.get('files_skipped_limits')}; "
                    f"failed: {scan.get('files_failed')}; non-file entries ignored: {scan.get('non_file_entries_ignored')}. "
                    f"Timings (seconds): {scan.get('timings')}. "
                    "Scope: regular default file streams; no deleted-file recovery or alternate stream guarantee. "
                    "No signature match does not establish safety. Duration checks between native parser calls are cooperative."), styles['BodyText2']))
            raw_id = s.get("id", "")
            short_id = f"IN-...{raw_id[-6:]}" if len(raw_id) > 12 else raw_id
            raw_size = str(s.get("size", ""))
            data.append([
                Paragraph(escape(short_id), styles["CellText"]),
                Paragraph(escape(s.get("label", "")), styles["CellText"]),
                Paragraph(escape(s.get("kind", "")), styles["CellText"]),
                Paragraph(escape(raw_size), styles["CellText"]),
                Paragraph(escape(s.get("integrity", "")), styles["CellText"]),
                Paragraph(escape(s.get("state", "")), styles["CellText"]),
            ])
        t = Table(data, colWidths=[2.2 * cm, 4.4 * cm, 2.2 * cm, 2.6 * cm, 3.5 * cm, 2.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8732A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("LEADING", (0, 0), (-1, -1), 10),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F9FAFB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8))

    if pending:
        elements.append(Paragraph("Outstanding Acquisitions", styles["SubHeading"]))
        for p in pending:
            elements.append(Paragraph(
                f"<b>{escape(p.get('label', ''))}</b>: {escape(p.get('reason', ''))}",
                styles["BodyText2"],
            ))

    return elements


def _build_activity(case, styles):
    """Activity log section."""
    activity = case.get("activity", [])
    if not activity:
        return []

    elements = [
        Paragraph("6. Activity Log", styles["SectionHeading"]),
    ]

    data = [[
        Paragraph("Time", styles["CellText"]),
        Paragraph("Kind", styles["CellText"]),
        Paragraph("Severity", styles["CellText"]),
        Paragraph("Message", styles["CellText"]),
        Paragraph("Actor", styles["CellText"]),
    ]]
    for a in activity:
        raw_time = str(a.get("relative", a.get("at", "")))
        if "T" in raw_time and len(raw_time) >= 19:
            display_time = raw_time[:19].replace("T", " ")
        else:
            display_time = raw_time
        data.append([
            Paragraph(escape(display_time), styles["CellText"]),
            Paragraph(escape(a.get("kind", "")), styles["CellText"]),
            Paragraph(escape(a.get("severity", "")), styles["CellText"]),
            Paragraph(escape(a.get("message", "")), styles["CellText"]),
            Paragraph(escape(a.get("actor", "")), styles["CellText"]),
        ])

    t = Table(data, colWidths=[3.2 * cm, 1.8 * cm, 1.8 * cm, 7.6 * cm, 3.0 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8732A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("LEADING", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F9FAFB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)

    return elements



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_case_report(case_record):
    """
    Generate a PDF triage report for a case record.

    Parameters
    ----------
    case_record : dict
        A case record in the shape returned by ``GET /api/cases/:caseId``.

    Returns
    -------
    bytes
        The PDF document as a byte string.
    """
    def safe(value):
        if isinstance(value, str):
            return escape(value)
        if isinstance(value, dict):
            return {key: safe(item) for key, item in value.items()}
        if isinstance(value, list):
            return [safe(item) for item in value]
        return value
    case_record = safe(case_record)
    buffer = io.BytesIO()
    styles = _build_styles()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        title=f"Cyber Triage Report — {case_record.get('id', 'Unknown')}",
        author="Cyber Triage Tool",
        subject="Digital Forensic Investigation Report",
    )

    elements = []
    elements.extend(_build_cover(case_record, styles))
    elements.extend(_build_summary(case_record, styles))
    elements.extend(_build_threat_assessment(case_record, styles))
    elements.extend(_build_findings(case_record, styles))
    elements.extend(_build_recommendation(case_record, styles))
    elements.extend(_build_evidence(case_record, styles))
    elements.extend(_build_activity(case_record, styles))

    doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    logger.info(
        "Generated PDF report for case %s (%d bytes)",
        case_record.get("id", "?"),
        len(pdf_bytes),
    )
    return pdf_bytes
