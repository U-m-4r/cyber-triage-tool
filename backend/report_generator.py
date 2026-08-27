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
        textColor=colors.HexColor("#C0C4CC"),
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
    assessment = case.get("assessment")
    if not assessment:
        return [
            Paragraph("2. Threat Assessment", styles["SectionHeading"]),
            Paragraph(
                "Assessment not available — the pipeline has not scored this case yet.",
                styles["BodyText2"],
            ),
        ]

    elements = [
        Paragraph("2. Threat Assessment", styles["SectionHeading"]),
        Paragraph(
            f"<b>Threat Score: {case.get('threatScore', 'N/A')}/100</b> · "
            f"Severity: <b>{case.get('severity', 'N/A')}</b> · "
            f"Confidence: {assessment.get('confidence', 'N/A')}",
            styles["BodyText2"],
        ),
    ]

    # Score composition
    composition = assessment.get("composition", [])
    if composition:
        elements.append(Paragraph("Score Composition", styles["SubHeading"]))
        data = [["Component", "Score", "Weight", "Contribution"]]
        for comp in composition:
            data.append([
                comp.get("label", ""),
                str(comp.get("score", "")),
                f"{comp.get('weight', 0) * 100:.0f}%",
                str(comp.get("contribution", "")),
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
    priorities = assessment.get("artifactPriorities", [])
    if priorities:
        elements.append(Paragraph("Artifact Priority Distribution", styles["SubHeading"]))
        data = [["Priority", "Count"]]
        for p in priorities:
            data.append([p.get("severity", ""), f"{p.get('count', 0):,}"])
        t = Table(data, colWidths=[6 * cm, 6 * cm])
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
        data = [["Tactic", "State", "Note"]]
        for c in coverage:
            state = c.get("state", "")
            state_display = state.upper()
            data.append([c.get("tactic", ""), state_display, c.get("note", "")])
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


def _build_findings(case, styles):
    """Priority findings section."""
    findings = case.get("findings", [])
    elements = [
        Paragraph("3. Priority Findings", styles["SectionHeading"]),
    ]

    if not findings:
        elements.append(Paragraph(
            "No findings available — the case has not been scored yet.",
            styles["BodyText2"],
        ))
        return elements

    elements.append(Paragraph(
        f"{len(findings)} findings ranked by risk score.",
        styles["BodyText2"],
    ))

    data = [["#", "ID", "Title", "Severity", "Risk", "Technique", "Source"]]
    for i, f in enumerate(findings, 1):
        technique = f.get("technique", {})
        tech_str = f"{technique.get('id', '')} {technique.get('name', '')}"
        data.append([
            str(i),
            f.get("id", ""),
            Paragraph(f.get("title", ""), styles["CellText"]),
            f.get("severity", ""),
            str(f.get("riskScore", "")),
            Paragraph(tech_str, styles["CellText"]),
            Paragraph(f.get("source", ""), styles["CellText"]),
        ])

    t = Table(data, colWidths=[1 * cm, 1.5 * cm, 3.5 * cm, 2 * cm, 1.5 * cm, 3.5 * cm, 3 * cm])
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
    elements.append(Spacer(1, 10))

    # Detailed rationales
    elements.append(Paragraph("Finding Details", styles["SubHeading"]))
    for f in findings:
        elements.append(Paragraph(
            f"<b>{f.get('id', '')} — {f.get('title', '')}</b> "
            f"(Risk: {f.get('riskScore', 'N/A')}, "
            f"Confidence: {f.get('confidence', 'N/A')})",
            styles["FindingTitle"],
        ))
        elements.append(Paragraph(f.get("rationale", "No rationale provided."), styles["BodyText2"]))
        host = f.get("host", "")
        observed = f.get("observedAt", "")
        if host or observed:
            elements.append(Paragraph(
                f"Host: {host} · Observed: {observed}",
                styles["SmallMono"],
            ))
        elements.append(Spacer(1, 4))

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
        data = [["ID", "Label", "Kind", "Size", "Integrity", "State"]]
        for s in sources:
            data.append([
                s.get("id", ""),
                Paragraph(s.get("label", ""), styles["CellText"]),
                s.get("kind", ""),
                s.get("size", ""),
                s.get("integrity", ""),
                s.get("state", ""),
            ])
        t = Table(data, colWidths=[2.2 * cm, 4.5 * cm, 2 * cm, 2 * cm, 2.8 * cm, 2.5 * cm])
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
                f"<b>{p.get('label', '')}</b>: {p.get('reason', '')}",
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

    data = [["Time", "Kind", "Severity", "Message", "Actor"]]
    for a in activity:
        data.append([
            a.get("relative", a.get("at", "")),
            a.get("kind", ""),
            a.get("severity", ""),
            Paragraph(a.get("message", ""), styles["CellText"]),
            a.get("actor", ""),
        ])

    t = Table(data, colWidths=[2.5 * cm, 2 * cm, 2 * cm, 6.5 * cm, 3 * cm])
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
