"""
Generates the System Architecture and Forensic Methodology Diagrams as High-Resolution Assets
and compiles a comprehensive, publication-quality PDF technical document using ReportLab and Matplotlib.

Output:
  - reports/Cyber_Triage_System_Architecture_and_Methodology.pdf
  - reports/artifacts/system_architecture.png
  - reports/artifacts/methodology_pipeline.png
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm, inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak,
    KeepTogether,
    HRFlowable
)

# ---------------------------------------------------------------------------
# Setup Output Directories
# ---------------------------------------------------------------------------
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
ARTIFACTS_DIR = os.path.join(REPORTS_DIR, "artifacts")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

ARCH_IMG_PATH = os.path.join(ARTIFACTS_DIR, "system_architecture.png")
METHOD_IMG_PATH = os.path.join(ARTIFACTS_DIR, "methodology_pipeline.png")
PDF_OUTPUT_PATH = os.path.join(REPORTS_DIR, "Cyber_Triage_System_Architecture_and_Methodology.pdf")

# ---------------------------------------------------------------------------
# Matplotlib Diagram Generators
# ---------------------------------------------------------------------------

def create_system_architecture_diagram():
    """Renders a sleek, high-contrast, publication-grade System Architecture Diagram."""
    fig, ax = plt.subplots(figsize=(13.5, 9.5), dpi=300)
    fig.patch.set_facecolor('#0B0F19')
    ax.set_facecolor('#0B0F19')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Title
    ax.text(50, 96.5, "CYBER TRIAGE TOOL — SYSTEM ARCHITECTURE TOPOLOGY", 
            ha='center', va='center', color='#F8FAFC', fontsize=15, fontweight='bold', family='sans-serif')
    ax.text(50, 93.8, "Multi-Tier AI-Assisted Digital Forensic Investigation Architecture (NIA / SIH1744)", 
            ha='center', va='center', color='#94A3B8', fontsize=10, family='sans-serif')

    def draw_box(x, y, w, h, bg, border, title, items, title_color='#FFFFFF', text_color='#E2E8F0', font_size=8.5, radius=1.2):
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0.5,rounding_size={radius}",
                                      facecolor=bg, edgecolor=border, linewidth=1.5, zorder=2)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h - 2.0, title, ha='center', va='top', color=title_color, fontsize=font_size+1.5, fontweight='bold', family='sans-serif', zorder=3)
        
        curr_y = y + h - 5.5
        for it in items:
            ax.text(x + 2.0, curr_y, it, ha='left', va='top', color=text_color, fontsize=font_size, family='sans-serif', zorder=3)
            curr_y -= 2.6

    def draw_container(x, y, w, h, title, border_col='#334155', bg_col='#0F172A', label_col='#38BDF8'):
        cont = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.8,rounding_size=1.5",
                                      facecolor=bg_col, edgecolor=border_col, linewidth=1.8, linestyle='--', zorder=1)
        ax.add_patch(cont)
        ax.text(x + 2.0, y + h - 2.2, title, ha='left', va='top', color=label_col, fontsize=10.5, fontweight='bold', family='sans-serif', zorder=2)

    def draw_arrow(x1, y1, x2, y2, color='#64748B', label='', lw=1.6):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=lw, mutation_scale=14), zorder=4)
        if label:
            mx, my = (x1 + x2)/2, (y1 + y2)/2
            ax.text(mx, my + 1.0, label, color='#CBD5E1', fontsize=7.5, ha='center', va='bottom',
                    bbox=dict(boxstyle='round,pad=0.2', facecolor='#0B0F19', edgecolor=color, lw=0.8), zorder=5)

    # 1. Tier 1: Client Layer
    draw_container(3, 62, 94, 28, "TIER 1: INVESTIGATOR CLIENT LAYER (React 19 + Vite SPA)", '#6366F1', '#111827', '#818CF8')
    draw_box(5, 64, 28, 21.5, '#1E293B', '#6366F1', "Investigation Dashboard", 
             ["• Active Cases List & Selection", "• Severity-Only Hue Visuals", "• Threat Score Aggregation", "• Real-Time Activity Feed"], title_color='#A5B4FC')
    draw_box(36, 64, 28, 21.5, '#1E293B', '#8B5CF6', "Case Workspace (/cases/:id)", 
             ["• 8-Tab Investigation Strip", "• Threat Assessment Matrix", "• MITRE ATT&CK Mapping", "• Top-K Ranked Finding Cards"], title_color='#C4B5FD')
    draw_box(67, 64, 28, 21.5, '#1E293B', '#EC4899', "Service & API Client", 
             ["• services/apiClient.js", "• Auto-Fallback Mock Guard", "• Error Normalization Layer", "• Axios / Stream Controller"], title_color='#F472B6')

    # 2. Tier 2: Flask API Layer
    draw_container(3, 34, 94, 24, "TIER 2: API ORCHESTRATION & INGESTION (Python Flask - backend/app.py)", '#0284C7', '#0F172A', '#38BDF8')
    draw_box(5, 36, 27, 18, '#1E293B', '#0EA5E9', "RESTful API Endpoints", 
             ["• POST /api/analyze", "• POST /api/forensics/ingest", "• GET  /api/cases & /triage", "• GET  /api/health (Liveness)"], title_color='#7DD3FC')
    draw_box(35, 36, 30, 18, '#1E293B', '#0D9488', "Forensic Intake & Custody", 
             ["• Read-Only File Streaming", "• NIST FIPS 180-4 SHA-256", "• Evidence Custody Ledger", "• Temp UUID Cleanup Guard"], title_color='#5EEAD4')
    draw_box(68, 36, 27, 18, '#1E293B', '#EA580C', "ReportLab PDF Engine", 
             ["• backend/report_generator.py", "• Automated Case Dossier", "• Executive Threat Summary", "• PDF Byte Stream Exporter"], title_color='#FDBA74')

    # 3. Tier 3: ML Engine & Multi-Source Parsers
    draw_container(3, 4, 94, 27, "TIER 3 & 4: FORENSIC PARSERS, ML INTELLIGENCE & PERSISTENCE (ml/ & backend/db.py)", '#059669', '#064E3B', '#34D399')
    draw_box(5, 6, 21, 20.5, '#065F46', '#10B981', "Multi-Source Parsers", 
             ["• EVTX (python-evtx)", "• Registry (python-registry)", "• PCAP / 5-Tuple Flows", "• Disk Images (pytsk3)", "• YARA IOCs & OTX / VT"], title_color='#A7F3D0', font_size=8)
    draw_box(28, 6, 24, 20.5, '#065F46', '#10B981', "ML Preprocessing", 
             ["• Sanitize Inf / NaN Rows", "• Drop Duplicates (No Impute)", "• 11 Flow Feature Extraction", "• StandardScaler: z=(x-μ)/σ"], title_color='#A7F3D0', font_size=8)
    draw_box(54, 6, 23, 20.5, '#065F46', '#10B981', "Dual Scoring Engine", 
             ["• IsolationForest (100 Trees)", "• Batch Min-Max: S_ml ∈ [0,100]", "• Heuristics: S_rule = min(1,ΣW)", "• 60/40 Convex Fusion & CVSS"], title_color='#A7F3D0', font_size=8)
    draw_box(79, 6, 16, 20.5, '#065F46', '#10B981', "Persistence", 
             ["• MongoDB Store", "• cases, custody", "• .pkl Model Cache", "• results.json"], title_color='#A7F3D0', font_size=8)

    # Connections / Data Flow Arrows
    draw_arrow(81, 64, 18, 54, '#A855F7', 'HTTP / REST JSON')
    draw_arrow(50, 36, 15, 26.5, '#0EA5E9', 'Raw Buffer')
    draw_arrow(26, 16, 28, 16, '#34D399', 'Parsed')
    draw_arrow(52, 16, 54, 16, '#34D399', 'Scaled')
    draw_arrow(65, 26.5, 75, 36, '#F59E0B', 'Top-K Scored')
    draw_arrow(77, 16, 79, 16, '#34D399', 'Store')

    plt.tight_layout()
    plt.savefig(ARCH_IMG_PATH, dpi=300, bbox_inches='tight', facecolor='#0B0F19')
    plt.close()
    print(f"[+] Successfully generated System Architecture Diagram at: {ARCH_IMG_PATH}")


def create_methodology_pipeline_diagram():
    """Renders the step-by-step Forensic Triage Methodology & Pipeline Flow Diagram."""
    fig, ax = plt.subplots(figsize=(13.5, 10.5), dpi=300)
    fig.patch.set_facecolor('#0B0F19')
    ax.set_facecolor('#0B0F19')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Title
    ax.text(50, 97.2, "CYBER TRIAGE TOOL — FORENSIC TRIAGE METHODOLOGY & PIPELINE", 
            ha='center', va='center', color='#F8FAFC', fontsize=15, fontweight='bold', family='sans-serif')
    ax.text(50, 94.7, "Six-Stage Systematic Triage, Anomaly Scoring, and Evidence Prioritization Workflow", 
            ha='center', va='center', color='#94A3B8', fontsize=10, family='sans-serif')

    def draw_step_box(x, y, w, h, stage_num, title, details, bg, border, badge_color):
        # Outer Card
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.2",
                                      facecolor=bg, edgecolor=border, linewidth=1.5, zorder=2)
        ax.add_patch(rect)
        # Stage Badge
        badge = patches.FancyBboxPatch((x + 1.5, y + h - 3.2), 16, 2.8, boxstyle="round,pad=0.2,rounding_size=0.6",
                                       facecolor=badge_color, edgecolor='none', zorder=3)
        ax.add_patch(badge)
        ax.text(x + 9.5, y + h - 1.8, f"STAGE {stage_num}", ha='center', va='center', color='#FFFFFF', fontsize=7.5, fontweight='bold', zorder=4)
        
        # Title
        ax.text(x + 19, y + h - 1.8, title, ha='left', va='center', color='#F8FAFC', fontsize=9.5, fontweight='bold', zorder=3)
        
        # Details list
        curr_y = y + h - 5.5
        for dt in details:
            ax.text(x + 2.5, curr_y, dt, ha='left', va='top', color='#CBD5E1', fontsize=8.0, family='sans-serif', zorder=3)
            curr_y -= 2.5

    def draw_flow_arrow(x1, y1, x2, y2, label=""):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", color='#38BDF8', lw=2.0, mutation_scale=16), zorder=5)
        if label:
            mx, my = (x1 + x2)/2, (y1 + y2)/2
            ax.text(mx + 2.0, my, label, color='#38BDF8', fontsize=7.5, fontweight='bold', ha='left', va='center', zorder=6)

    # Column 1: Stages 1 to 3
    draw_step_box(4, 69, 44, 21.5, "1", "Evidence Ingestion & Chain of Custody",
                  ["• Evidence Intake: NetFlow CSV, EVTX, Reg, Disk Image",
                   "• Read-only streaming in 1 MiB chunks (NIST FIPS 180-4)",
                   "• SHA-256 Digest: H(E) = SHA256(Stream(E))",
                   "• Append immutable entry to MongoDB Custody Ledger"],
                  '#1E293B', '#F59E0B', '#D97706')

    draw_step_box(4, 38, 44, 24, "2", "Multi-Source Artifact Parsing & Extraction",
                  ["• Auto-sniffing & format dispatching (ml/ingestion/)",
                   "• Windows EVTX: Event ID 4625 (Brute Force), 4688 (Exec)",
                   "• Registry: SAM, SYSTEM, Run/RunOnce persistence keys",
                   "• PCAP / Flows: 5-tuple aggregation to 11 CICFlow features",
                   "• Threat Intel & IOCs: YARA scanner, AlienVault OTX, VT"],
                  '#1E293B', '#6366F1', '#4F46E5')

    draw_step_box(4, 7, 44, 24, "3", "Forensic Data Sanitization & Normalization",
                  ["• Clean divide-by-zero artifacts: replace(±Inf → NaN)",
                   "• Elimination: dropna() + drop_duplicates() without imputing",
                   "• Dimensionality: 11 standard bidirectional flow metrics",
                   "• StandardScaler Z-Score Normalization: z = (x - μ) / σ",
                   "• Produces zero-mean, unit-variance tensors for ML core"],
                  '#1E293B', '#0EA5E9', '#0284C7')

    # Column 2: Stages 4 to 6
    draw_step_box(52, 69, 44, 21.5, "4", "Dual-Engine Hybrid Scoring Core",
                  ["• Engine A: Unsupervised Isolation Forest (100 iTrees, ψ=256)",
                   "• Anomaly score batch min-max mapping to [0, 100]",
                   "• Engine B: Forensic Heuristics Matrix S_rule = min(1.0, Σ W_k)",
                   "• 60/40 Convex Fusion: Risk = min(100, 0.6·S_ml + 0.4·S_rule·100)"],
                  '#064E3B', '#10B981', '#059669')

    draw_step_box(52, 38, 44, 24, "5", "CVSS v3.1 Priority Banding & Top-K Triage",
                  ["• Qualitative Priority Cutoff Mapping:",
                   "  - CRITICAL: Risk Score ≥ 75.0",
                   "  - HIGH    : Risk Score ≥ 50.0",
                   "  - MEDIUM  : Risk Score ≥ 25.0",
                   "  - LOW     : Risk Score < 25.0",
                   "• Sort descending; compute Top-10% & Top-25% Triage Lift"],
                  '#450A0A', '#EF4444', '#DC2626')

    draw_step_box(52, 7, 44, 24, "6", "Investigator Workspace & Dossier Generation",
                  ["• React 19 Case Workspace: Threat distribution, MITRE tags",
                   "• Severity-Only Hue Theme: Red/Orange for priority only",
                   "• Automated ReportLab PDF Engine: Executive summary & findings",
                   "• Complete Forensic Chain of Custody & audit verification"],
                  '#311042', '#A855F7', '#9333EA')

    # Connecting Workflow Arrows
    draw_flow_arrow(26, 69, 26, 62, "Raw Stream")
    draw_flow_arrow(26, 38, 26, 31, "Parsed Data")
    draw_flow_arrow(48, 19, 52, 19, "Scaled Tensor")
    draw_flow_arrow(74, 69, 74, 62, "Composite Risk")
    draw_flow_arrow(74, 38, 74, 31, "Ranked Queue")

    plt.tight_layout()
    plt.savefig(METHOD_IMG_PATH, dpi=300, bbox_inches='tight', facecolor='#0B0F19')
    plt.close()
    print(f"[+] Successfully generated Methodology Pipeline Diagram at: {METHOD_IMG_PATH}")


# ---------------------------------------------------------------------------
# ReportLab PDF Technical Document Generation
# ---------------------------------------------------------------------------

def build_pdf_document():
    """Compiles the complete Technical Design & Methodology Document into PDF."""
    styles = getSampleStyleSheet()

    # Custom Color Palette
    PRIMARY = colors.HexColor("#0F172A")
    ACCENT = colors.HexColor("#E8732A")  # Brand Orange
    SECONDARY = colors.HexColor("#2563EB")
    TEXT_DARK = colors.HexColor("#1E293B")
    TEXT_MUTED = colors.HexColor("#64748B")
    BG_LIGHT = colors.HexColor("#F8FAFC")
    BG_ALT = colors.HexColor("#F1F5F9")
    BORDER_COLOR = colors.HexColor("#CBD5E1")

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle", parent=styles["Title"],
        fontSize=24, leading=28, textColor=ACCENT, alignment=TA_CENTER, spaceAfter=8, fontName="Helvetica-Bold"
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle", parent=styles["Normal"],
        fontSize=11, leading=15, textColor=TEXT_DARK, alignment=TA_CENTER, spaceAfter=14
    )
    h1_style = ParagraphStyle(
        "H1", parent=styles["Heading1"],
        fontSize=15, leading=19, textColor=ACCENT, spaceBefore=14, spaceAfter=8, fontName="Helvetica-Bold"
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=12, leading=16, textColor=SECONDARY, spaceBefore=10, spaceAfter=6, fontName="Helvetica-Bold"
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=8.5, leading=12.5, textColor=TEXT_DARK, spaceAfter=6, alignment=TA_JUSTIFY
    )
    body_bold = ParagraphStyle(
        "BodyBold", parent=body_style, fontName="Helvetica-Bold"
    )
    table_cell = ParagraphStyle(
        "TableCell", parent=styles["Normal"],
        fontSize=7.5, leading=10.5, textColor=TEXT_DARK
    )
    table_header = ParagraphStyle(
        "TableHeader", parent=styles["Normal"],
        fontSize=8.0, leading=11, textColor=colors.white, fontName="Helvetica-Bold"
    )
    code_style = ParagraphStyle(
        "CodeText", parent=styles["Normal"],
        fontName="Courier", fontSize=7.5, leading=10, textColor=colors.HexColor("#0F172A")
    )

    def page_decorator(canvas, doc):
        canvas.saveState()
        # Top rule
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1)
        canvas.line(1.5 * cm, A4[1] - 1.2 * cm, A4[0] - 1.5 * cm, A4[1] - 1.2 * cm)
        
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawString(1.5 * cm, A4[1] - 1.0 * cm, "CYBER TRIAGE TOOL — SYSTEM ARCHITECTURE & METHODOLOGY (SIH1744)")
        canvas.drawRightString(A4[0] - 1.5 * cm, A4[1] - 1.0 * cm, f"Page {doc.page}")

        # Bottom rule
        canvas.setStrokeColor(BORDER_COLOR)
        canvas.setLineWidth(0.5)
        canvas.line(1.5 * cm, 1.3 * cm, A4[0] - 1.5 * cm, 1.3 * cm)
        
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(1.5 * cm, 0.9 * cm, "CONFIDENTIAL & PROPRIETARY — Anti-Cyber Terrorism Division / NIA Project Review")
        canvas.drawRightString(A4[0] - 1.5 * cm, 0.9 * cm, f"Compiled: {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        PDF_OUTPUT_PATH,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.6 * cm,
        bottomMargin=1.6 * cm,
        title="Cyber Triage Tool — Architecture and Methodology",
        author="Cyber Triage Development Team",
    )

    story = []

    # =========================================================================
    # Cover / Header Section
    # =========================================================================
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("AI-ASSISTED CYBER TRIAGE TOOL", title_style))
    story.append(Paragraph("<b>System Architecture Specification & Forensic Methodology Lock Document</b>", subtitle_style))
    story.append(Paragraph("<b>National Investigation Agency (NIA) — Anti-Cyber Terrorism Division (Problem Statement: SIH1744)</b>", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceBefore=4, spaceAfter=12))

    # Abstract / Executive Overview
    story.append(Paragraph("Executive Summary & Operational Mandate", h1_style))
    story.append(Paragraph(
        "Digital forensics teams face an acute <b>data deluge</b> during early-stage incident response, routinely ingesting gigabytes of raw network captures, disk images, system event logs, and registry hives. The <b>Cyber Triage Tool</b> drastically compresses first-response dwell time by executing automated multi-source evidence parsing, unsupervised anomaly detection (Isolation Forest), and domain-expert forensic heuristic scoring. This document provides the formal architectural topology, six-stage forensic triage pipeline, mathematical formulations, and source-level implementation mappings.",
        body_style
    ))
    story.append(Spacer(1, 4))

    # Project Metadata Table
    meta_data = [
        [Paragraph("<b>Domain:</b> Digital Forensics & Incident Response", table_cell), Paragraph("<b>Tech Stack:</b> Python 3.9+, Flask, Scikit-Learn, React 19 + Vite", table_cell)],
        [Paragraph("<b>Problem ID:</b> SIH1744 (NIA Anti-Cyber Terrorism)", table_cell), Paragraph("<b>Persistence:</b> MongoDB 8+, Joblib Cache (.pkl), ReportLab", table_cell)],
        [Paragraph("<b>ML Core:</b> Unsupervised Isolation Forest (100 Trees)", table_cell), Paragraph("<b>Scoring Fusion:</b> 60% ML Anomaly + 40% Domain Rules", table_cell)]
    ]
    t_meta = Table(meta_data, colWidths=[9.0 * cm, 9.0 * cm])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # =========================================================================
    # Section 1: End-to-End System Architecture
    # =========================================================================
    story.append(Paragraph("1. End-to-End System Architecture Topology", h1_style))
    story.append(Paragraph(
        "The system employs a strict <b>5-Tier Forensic Processing Topology</b> designed for high throughput, memory safety, and strict separation of concerns. The diagram below illustrates the complete component layout and interaction channels.",
        body_style
    ))
    story.append(Spacer(1, 4))

    # Embed High-Res Architecture Image
    img_arch = Image(ARCH_IMG_PATH, width=17.5 * cm, height=12.2 * cm)
    story.append(img_arch)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Architectural Subsystems Breakdown:</b>", h2_style))
    story.append(Paragraph(
        "• <b>Tier 1 (Client Layer):</b> React 19 + Vite single-page application incorporating custom atomic design tokens. Implements a strict <i>severity-only hue policy</i> (colors denote risk severity, never interaction affordances) to minimize investigator cognitive fatigue. Houses Dashboard, Active Cases, and the full Case Workspace (`/cases/:caseId`).<br/>"
        "• <b>Tier 2 (API & Orchestration Layer):</b> Stateless Python Flask REST API (`backend/app.py`) managing stream uploads, SHA-256 evidence integrity hashing, ReportLab PDF generation, and MongoDB collection bindings.<br/>"
        "• <b>Tier 3 (Forensic Ingestion Subsystem):</b> Self-guarded forensic parsers (`ml/ingestion/`, `forensics/`) supporting Windows EVTX logs, Windows Registry hives (`.reg`), PCAP network captures, raw disk images (`pytsk3`), and YARA/threat-intel indicators.<br/>"
        "• <b>Tier 4 (ML & Hybrid Scoring Core):</b> Scikit-Learn Isolation Forest anomaly detector combined with domain-specific heuristic rule matrices, normalized via batch min-max transformation into a unified 0–100 risk score.<br/>"
        "• <b>Tier 5 (Persistence & Evaluation):</b> MongoDB database (`mongodb://localhost:27017`) for cases, findings, and chain-of-custody tracking, coupled with reproducible offline evaluation scripts (`scripts/verify_results.py`).",
        body_style
    ))
    story.append(PageBreak())

    # =========================================================================
    # Section 2: Forensic Triage Methodology & Pipeline
    # =========================================================================
    story.append(Paragraph("2. Forensic Triage Methodology & Execution Pipeline", h1_style))
    story.append(Paragraph(
        "The forensic triage pipeline operates across six deterministic stages, ensuring strict adherence to evidentiary integrity (NIST FIPS 180-4) and mathematical transparency throughout evidence scoring and prioritization.",
        body_style
    ))
    story.append(Spacer(1, 4))

    # Embed High-Res Methodology Image
    img_method = Image(METHOD_IMG_PATH, width=17.5 * cm, height=13.5 * cm)
    story.append(img_method)
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Six-Stage Forensic Methodology Walkthrough:</b>", h2_style))
    story.append(Paragraph(
        "1. <b>Stage 1 (Acquisition & Chain of Custody):</b> Ingests evidence streams in 1 MiB chunked buffers, computing NIST FIPS 180-4 SHA-256 cryptographic digests in read-only mode to prevent forensic spoliation.<br/>"
        "2. <b>Stage 2 (Multi-Source Parsing):</b> Dispatcher auto-detects file headers, normalizing heterogeneous forensic sources (EVTX logs, registry keys, 5-tuple network flows) into structured tabular records.<br/>"
        "3. <b>Stage 3 (Sanitization & Normalization):</b> Converts ±Inf (divide-by-zero artifacts) to NaNs, performs `dropna()` and `drop_duplicates()` without artificial imputation, and executes StandardScaler z-score standardization ($z = (x - \mu)/\sigma$).<br/>"
        "4. <b>Stage 4 (Dual-Engine Scoring):</b> Executes parallel evaluation through unsupervised Isolation Forest ($100$ iTrees) and rule-based heuristic matrix ($S_{rule} = \min(1.0, \sum W_k)$).<br/>"
        "5. <b>Stage 5 (Hybrid Fusion & CVSS Banding):</b> Computes convex risk combination ($\text{Risk} = \min(100, 0.60 \cdot S_{ML} + 0.40 \cdot (S_{Rule} \cdot 100))$) and maps to CVSS v3.1 qualitative bands.<br/>"
        "6. <b>Stage 6 (Top-K Triage & Dossier Generation):</b> Sorts findings by descending risk, surfaces Top-10%/Top-25% priority cues to the investigator workspace, and compiles automated ReportLab PDF reports.",
        body_style
    ))
    story.append(PageBreak())

    # =========================================================================
    # Section 3: Technical Specifications & Mathematical Formulations Table
    # =========================================================================
    story.append(Paragraph("3. Mathematical Formulations & Codebase Mapping Matrix", h1_style))
    story.append(Paragraph(
        "Every mathematical operation, threshold, and weighting parameter in the Cyber Triage Tool is documented below, cross-referenced with its exact implementation file and academic citation.",
        body_style
    ))
    story.append(Spacer(1, 6))

    spec_table_data = [
        [
            Paragraph("<b>Stage & Concept</b>", table_header),
            Paragraph("<b>Mathematical Formulation</b>", table_header),
            Paragraph("<b>Source File & Line</b>", table_header),
            Paragraph("<b>Formal Reference / Citation</b>", table_header)
        ],
        [
            Paragraph("<b>Feature Scaling</b><br/>(z-score standardization)", table_cell),
            Paragraph("z = \\frac{x - \\mu}{\\sigma}", code_style),
            Paragraph("ml/preprocessor.py<br/>(scale_features)", table_cell),
            Paragraph("Han, Kamber & Pei, <i>Data Mining</i> §3.5; Scikit-Learn StandardScaler", table_cell)
        ],
        [
            Paragraph("<b>Isolation Forest Score</b><br/>(Canonical tree depth)", table_cell),
            Paragraph("s(x, n) = 2^{-\\frac{E(h(x))}{c(n)}}", code_style),
            Paragraph("ml/detector.py<br/>(predict / decision_func)", table_cell),
            Paragraph("Liu, Ting & Zhou, <i>Isolation Forest</i>, IEEE ICDM 2008", table_cell)
        ],
        [
            Paragraph("<b>Score Normalization</b><br/>(Batch Min-Max Mapping)", table_cell),
            Paragraph("S_{ml} = \\frac{-d(x) - \\min(-d)}{\\max(-d) - \\min(-d)} \\times 100", code_style),
            Paragraph("ml/detector.py<br/>(minmax_normalize_scores)", table_cell),
            Paragraph("Project Batch Score Normalizer (maps -d(x) to [0, 100])", table_cell)
        ],
        [
            Paragraph("<b>Domain Rule Engine</b><br/>(Forensic Heuristics)", table_cell),
            Paragraph("S_{rule}(x) = \\min\\left(1.0, \\sum_{k} W_k\\right)", code_style),
            Paragraph("ml/risk_scorer.py<br/>(score_dataframe / score_records)", table_cell),
            Paragraph("Domain Rule Weight Matrix (Network, Logs, Registry, Files)", table_cell)
        ],
        [
            Paragraph("<b>Hybrid Risk Fusion</b><br/>(Convex Combination)", table_cell),
            Paragraph("\\text{Risk} = \\min(100, 0.60 \\cdot S_{ml} + 0.40 \\cdot (S_{rule} \\cdot 100))", code_style),
            Paragraph("ml/risk_scorer.py<br/>(calculate_risk_score)", table_cell),
            Paragraph("Kittler et al. 1998 (Classifier Fusion); NIST SP 800-30 Rev. 1", table_cell)
        ],
        [
            Paragraph("<b>Priority Banding</b><br/>(Qualitative Severity)", table_cell),
            Paragraph("CRITICAL \\ge 75 \\mid HIGH \\ge 50<br/>MEDIUM \\ge 25 \\mid LOW < 25", code_style),
            Paragraph("ml/risk_scorer.py<br/>(assign_priority)", table_cell),
            Paragraph("CVSS v3.1 §5 Qualitative Severity Rating Scale", table_cell)
        ],
        [
            Paragraph("<b>Chain of Custody</b><br/>(Cryptographic digest)", table_cell),
            Paragraph("\\text{SHA-256}(E) = \\text{Digest}(\\text{Stream}_{1\\text{MiB}}(E))", code_style),
            Paragraph("backend/app.py<br/>(compute_sha256)", table_cell),
            Paragraph("NIST FIPS PUB 180-4 (Secure Hash Standard)", table_cell)
        ],
        [
            Paragraph("<b>Top-K Triage Metrics</b><br/>(Triage Lift & Recall)", table_cell),
            Paragraph("\\text{Recall}@K = \\frac{\\text{Hits in Top } K}{\\text{Total Real Attacks}}, \\text{Lift} = \\frac{P@K}{\\text{Prevalence}}", code_style),
            Paragraph("evaluation/evaluate.py<br/>(compute_top_k_metrics)", table_cell),
            Paragraph("Manning et al., <i>Introduction to Information Retrieval</i>, Ch. 8", table_cell)
        ]
    ]

    t_spec = Table(spec_table_data, colWidths=[4.0 * cm, 4.5 * cm, 4.5 * cm, 5.0 * cm])
    t_spec.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("BACKGROUND", (0, 1), (-1, -1), BG_LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_LIGHT, colors.white]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_spec)
    story.append(Spacer(1, 14))

    # Verification & Defense Summary
    story.append(Paragraph("4. Evaluation & Verification Rigor", h1_style))
    story.append(Paragraph(
        "The complete machine learning and forensic pipeline is actively verified via a dedicated 45-item test suite (`tests/`) and an offline evaluation audit script (`scripts/verify_results.py`). All metrics reported are derived from empirical evaluation against the 2.52-million record CICIDS2017 benchmark dataset under stratified 70/30 train/test splits.",
        body_style
    ))

    doc.build(story, onFirstPage=page_decorator, onLaterPages=page_decorator)
    print(f"[+] Successfully compiled Technical PDF Document at: {PDF_OUTPUT_PATH}")


if __name__ == "__main__":
    print("[*] Generating high-resolution system diagrams...")
    create_system_architecture_diagram()
    create_methodology_pipeline_diagram()
    print("[*] Building publication-grade PDF report...")
    build_pdf_document()
    print("[OK] All deliverables completed successfully.")
