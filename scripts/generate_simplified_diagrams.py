"""
Simplified & Streamlined System Architecture & Forensic Methodology Diagram Generator.
Produces clean, high-contrast, publication-grade assets and compiles an executive PDF.

Outputs:
  - reports/Cyber_Triage_Simplified_Architecture_and_Methodology.pdf
  - reports/artifacts/system_architecture_simple.png
  - reports/artifacts/methodology_pipeline_simple.png
  - reports/CyberTriage_Architecture_Diagrams_Simplified.html
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak,
    HRFlowable
)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
ARTIFACTS_DIR = os.path.join(REPORTS_DIR, "artifacts")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

ARCH_SIMPLE_PNG = os.path.join(ARTIFACTS_DIR, "system_architecture_simple.png")
METHOD_SIMPLE_PNG = os.path.join(ARTIFACTS_DIR, "methodology_pipeline_simple.png")
PDF_OUTPUT_PATH = os.path.join(REPORTS_DIR, "Cyber_Triage_Simplified_Architecture_and_Methodology.pdf")
HTML_OUTPUT_PATH = os.path.join(REPORTS_DIR, "CyberTriage_Architecture_Diagrams_Simplified.html")

# ---------------------------------------------------------------------------
# 1. Simplified Architecture Diagram (Matplotlib)
# ---------------------------------------------------------------------------
def generate_simple_architecture_img():
    fig, ax = plt.subplots(figsize=(12, 8), dpi=300)
    fig.patch.set_facecolor('#0F172A')
    ax.set_facecolor('#0F172A')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Title
    ax.text(50, 96, "CYBER TRIAGE TOOL — SIMPLIFIED SYSTEM ARCHITECTURE", 
            ha='center', va='center', color='#F8FAFC', fontsize=14, fontweight='bold')
    ax.text(50, 93, "High-Level Multi-Tier Forensic Triage & Scoring Topology (SIH1744)", 
            ha='center', va='center', color='#94A3B8', fontsize=9.5)

    def draw_card(x, y, w, h, title, subtitle, items, bg='#1E293B', border='#38BDF8', title_color='#38BDF8'):
        box = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.0",
                                     facecolor=bg, edgecolor=border, linewidth=1.5, zorder=2)
        ax.add_patch(box)
        ax.text(x + w/2, y + h - 2.2, title, ha='center', va='top', color=title_color, fontsize=10, fontweight='bold', zorder=3)
        if subtitle:
            ax.text(x + w/2, y + h - 5.0, subtitle, ha='center', va='top', color='#94A3B8', fontsize=7.5, style='italic', zorder=3)
        
        curr_y = y + h - (7.5 if subtitle else 5.2)
        for it in items:
            ax.text(x + 2.0, curr_y, it, ha='left', va='top', color='#E2E8F0', fontsize=8.0, zorder=3)
            curr_y -= 2.6

    def draw_arrow(x1, y1, x2, y2, label='', color='#38BDF8'):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=1.6, mutation_scale=14), zorder=4)
        if label:
            mx, my = (x1 + x2)/2, (y1 + y2)/2
            ax.text(mx, my + 1.2, label, color='#F8FAFC', fontsize=7.5, ha='center', va='bottom',
                    bbox=dict(boxstyle='round,pad=0.2', facecolor='#0F172A', edgecolor=color, lw=0.8), zorder=5)

    # 1. Tier 1: Client
    draw_card(4, 68, 92, 22, "1. INVESTIGATOR CLIENT LAYER (React 19 + Vite)", 
              "Single Page Application with Severity-Only Hue Styling",
              ["• Dashboard & Active Investigations View", 
               "• Case Workspace (/cases/:caseId) with 8-Tab Forensic Strip",
               "• API Client Service Layer (services/apiClient.js) with Mock Fallback"],
              bg='#1E293B', border='#818CF8', title_color='#A5B4FC')

    # 2. Tier 2: API
    draw_card(4, 38, 92, 22, "2. API & ORCHESTRATION LAYER (Flask :5001)", 
              "Lightweight RESTful Backend (backend/app.py)",
              ["• REST Routes: /api/analyze, /api/forensics/ingest, /api/cases, /api/report",
               "• Chain of Custody: NIST FIPS 180-4 SHA-256 Chunked Streaming Intake",
               "• ReportLab Automated PDF Dossier Generator (backend/report_generator.py)"],
              bg='#1E293B', border='#38BDF8', title_color='#7DD3FC')

    # 3. Tier 3: Core Processing (3 Columns)
    draw_card(4, 6, 29, 24, "3. FORENSIC PARSERS", "ml/ingestion/ & forensics/",
              ["• EVTX (Event 4625)", "• Registry (.reg Hives)", "• PCAP (5-Tuple Flows)", "• Disk Images (pytsk3)", "• YARA + Threat Intel"],
              bg='#1E293B', border='#F59E0B', title_color='#FBBF24')

    draw_card(35.5, 6, 29, 24, "4. AI & HYBRID SCORER", "ml/ (Engine Core)",
              ["• Preprocessor (z-scores)", "• Isolation Forest (100 Trees)", "• Domain Heuristic Rules", "• 60/40 Risk Fusion", "• CVSS Priority Bands"],
              bg='#064E3B', border='#10B981', title_color='#6EE7B7')

    draw_card(67, 6, 29, 24, "5. PERSISTENCE & EVAL", "MongoDB & Storage",
              ["• MongoDB (cases, custody)", "• Serialized Model (.pkl)", "• Evaluation results.json", "• Top-K Triage Metrics", "• Generated PDF Dossiers"],
              bg='#311042', border='#F43F5E', title_color='#FDA4AF')

    # Arrows
    draw_arrow(50, 68, 50, 60, "REST / JSON (:5173 ➔ :5001)")
    draw_arrow(18.5, 38, 18.5, 30, "Raw Stream")
    draw_arrow(33, 18, 35.5, 18, "DataFrames")
    draw_arrow(64.5, 18, 67, 18, "Store & Scored")
    draw_arrow(50, 30, 50, 38, "Ranked Findings", color='#10B981')

    plt.tight_layout()
    plt.savefig(ARCH_SIMPLE_PNG, dpi=300, bbox_inches='tight', facecolor='#0F172A')
    plt.close()
    print(f"[+] Generated Simplified Architecture Diagram: {ARCH_SIMPLE_PNG}")


# ---------------------------------------------------------------------------
# 2. Simplified Methodology Diagram (Matplotlib)
# ---------------------------------------------------------------------------
def generate_simple_methodology_img():
    fig, ax = plt.subplots(figsize=(12, 8.5), dpi=300)
    fig.patch.set_facecolor('#0F172A')
    ax.set_facecolor('#0F172A')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Title
    ax.text(50, 96.5, "CYBER TRIAGE TOOL — SIMPLIFIED FORENSIC METHODOLOGY", 
            ha='center', va='center', color='#F8FAFC', fontsize=14, fontweight='bold')
    ax.text(50, 93.5, "Six-Stage End-to-End Forensic Triage & Prioritization Pipeline", 
            ha='center', va='center', color='#94A3B8', fontsize=9.5)

    def draw_step(x, y, w, h, stage_num, title, details, border_col='#38BDF8', badge_col='#0284C7'):
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=0.8",
                                      facecolor='#1E293B', edgecolor=border_col, linewidth=1.5, zorder=2)
        ax.add_patch(rect)
        # Badge
        badge = patches.FancyBboxPatch((x + 1.2, y + h - 2.8), 14, 2.2, boxstyle="round,pad=0.2,rounding_size=0.5",
                                       facecolor=badge_col, edgecolor='none', zorder=3)
        ax.add_patch(badge)
        ax.text(x + 8.2, y + h - 1.7, f"STAGE {stage_num}", ha='center', va='center', color='#FFFFFF', fontsize=7.5, fontweight='bold', zorder=4)
        
        ax.text(x + 16.5, y + h - 1.7, title, ha='left', va='center', color='#F8FAFC', fontsize=9.0, fontweight='bold', zorder=3)
        
        curr_y = y + h - 4.8
        for dt in details:
            ax.text(x + 2.0, curr_y, dt, ha='left', va='top', color='#CBD5E1', fontsize=7.6, zorder=3)
            curr_y -= 2.3

    def draw_arrow(x1, y1, x2, y2, label=''):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", color='#38BDF8', lw=1.6, mutation_scale=13), zorder=4)
        if label:
            mx, my = (x1 + x2)/2, (y1 + y2)/2
            ax.text(mx, my + 1.0, label, color='#38BDF8', fontsize=7.2, fontweight='bold', ha='center', va='bottom', zorder=5)

    # 6 Steps in a clean 2x3 Grid
    # Row 1 (Left to Right: Stages 1, 2, 3)
    draw_step(4, 52, 28, 36, "1", "Ingest & Hash",
              ["• Multi-Evidence Intake", "• 1 MiB Chunk Streaming", "• NIST SHA-256 Digest", "• Custody Ledger Entry"],
              border_col='#F59E0B', badge_col='#D97706')

    draw_step(36, 52, 28, 36, "2", "Parse Artifacts",
              ["• Format Auto-Sniffing", "• EVTX (Event 4625)", "• Registry Run Keys", "• PCAP 5-Tuple Flows", "• Raw Disk Images"],
              border_col='#6366F1', badge_col='#4F46E5')

    draw_step(68, 52, 28, 36, "3", "Clean & Standardize",
              ["• Convert ±Inf ➔ NaN", "• dropna() + de-dupe", "• 11 Flow Features", "• StandardScaler z-score:", "  z = (x - μ) / σ"],
              border_col='#0EA5E9', badge_col='#0284C7')

    # Row 2 (Right to Left / Continuous Flow: Stages 4, 5, 6)
    draw_step(68, 10, 28, 34, "4", "Dual ML/Rule Scoring",
              ["• Isolation Forest (100 Trees)", "  Min-Max S_anomaly [0,100]", "• Heuristic Matrix: S_rule", "• 60/40 Convex Fusion:", "  Risk = 0.6·S_ml + 0.4·S_rule"],
              border_col='#10B981', badge_col='#059669')

    draw_step(36, 10, 28, 34, "5", "CVSS v3.1 Banding",
              ["• Qualitative Priorities:", "  • CRITICAL: Risk ≥ 75", "  • HIGH:     Risk ≥ 50", "  • MEDIUM:   Risk ≥ 25", "  • LOW:      Risk < 25"],
              border_col='#EF4444', badge_col='#DC2626')

    draw_step(4, 10, 28, 34, "6", "Triage & Reporting",
              ["• Top-K Priority Queue", "• React Case Workspace", "• MITRE ATT&CK Mapping", "• ReportLab PDF Dossier"],
              border_col='#A855F7', badge_col='#9333EA')

    # Connecting Flow Arrows
    draw_arrow(32, 70, 36, 70)
    draw_arrow(64, 70, 68, 70)
    draw_arrow(82, 52, 82, 44, "Tensors")
    draw_arrow(68, 27, 64, 27)
    draw_arrow(36, 27, 32, 27)

    plt.tight_layout()
    plt.savefig(METHOD_SIMPLE_PNG, dpi=300, bbox_inches='tight', facecolor='#0F172A')
    plt.close()
    print(f"[+] Generated Simplified Methodology Diagram: {METHOD_SIMPLE_PNG}")


# ---------------------------------------------------------------------------
# 3. Simplified HTML Generator
# ---------------------------------------------------------------------------
def generate_simple_html():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cyber Triage Tool — Simplified Architecture & Methodology (SIH1744)</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"></script>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #0F172A; background: #F8FAFC; margin: 0; padding: 24px; line-height: 1.5;
  }
  .page { max-width: 960px; margin: 0 auto; background: #FFFFFF; padding: 32px 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
  h1 { font-size: 24px; margin: 0 0 4px; color: #0C4A6E; }
  .sub { color: #475569; font-size: 13.5px; margin-bottom: 24px; }
  h2 { font-size: 18px; color: #1E293B; border-bottom: 2px solid #E2E8F0; padding-bottom: 6px; margin: 32px 0 16px; }
  .diagram { border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; background: #FFFFFF; overflow-x: auto; text-align: center; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 12px; }
  th, td { border: 1px solid #E2E8F0; padding: 8px 10px; text-align: left; }
  th { background: #0F172A; color: #FFFFFF; }
  tr:nth-child(even) td { background: #F8FAFC; }
  code { background: #E2E8F0; padding: 1px 4px; border-radius: 4px; font-size: 11.5px; }
</style>
</head>
<body>
<div class="page">
  <h1>Cyber Triage Tool for Digital Forensic Investigation</h1>
  <div class="sub">SIH1744 · National Investigation Agency (Anti-Cyber Terrorism) · Simplified Architecture &amp; Methodology</div>

  <h2>1. Simplified System Architecture Diagram</h2>
  <div class="diagram">
<pre class="mermaid">
flowchart TD
    CLIENT["<b>Investigator Client Layer</b><br/>React 19 + Vite SPA | /cases/:id Workspace | Severity-Only Hue"]
    API["<b>API & Orchestration Layer</b><br/>Flask :5001 | SHA-256 Ingest | ReportLab PDF Generator"]
    
    subgraph ENGINE ["Forensic Ingestion & ML Scoring Core"]
        direction LR
        PARSE["<b>Forensic Parsers</b><br/>EVTX | Registry | PCAP | Disk (.dd)"]
        PRE["<b>Preprocessor</b><br/>Clean NaNs + StandardScaler z-score"]
        SCORER["<b>Hybrid Risk Scorer</b><br/>60% Isolation Forest + 40% Rules<br/>CVSS Bands (CRITICAL ≥ 75)"]
        PARSE --> PRE --> SCORER
    end

    STORE[("<b>Persistence Layer</b><br/>MongoDB :27017 | .pkl Model Cache")]

    CLIENT <==>|"REST / JSON"| API
    API ==>|"Raw Stream"| PARSE
    SCORER ==>|"Ranked Artifacts"| API
    API <-->|"Cases & Custody"| STORE
    SCORER <-->|"Cache Model"| STORE

    classDef client fill:#0EA5E9,stroke:#0369A1,color:#FFF;
    classDef api fill:#6366F1,stroke:#4338CA,color:#FFF;
    classDef engine fill:#065F46,stroke:#047857,color:#FFF;
    classDef store fill:#311042,stroke:#4A044E,color:#FFF;

    class CLIENT client;
    class API api;
    class PARSE,PRE,SCORER engine;
    class STORE store;
</pre>
  </div>

  <h2>2. Simplified Forensic Methodology Flowchart</h2>
  <div class="diagram">
<pre class="mermaid">
flowchart TD
    S1["<b>Stage 1: Ingest & SHA-256</b><br/>NIST FIPS 180-4 Read-Only Chunk Digest"] --> S2["<b>Stage 2: Parse Artifacts</b><br/>EVTX, Registry, PCAP Flows, Disk Images"]
    S2 --> S3["<b>Stage 3: Clean & Standardize</b><br/>Drop NaNs/Inf, Extract 11 Features, StandardScaler (z=(x-μ)/σ)"]
    S3 --> S4["<b>Stage 4: Dual Scoring Engine</b><br/>Isolation Forest (60%) + Domain Rules (40%)"]
    S4 --> S5["<b>Stage 5: CVSS v3.1 Banding</b><br/>CRITICAL ≥ 75 | HIGH ≥ 50 | MEDIUM ≥ 25 | LOW &lt; 25"]
    S5 --> S6["<b>Stage 6: Triage & Reporting</b><br/>Top-K Findings Queue ➔ React Workspace ➔ PDF Report"]

    classDef step fill:#1E293B,stroke:#0F172A,color:#F8FAFC;
    class S1,S2,S3,S4,S5,S6 step;
</pre>
  </div>

  <h2>3. Key Formulation & Codebase Mapping</h2>
  <table>
    <thead><tr><th>Component</th><th>Formula / Method</th><th>Source File</th></tr></thead>
    <tbody>
      <tr><td>Feature Scaling</td><td><code>z = (x - μ) / σ</code> (StandardScaler)</td><td><code>ml/preprocessor.py</code></td></tr>
      <tr><td>Anomaly Detector</td><td>Isolation Forest (100 iTrees, ψ=256) ➔ Batch Min-Max</td><td><code>ml/detector.py</code></td></tr>
      <tr><td>Hybrid Fusion</td><td><code>Risk = min(100, 0.60·S_ml + 0.40·(S_rule·100))</code></td><td><code>ml/risk_scorer.py</code></td></tr>
      <tr><td>Priority Bands</td><td>CRITICAL ≥ 75, HIGH ≥ 50, MEDIUM ≥ 25, LOW &lt; 25</td><td><code>ml/risk_scorer.py</code></td></tr>
      <tr><td>Evidence Hashing</td><td>SHA-256 streamed read-only in 1 MiB buffers</td><td><code>backend/app.py</code></td></tr>
    </tbody>
  </table>
</div>
<script>
  mermaid.initialize({ startOnLoad: true, theme: "default" });
</script>
</body>
</html>
"""
    with open(HTML_OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Generated Simplified HTML: {HTML_OUTPUT_PATH}")


# ---------------------------------------------------------------------------
# 4. Simplified PDF Document Builder
# ---------------------------------------------------------------------------
def build_simplified_pdf():
    styles = getSampleStyleSheet()
    ACCENT = colors.HexColor("#E8732A")
    TEXT_DARK = colors.HexColor("#0F172A")
    TEXT_MUTED = colors.HexColor("#64748B")
    BG_LIGHT = colors.HexColor("#F8FAFC")
    BORDER_COLOR = colors.HexColor("#CBD5E1")

    title_style = ParagraphStyle("T", parent=styles["Title"], fontSize=20, leading=24, textColor=ACCENT, alignment=TA_CENTER, fontName="Helvetica-Bold")
    sub_style = ParagraphStyle("S", parent=styles["Normal"], fontSize=10, leading=14, textColor=TEXT_DARK, alignment=TA_CENTER, spaceAfter=10)
    h1_style = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=13, leading=16, textColor=ACCENT, spaceBefore=10, spaceAfter=6, fontName="Helvetica-Bold")
    body_style = ParagraphStyle("B", parent=styles["Normal"], fontSize=8.0, leading=11.5, textColor=TEXT_DARK, spaceAfter=4, alignment=TA_JUSTIFY)
    table_cell = ParagraphStyle("TC", parent=styles["Normal"], fontSize=7.2, leading=9.5, textColor=TEXT_DARK)
    table_header = ParagraphStyle("TH", parent=styles["Normal"], fontSize=7.5, leading=10, textColor=colors.white, fontName="Helvetica-Bold")

    def page_decorator(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1)
        canvas.line(1.5 * cm, A4[1] - 1.2 * cm, A4[0] - 1.5 * cm, A4[1] - 1.2 * cm)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(TEXT_MUTED)
        canvas.drawString(1.5 * cm, A4[1] - 1.0 * cm, "CYBER TRIAGE TOOL — SIMPLIFIED ARCHITECTURE & METHODOLOGY (SIH1744)")
        canvas.drawRightString(A4[0] - 1.5 * cm, A4[1] - 1.0 * cm, f"Page {doc.page}")
        canvas.setStrokeColor(BORDER_COLOR)
        canvas.setLineWidth(0.5)
        canvas.line(1.5 * cm, 1.3 * cm, A4[0] - 1.5 * cm, 1.3 * cm)
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(1.5 * cm, 0.9 * cm, "CONFIDENTIAL — Anti-Cyber Terrorism Division / NIA Project Review")
        canvas.drawRightString(A4[0] - 1.5 * cm, 0.9 * cm, f"Generated: {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        PDF_OUTPUT_PATH,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    story = [
        Spacer(1, 0.2 * cm),
        Paragraph("CYBER TRIAGE TOOL — SIMPLIFIED ARCHITECTURE", title_style),
        Paragraph("<b>Digital Forensic Investigation & Anomaly Prioritization (NIA / SIH1744)</b>", sub_style),
        HRFlowable(width="100%", thickness=1.2, color=ACCENT, spaceBefore=2, spaceAfter=8),

        Paragraph("1. Simplified System Architecture", h1_style),
        Paragraph("High-level 5-tier topology: React 19 Client ➔ Flask API ➔ Forensic Ingestion ➔ ML Core ➔ Persistence.", body_style),
        Spacer(1, 4),
        Image(ARCH_SIMPLE_PNG, width=17.5 * cm, height=11.2 * cm),
        Spacer(1, 8),
        PageBreak(),

        Paragraph("2. Simplified Forensic Methodology Flowchart", h1_style),
        Paragraph("Six-stage deterministic workflow tracing evidence intake, sanitization, scoring, and triage reporting.", body_style),
        Spacer(1, 4),
        Image(METHOD_SIMPLE_PNG, width=17.5 * cm, height=11.8 * cm),
        Spacer(1, 8),

        Paragraph("3. Core Formulation & Specification Matrix", h1_style),
    ]

    table_data = [
        [Paragraph("<b>Component</b>", table_header), Paragraph("<b>Mathematical Formulation</b>", table_header), Paragraph("<b>Source File</b>", table_header)],
        [Paragraph("<b>Feature Scaling</b>", table_cell), Paragraph("z = (x - μ) / σ (StandardScaler)", table_cell), Paragraph("ml/preprocessor.py", table_cell)],
        [Paragraph("<b>Anomaly Detector</b>", table_cell), Paragraph("Isolation Forest (100 Trees, ψ=256) ➔ Min-Max [0, 100]", table_cell), Paragraph("ml/detector.py", table_cell)],
        [Paragraph("<b>Hybrid Fusion</b>", table_cell), Paragraph("Risk = min(100, 0.60·S_ml + 0.40·(S_rule·100))", table_cell), Paragraph("ml/risk_scorer.py", table_cell)],
        [Paragraph("<b>CVSS Bands</b>", table_cell), Paragraph("CRITICAL ≥ 75, HIGH ≥ 50, MEDIUM ≥ 25, LOW < 25", table_cell), Paragraph("ml/risk_scorer.py", table_cell)],
        [Paragraph("<b>Evidence Hash</b>", table_cell), Paragraph("SHA-256 streamed read-only in 1 MiB chunks", table_cell), Paragraph("backend/app.py", table_cell)]
    ]
    t = Table(table_data, colWidths=[4.5 * cm, 8.5 * cm, 4.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("BACKGROUND", (0, 1), (-1, -1), BG_LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_LIGHT, colors.white]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    doc.build(story, onFirstPage=page_decorator, onLaterPages=page_decorator)
    print(f"[+] Compiled Simplified PDF Document: {PDF_OUTPUT_PATH}")


if __name__ == "__main__":
    generate_simple_architecture_img()
    generate_simple_methodology_img()
    generate_simple_html()
    build_simplified_pdf()
    print("[OK] All simplified deliverables ready.")
