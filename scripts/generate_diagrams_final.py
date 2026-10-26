"""
Compact, systematic System Architecture & Methodology diagrams.
Clean engineering block-diagram style — no clutter, tight labels.

Outputs:
  reports/artifacts/architecture_final.png
  reports/artifacts/methodology_final.png
  reports/Cyber_Triage_Architecture_Methodology_Final.pdf
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from datetime import datetime, timezone

from reportlab.lib import colors as rl_colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, HRFlowable,
)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "reports", "artifacts")
os.makedirs(OUT, exist_ok=True)

ARCH_PNG = os.path.join(OUT, "architecture_final.png")
METH_PNG = os.path.join(OUT, "methodology_final.png")
PDF_PATH = os.path.join(BASE, "reports", "Cyber_Triage_Architecture_Methodology_Final.pdf")

# ── colour palette ──────────────────────────────────────────────────────────
BG       = "#FFFFFF"
BORDER   = "#CBD5E1"
TEXT     = "#0F172A"
MUTED    = "#64748B"

C_CLIENT = "#DBEAFE"  ; B_CLIENT = "#2563EB"
C_API    = "#E0E7FF"  ; B_API    = "#4F46E5"
C_PARSE  = "#FEF3C7"  ; B_PARSE  = "#D97706"
C_ML     = "#D1FAE5"  ; B_ML     = "#059669"
C_STORE  = "#FCE7F3"  ; B_STORE  = "#DB2777"
C_STEP   = "#F1F5F9"  ; B_STEP   = "#334155"

SEV = {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "MEDIUM": "#2563EB", "LOW": "#16A34A"}

# ── helpers ─────────────────────────────────────────────────────────────────
def _box(ax, cx, cy, w, h, label, sub=None, fc="#F1F5F9", ec="#334155", fs=7.5, bold=True):
    """Draw a rounded box centred at (cx, cy)."""
    x0, y0 = cx - w / 2, cy - h / 2
    r = FancyBboxPatch((x0, y0), w, h,
                       boxstyle="round,pad=0.15,rounding_size=0.3",
                       facecolor=fc, edgecolor=ec, linewidth=1.0, zorder=2)
    ax.add_patch(r)
    weight = "bold" if bold else "normal"
    if sub:
        ax.text(cx, cy + 0.18, label, ha="center", va="center",
                fontsize=fs, fontweight=weight, color=TEXT, zorder=3)
        ax.text(cx, cy - 0.22, sub, ha="center", va="center",
                fontsize=fs - 1.5, color=MUTED, zorder=3)
    else:
        ax.text(cx, cy, label, ha="center", va="center",
                fontsize=fs, fontweight=weight, color=TEXT, zorder=3)

def _arrow(ax, x1, y1, x2, y2, label="", color="#64748B"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color=color, lw=1.0,
                                mutation_scale=10), zorder=4)
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mx, my, f" {label} ", ha="center", va="center",
                fontsize=5.5, color=color,
                bbox=dict(boxstyle="round,pad=0.12", fc=BG, ec=color, lw=0.5),
                zorder=5)

def _section_label(ax, x, y, text, color="#334155"):
    ax.text(x, y, text, ha="left", va="center",
            fontsize=7, fontweight="bold", color=color, zorder=5)


# ═══════════════════════════════════════════════════════════════════════════
#  DIAGRAM 1 — System Architecture (compact block diagram)
# ═══════════════════════════════════════════════════════════════════════════
def draw_architecture():
    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=300)
    ax.set_xlim(-0.5, 10.5)
    ax.set_ylim(-0.5, 8.0)
    ax.set_aspect("equal")
    ax.axis("off")
    fig.patch.set_facecolor(BG)

    # ── title ──
    ax.text(5, 7.55, "System Architecture — Cyber Triage Tool (SIH1744)",
            ha="center", va="center", fontsize=9, fontweight="bold", color=TEXT)

    # ── Tier 1  Client ──
    _section_label(ax, 0.2, 6.95, "Tier 1  Client", B_CLIENT)
    _box(ax, 2.0, 6.4, 3.0, 0.7, "Dashboard & Cases",
         "React 19 + Vite SPA", fc=C_CLIENT, ec=B_CLIENT)
    _box(ax, 5.5, 6.4, 3.0, 0.7, "Case Workspace",
         "/cases/:id  (8 tabs)", fc=C_CLIENT, ec=B_CLIENT)
    _box(ax, 8.8, 6.4, 1.6, 0.7, "apiClient.js",
         "services/", fc=C_CLIENT, ec=B_CLIENT, fs=6.5)

    # ── Tier 2  API ──
    _section_label(ax, 0.2, 5.55, "Tier 2  API", B_API)
    _box(ax, 2.3, 4.95, 3.6, 0.7, "Flask REST API",
         "/analyze  /ingest  /cases  /report", fc=C_API, ec=B_API)
    _box(ax, 6.2, 4.95, 2.2, 0.7, "SHA-256 Intake",
         "NIST FIPS 180-4", fc=C_API, ec=B_API, fs=6.8)
    _box(ax, 8.8, 4.95, 1.6, 0.7, "PDF Gen",
         "ReportLab", fc=C_API, ec=B_API, fs=6.5)

    # ── Tier 3  Parsers ──
    _section_label(ax, 0.2, 4.05, "Tier 3  Parsers", B_PARSE)
    for i, (name, lib) in enumerate([
        ("EVTX", "python-evtx"), ("Registry", "python-registry"),
        ("PCAP", "pcap_parser"), ("Disk Image", "pytsk3"),
        ("YARA / OTX", "Threat Intel"),
    ]):
        _box(ax, 1.0 + i * 2.0, 3.45, 1.7, 0.7, name, lib,
             fc=C_PARSE, ec=B_PARSE, fs=6.5)

    # ── Tier 4  ML Core ──
    _section_label(ax, 0.2, 2.55, "Tier 4  ML Core", B_ML)
    _box(ax, 1.8, 1.95, 2.6, 0.7, "Preprocessor",
         "z = (x - \u03bc) / \u03c3  (11 features)", fc=C_ML, ec=B_ML, fs=6.8)
    _box(ax, 5.0, 1.95, 2.6, 0.7, "Isolation Forest",
         "100 trees  \u03c8=256  \u2192 [0,100]", fc=C_ML, ec=B_ML, fs=6.8)
    _box(ax, 8.2, 1.95, 2.0, 0.7, "Risk Fusion",
         "0.6 ML + 0.4 Rules", fc=C_ML, ec=B_ML, fs=6.8)

    # ── Tier 5  Persistence ──
    _section_label(ax, 0.2, 1.05, "Tier 5  Storage", B_STORE)
    _box(ax, 2.5, 0.45, 2.6, 0.7, "MongoDB",
         "cases / custody / reports", fc=C_STORE, ec=B_STORE, fs=6.8)
    _box(ax, 5.7, 0.45, 2.2, 0.7, "Model Cache",
         "isolation_forest.pkl", fc=C_STORE, ec=B_STORE, fs=6.8)
    _box(ax, 8.5, 0.45, 2.0, 0.7, "Eval Artifacts",
         "results.json / PNGs", fc=C_STORE, ec=B_STORE, fs=6.5)

    # ── arrows ──
    # client -> api
    _arrow(ax, 5.0, 6.0, 5.0, 5.35, "REST JSON", B_CLIENT)
    # api -> parsers
    _arrow(ax, 3.5, 4.55, 3.5, 3.85, "dispatch", B_API)
    # parsers -> preprocessor
    _arrow(ax, 3.0, 3.05, 1.8, 2.35, "DataFrames", B_PARSE)
    # preprocessor -> iforest
    _arrow(ax, 3.15, 1.95, 3.65, 1.95, "", B_ML)
    # iforest -> risk fusion
    _arrow(ax, 6.35, 1.95, 7.15, 1.95, "", B_ML)
    # risk fusion -> api (scored)
    _arrow(ax, 8.2, 2.35, 7.5, 4.55, "scored", B_ML)
    # api <-> mongo
    _arrow(ax, 2.3, 4.55, 2.5, 0.85, "CRUD", B_STORE)
    # iforest <-> pkl
    _arrow(ax, 5.0, 1.55, 5.7, 0.85, "pkl", B_ML)

    # light horizontal tier dividers
    for y_line in [5.65, 4.15, 2.65, 1.15]:
        ax.axhline(y=y_line, color="#E2E8F0", lw=0.5, ls="--", zorder=0)

    plt.tight_layout(pad=0.3)
    plt.savefig(ARCH_PNG, dpi=300, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"[+] {ARCH_PNG}")


# ═══════════════════════════════════════════════════════════════════════════
#  DIAGRAM 2 — Methodology Pipeline (compact linear flow)
# ═══════════════════════════════════════════════════════════════════════════
def draw_methodology():
    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=300)
    ax.set_xlim(-0.2, 10.2)
    ax.set_ylim(-0.5, 7.5)
    ax.set_aspect("equal")
    ax.axis("off")
    fig.patch.set_facecolor(BG)

    ax.text(5, 7.1, "Forensic Triage Methodology — Six-Stage Pipeline",
            ha="center", va="center", fontsize=9, fontweight="bold", color=TEXT)

    stages = [
        ("Stage 1", "Evidence Intake & Hashing",
         "SHA-256 chunked (1 MiB)\nCustody ledger entry", "#FEF3C7", "#B45309"),
        ("Stage 2", "Artifact Parsing",
         "EVTX  |  Registry  |  PCAP\nDisk Image  |  YARA / OTX", "#EDE9FE", "#6D28D9"),
        ("Stage 3", "Clean & Standardize",
         "Drop NaN / \u00b1Inf, de-dupe\n11 features, z = (x-\u03bc)/\u03c3", "#DBEAFE", "#1D4ED8"),
        ("Stage 4", "Dual Scoring Engine",
         "Isolation Forest (60%)\nDomain heuristics (40%)", "#D1FAE5", "#047857"),
        ("Stage 5", "Priority Banding",
         "CRIT \u226575 | HIGH \u226550\nMED \u226525 | LOW <25", "#FEE2E2", "#B91C1C"),
        ("Stage 6", "Triage & Reporting",
         "Top-K queue \u2192 Workspace\nAutomated PDF dossier", "#F3E8FF", "#7E22CE"),
    ]

    # 2 rows x 3 columns grid
    positions = [
        (1.7, 5.0), (5.0, 5.0), (8.3, 5.0),   # row 1
        (1.7, 2.0), (5.0, 2.0), (8.3, 2.0),    # row 2
    ]

    bw, bh = 2.8, 1.6  # box width, height

    for idx, ((sx, sy), (tag, title, detail, fc, ec)) in enumerate(zip(positions, stages)):
        # main box
        x0, y0 = sx - bw / 2, sy - bh / 2
        rect = FancyBboxPatch((x0, y0), bw, bh,
                              boxstyle="round,pad=0.15,rounding_size=0.25",
                              facecolor=fc, edgecolor=ec, linewidth=1.2, zorder=2)
        ax.add_patch(rect)

        # stage badge
        badge = FancyBboxPatch((x0 + 0.1, y0 + bh - 0.42), 1.1, 0.35,
                               boxstyle="round,pad=0.06,rounding_size=0.12",
                               facecolor=ec, edgecolor="none", zorder=3)
        ax.add_patch(badge)
        ax.text(x0 + 0.65, y0 + bh - 0.25, tag,
                ha="center", va="center", fontsize=5.5, fontweight="bold",
                color="white", zorder=4)

        # title
        ax.text(sx, sy + 0.25, title,
                ha="center", va="center", fontsize=7, fontweight="bold",
                color=TEXT, zorder=3)
        # detail
        ax.text(sx, sy - 0.35, detail,
                ha="center", va="center", fontsize=5.8, color=MUTED,
                linespacing=1.35, zorder=3)

    # arrows — row 1: left to right
    _arrow(ax, 3.15, 5.0, 3.55, 5.0, "", "#64748B")
    _arrow(ax, 6.45, 5.0, 6.85, 5.0, "", "#64748B")
    # row 1 last -> row 2 first (down-right wrap)
    _arrow(ax, 8.3, 4.15, 8.3, 2.85, "", "#64748B")
    # row 2: right to left
    _arrow(ax, 6.85, 2.0, 6.45, 2.0, "", "#64748B")
    _arrow(ax, 3.55, 2.0, 3.15, 2.0, "", "#64748B")

    # Severity legend at bottom
    lx = 1.5
    ax.text(lx, 0.15, "Risk Bands:", ha="left", fontsize=6, fontweight="bold", color=TEXT)
    for label, col in SEV.items():
        lx += 1.8
        ax.plot(lx - 0.15, 0.15, "s", color=col, markersize=5, zorder=3)
        ax.text(lx + 0.1, 0.15, f"{label}", ha="left", va="center",
                fontsize=5.5, color=TEXT, zorder=3)

    plt.tight_layout(pad=0.3)
    plt.savefig(METH_PNG, dpi=300, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"[+] {METH_PNG}")


# ═══════════════════════════════════════════════════════════════════════════
#  PDF compilation
# ═══════════════════════════════════════════════════════════════════════════
def build_pdf():
    styles = getSampleStyleSheet()
    ACCENT = rl_colors.HexColor("#0F172A")
    ORANGE = rl_colors.HexColor("#E8732A")
    MUTED  = rl_colors.HexColor("#64748B")
    LIGHT  = rl_colors.HexColor("#F8FAFC")
    BORD   = rl_colors.HexColor("#CBD5E1")

    t_style  = ParagraphStyle("T", parent=styles["Title"], fontSize=18, leading=22, textColor=ACCENT, alignment=TA_CENTER, fontName="Helvetica-Bold")
    s_style  = ParagraphStyle("S", parent=styles["Normal"], fontSize=9, leading=13, textColor=MUTED, alignment=TA_CENTER, spaceAfter=8)
    h1       = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=12, leading=15, textColor=ACCENT, spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold")
    body     = ParagraphStyle("B", parent=styles["Normal"], fontSize=7.5, leading=10.5, textColor=ACCENT, spaceAfter=3, alignment=TA_JUSTIFY)
    tc       = ParagraphStyle("TC", parent=styles["Normal"], fontSize=7, leading=9.5, textColor=ACCENT)
    th       = ParagraphStyle("TH", parent=styles["Normal"], fontSize=7, leading=9.5, textColor=rl_colors.white, fontName="Helvetica-Bold")

    def decor(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(ORANGE)
        canvas.setLineWidth(0.8)
        canvas.line(1.5*cm, A4[1]-1.1*cm, A4[0]-1.5*cm, A4[1]-1.1*cm)
        canvas.setFont("Helvetica-Bold", 6.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(1.5*cm, A4[1]-0.9*cm, "CYBER TRIAGE TOOL  |  SIH1744  |  System Architecture & Methodology")
        canvas.drawRightString(A4[0]-1.5*cm, A4[1]-0.9*cm, f"Page {doc.page}")
        canvas.setStrokeColor(BORD)
        canvas.setLineWidth(0.4)
        canvas.line(1.5*cm, 1.2*cm, A4[0]-1.5*cm, 1.2*cm)
        canvas.setFont("Helvetica", 6)
        canvas.drawString(1.5*cm, 0.8*cm, "CONFIDENTIAL  |  NIA Anti-Cyber Terrorism Division")
        canvas.drawRightString(A4[0]-1.5*cm, 0.8*cm, datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"))
        canvas.restoreState()

    doc = SimpleDocTemplate(PDF_PATH, pagesize=A4,
                            leftMargin=1.5*cm, rightMargin=1.5*cm,
                            topMargin=1.4*cm, bottomMargin=1.4*cm)

    story = [
        Paragraph("Cyber Triage Tool", t_style),
        Paragraph("<b>System Architecture & Forensic Methodology</b>  |  SIH1744 (NIA)", s_style),
        HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=6),

        Paragraph("1. System Architecture", h1),
        Paragraph(
            "Five-tier topology: React 19 client communicates over REST with a Flask API layer, "
            "which dispatches multi-source forensic evidence to parsers, pipes normalised DataFrames "
            "through an Isolation Forest anomaly detector and domain-rule engine, fuses scores 60/40, "
            "and persists results in MongoDB.",
            body),
        Spacer(1, 3),
        Image(ARCH_PNG, width=17*cm, height=11.5*cm),
        PageBreak(),

        Paragraph("2. Forensic Triage Methodology", h1),
        Paragraph(
            "Six deterministic stages trace evidence from raw intake through SHA-256 integrity hashing, "
            "multi-format parsing, data sanitisation and z-score standardisation, dual ML/rule scoring, "
            "CVSS v3.1 priority banding, to a ranked Top-K triage queue with automated PDF reporting.",
            body),
        Spacer(1, 3),
        Image(METH_PNG, width=17*cm, height=11.5*cm),
        Spacer(1, 6),

        Paragraph("3. Key Formulations", h1),
    ]

    rows = [
        [Paragraph("<b>Component</b>", th), Paragraph("<b>Formula / Standard</b>", th), Paragraph("<b>Source</b>", th)],
        [Paragraph("Feature Scaling", tc), Paragraph("z = (x - mu) / sigma  (StandardScaler)", tc), Paragraph("ml/preprocessor.py", tc)],
        [Paragraph("Anomaly Detector", tc), Paragraph("Isolation Forest (100 trees, psi=256) -> Min-Max [0,100]", tc), Paragraph("ml/detector.py", tc)],
        [Paragraph("Risk Fusion", tc), Paragraph("Risk = min(100, 0.60*S_ml + 0.40*(S_rule*100))", tc), Paragraph("ml/risk_scorer.py", tc)],
        [Paragraph("Priority Bands", tc), Paragraph("CRITICAL >= 75 | HIGH >= 50 | MEDIUM >= 25 | LOW < 25", tc), Paragraph("ml/risk_scorer.py", tc)],
        [Paragraph("Evidence Hash", tc), Paragraph("SHA-256 streamed 1 MiB chunks (NIST FIPS 180-4)", tc), Paragraph("backend/app.py", tc)],
    ]
    t = Table(rows, colWidths=[4*cm, 9*cm, 4.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), ACCENT),
        ("GRID", (0,0), (-1,-1), 0.4, BORD),
        ("BACKGROUND", (0,1), (-1,-1), LIGHT),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT, rl_colors.white]),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(t)

    doc.build(story, onFirstPage=decor, onLaterPages=decor)
    print(f"[+] {PDF_PATH}")


if __name__ == "__main__":
    draw_architecture()
    draw_methodology()
    build_pdf()
    print("[OK] Done.")
