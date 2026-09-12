"""
VulnMind AI - Report Generator
Generates: PDF (Enterprise-grade via ReportLab), HTML, TXT reports
"""

import os
import json
import html
import datetime
from typing import Dict, List, Optional
from rich.console import Console

# ReportLab Imports for high-quality PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

console = Console()

REPORTS_DIR = os.path.expanduser("~/.vulnmind/reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Resolve asset paths relative to this script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if __file__ else os.getcwd()
LOGO_PATH = os.path.join(SCRIPT_DIR, "logo.png")
WATERMARK_PATH = os.path.join(SCRIPT_DIR, "watermark.png")


class ReportGenerator:
    """Generates security assessment reports in multiple formats."""

    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    # Cyber/Corporate Palette for ReportLab PDF Layout
    PDF_BG_DARK = colors.HexColor("#eef2f7")
    PDF_BG_PANEL = colors.HexColor("#dbe7f0")
    PDF_BG_ROW = colors.HexColor("#f8fafc")
    PDF_CYAN = colors.HexColor("#0284c7")
    PDF_CYAN_DIM = colors.HexColor("#67b9d6")
    PDF_PURPLE = colors.HexColor("#475569")
    PDF_WHITE = colors.HexColor("#0f172a")
    PDF_MUTED = colors.HexColor("#334155")
    PDF_BORDER = colors.HexColor("#94a3b8")
    
    PDF_SEV_COLORS = {
        "critical": colors.HexColor("#fca5a5"),
        "high":     colors.HexColor("#fdba74"),
        "medium":   colors.HexColor("#fde68a"),
        "low":      colors.HexColor("#bfdbfe"),
        "info":     colors.HexColor("#cbd5e1"),
    }
    PDF_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

    def __init__(self, scan_data: Dict):
        self.scan_data = scan_data
        self.target = scan_data.get("target", "Unknown")
        self.timestamp = datetime.datetime.now()
        self.report_id = self.timestamp.strftime("%Y%m%d_%H%M%S")

    def generate_all(self) -> Dict[str, str]:
        """Generate all report formats."""
        paths = {}
        paths["html"] = self.generate_html()
        paths["txt"] = self.generate_txt()
        try:
            paths["pdf"] = self.generate_pdf()
        except Exception as e:
            console.print(f"[yellow]PDF generation skipped: {e}[/yellow]")
            import traceback
            traceback.print_exc()
        return paths

    def generate_html(self) -> str:
        """Generate HTML report."""
        path = os.path.join(REPORTS_DIR, f"report_{self.target.replace('/', '_')}_{self.report_id}.html")

        vulns = self.scan_data.get("vulnerabilities", [])
        ports = self.scan_data.get("ports", [])
        subdomains = self.scan_data.get("subdomains", [])
        ai_analysis = self.scan_data.get("ai_analysis", {})
        risk = self.scan_data.get("risk", {})

        severity_counts = {}
        for v in vulns:
            s = v.get("severity", "info").lower()
            severity_counts[s] = severity_counts.get(s, 0) + 1

        vuln_rows = ""
        severity_order = ["critical", "high", "medium", "low", "info"]
        sorted_vulns = sorted(vulns, key=lambda x: severity_order.index(
            x.get("severity", "info").lower()) if x.get("severity", "info").lower() in severity_order else 99)

        for i, v in enumerate(sorted_vulns, 1):
            sev = v.get("severity", "info").lower()
            color = self.SEVERITY_COLORS.get(sev, "#6b7280")
            cves = ", ".join(v.get("cve_ids", [])[:3]) or "—"
            cwes = ", ".join(v.get("cwe_ids", [])[:3]) or "—"
            mitre = ", ".join(v.get("mitre_attack", [])[:2]) or "—"

            vuln_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
                <td><strong>{v.get('name', 'Unknown')}</strong></td>
                <td>{v.get('type', '—')}</td>
                <td>{v.get('cvss_score', 0):.1f}</td>
                <td><code>{v.get('affected_url', '—')[:60]}</code></td>
                <td>{cves}</td>
                <td>{cwes}</td>
                <td>{mitre}</td>
            </tr>
            <tr class="details-row">
                <td colspan="9">
                    <div class="vuln-details">
                        <p><strong>Description:</strong> {v.get('description', '—')}</p>
                        <p><strong>Evidence:</strong> <code>{v.get('evidence', '—')[:200]}</code></p>
                        <p><strong>Business Impact:</strong> {v.get('business_impact', ai_analysis.get('attack_surface_analysis', '—'))}</p>
                        <p><strong>Remediation:</strong> {v.get('remediation', '—')}</p>
                    </div>
                </td>
            </tr>"""

        port_rows = ""
        for p in sorted(ports, key=lambda x: x.get("port", 0)):
            risk_class = "high" if p.get("port") in [21, 23, 445, 3389, 5900] else "low"
            port_rows += f"""
            <tr>
                <td>{p.get('port')}</td>
                <td>{p.get('protocol', 'tcp')}</td>
                <td>{p.get('state', 'open')}</td>
                <td>{p.get('service', '—')}</td>
                <td>{p.get('product', '')} {p.get('version', '')}</td>
                <td><span class="risk-{risk_class}">{risk_class.upper()}</span></td>
            </tr>"""

        sub_rows = "".join(f"<tr><td>{i}</td><td>{s}</td></tr>" for i, s in enumerate(subdomains[:50], 1))

        exec_summary = ai_analysis.get("executive_summary", "AI analysis not available.")
        priority_actions = ai_analysis.get("priority_actions", [])
        recommendations = ai_analysis.get("recommendations", [])
        risk_score = risk.get("score", 0)
        risk_level = risk.get("level", "low").upper()

        risk_color = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#2563eb"
        }.get(risk_level, "#6b7280")

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnMind AI Security Report - {self.target}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #06b6d4;
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #2563eb; --info: #6b7280;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); }}
  .page {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border: 1px solid var(--accent); border-radius: 12px; padding: 40px; margin-bottom: 24px; }}
  .logo {{ font-size: 2.5rem; font-weight: 900; color: var(--accent); letter-spacing: -1px; }}
  .logo span {{ color: #7c3aed; }}
  .header-meta {{ display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }}
  .meta-item {{ background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; }}
  .meta-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .meta-value {{ font-size: 15px; font-weight: 600; color: var(--text); }}
  .risk-gauge {{ display: flex; align-items: center; gap: 12px; margin-top: 20px; }}
  .risk-circle {{ width: 80px; height: 80px; border-radius: 50%; border: 4px solid {risk_color}; display: flex; flex-direction: column; align-items: center; justify-content: center; }}
  .risk-score {{ font-size: 22px; font-weight: 900; color: {risk_color}; }}
  .risk-label {{ font-size: 10px; color: var(--muted); text-transform: uppercase; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 20px; }}
  .section-title {{ font-size: 1.2rem; font-weight: 700; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 16px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; }}
  .stat-card {{ background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-number {{ font-size: 2rem; font-weight: 900; }}
  .stat-label {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #0f172a; color: var(--accent); padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); color: var(--text); }}
  tr:hover td {{ background: rgba(6,182,212,0.05); }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: white; font-size: 11px; font-weight: 700; }}
  code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #7dd3fc; }}
  .vuln-details {{ background: #0f172a; border-left: 3px solid var(--accent); padding: 12px 16px; font-size: 13px; }}
  .vuln-details p {{ margin-bottom: 8px; color: var(--muted); }}
  .vuln-details strong {{ color: var(--text); }}
  .risk-high {{ color: #ea580c; font-weight: 700; }}
  .risk-low {{ color: #22c55e; }}
  .details-row {{ background: rgba(6,182,212,0.03); }}
  .exec-summary {{ font-size: 14px; line-height: 1.7; color: #cbd5e1; white-space: pre-wrap; }}
  .action-list {{ list-style: none; }}
  .action-list li {{ padding: 8px 0; border-bottom: 1px solid var(--border); padding-left: 20px; position: relative; }}
  .action-list li::before {{ content: "▶"; position: absolute; left: 0; color: var(--accent); }}
  .footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 20px; }}
  .disclaimer {{ background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3); border-radius: 8px; padding: 12px 16px; color: #fca5a5; font-size: 13px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div class="logo">Vuln<span>Mind</span> AI</div>
    <div style="color: var(--muted); margin-top: 4px;">Enterprise Vulnerability Assessment Report</div>
    <div class="header-meta">
      <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">{self.target}</div></div>
      <div class="meta-item"><div class="meta-label">Date</div><div class="meta-value">{self.timestamp.strftime("%Y-%m-%d %H:%M")}</div></div>
      <div class="meta-item"><div class="meta-label">Scan Type</div><div class="meta-value">{self.scan_data.get('scan_type', 'Full').title()}</div></div>
      <div class="meta-item"><div class="meta-label">Report ID</div><div class="meta-value">{self.report_id}</div></div>
    </div>
    <div class="risk-gauge">
      <div class="risk-circle">
        <div class="risk-score">{risk_score:.0f}</div>
        <div class="risk-label">Risk</div>
      </div>
      <div>
        <div style="font-size: 1.4rem; font-weight: 700; color: {risk_color};">{risk_level} RISK</div>
        <div style="color: var(--muted); font-size: 13px;">Overall security posture</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">📊 Findings Overview</div>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-number" style="color: var(--critical)">{severity_counts.get('critical', 0)}</div><div class="stat-label">Critical</div></div>
      <div class="stat-card"><div class="stat-number" style="color: var(--high)">{severity_counts.get('high', 0)}</div><div class="stat-label">High</div></div>
      <div class="stat-card"><div class="stat-number" style="color: var(--medium)">{severity_counts.get('medium', 0)}</div><div class="stat-label">Medium</div></div>
      <div class="stat-card"><div class="stat-number" style="color: var(--low)">{severity_counts.get('low', 0)}</div><div class="stat-label">Low</div></div>
      <div class="stat-card"><div class="stat-number" style="color: var(--accent)">{len(ports)}</div><div class="stat-label">Open Ports</div></div>
      <div class="stat-card"><div class="stat-number" style="color: #7c3aed">{len(subdomains)}</div><div class="stat-label">Subdomains</div></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">📋 Executive Summary</div>
    <div class="exec-summary">{exec_summary}</div>
    {f'''<br><strong style="color: var(--accent);">Priority Actions:</strong>
    <ul class="action-list" style="margin-top: 12px;">
      {"".join(f"<li>{a}</li>" for a in priority_actions)}
    </ul>''' if priority_actions else ""}
  </div>

  <div class="section">
    <div class="section-title">🔴 Vulnerabilities ({len(vulns)} Found)</div>
    <table>
      <thead>
        <tr><th>#</th><th>Severity</th><th>Name</th><th>Type</th><th>CVSS</th><th>Affected URL</th><th>CVE</th><th>CWE</th><th>MITRE</th></tr>
      </thead>
      <tbody>{vuln_rows if vuln_rows else '<tr><td colspan="9" style="text-align:center;color:var(--muted)">No vulnerabilities found</td></tr>'}</tbody>
    </table>
  </div>

  {f'''<div class="section">
    <div class="section-title">🔌 Open Ports & Services ({len(ports)} Found)</div>
    <table>
      <thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th><th>Risk</th></tr></thead>
      <tbody>{port_rows}</tbody>
    </table>
  </div>''' if ports else ""}

  {f'''<div class="section">
    <div class="section-title">🌐 Discovered Subdomains ({len(subdomains)} Found)</div>
    <table>
      <thead><tr><th>#</th><th>Subdomain</th></tr></thead>
      <tbody>{sub_rows}</tbody>
    </table>
  </div>''' if subdomains else ""}

  {f'''<div class="section">
    <div class="section-title">✅ Recommendations</div>
    <ul class="action-list">
      {"".join(f"<li>{r}</li>" for r in recommendations)}
    </ul>
  </div>''' if recommendations else ""}

  <div class="disclaimer">
    ⚠️ <strong>Legal Disclaimer:</strong> This report was generated by VulnMind AI for authorized security testing purposes only.
  </div>
</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return path

    def generate_txt(self) -> str:
        """Generate plain text report."""
        path = os.path.join(REPORTS_DIR, f"report_{self.target.replace('/', '_')}_{self.report_id}.txt")

        vulns = self.scan_data.get("vulnerabilities", [])
        ports = self.scan_data.get("ports", [])
        subdomains = self.scan_data.get("subdomains", [])
        ai_analysis = self.scan_data.get("ai_analysis", {})
        risk = self.scan_data.get("risk", {})

        lines = [
            "=" * 80, "VULNMIND AI - SECURITY ASSESSMENT REPORT", "=" * 80,
            f"Target:      {self.target}",
            f"Date:        {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Scan Type:   {self.scan_data.get('scan_type', 'Full')}",
            f"Risk Score:  {risk.get('score', 0):.1f}/100 ({risk.get('level', 'unknown').upper()})",
            f"Report ID:   {self.report_id}", "=" * 80, "",
            "EXECUTIVE SUMMARY", "-" * 40, ai_analysis.get("executive_summary", "N/A"), "",
            "VULNERABILITY SUMMARY", "-" * 40
        ]

        severity_counts = {}
        for v in vulns:
            s = v.get("severity", "info").lower()
            severity_counts[s] = severity_counts.get(s, 0) + 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            lines.append(f"  {sev.upper():10}: {severity_counts.get(sev, 0)}")

        lines += ["", "VULNERABILITIES", "-" * 40]
        for i, v in enumerate(vulns, 1):
            lines += [
                f"\n[{i}] {v.get('name', 'Unknown')}",
                f"    Severity:   {v.get('severity', '—').upper()}",
                f"    CVSS Score: {v.get('cvss_score', 0):.1f}",
                f"    Type:       {v.get('type', '—')}",
                f"    URL:        {v.get('affected_url', '—')}",
                f"    Description: {v.get('description', '—')}",
                f"    Remediation: {v.get('remediation', '—')}"
            ]

        if ports:
            lines += ["", "OPEN PORTS", "-" * 40]
            for p in sorted(ports, key=lambda x: x.get("port", 0)):
                lines.append(f"  {p['port']}/{p.get('protocol','tcp'):4} - {p.get('service','?'):15}")

        if subdomains:
            lines += ["", "SUBDOMAINS", "-" * 40]
            for s in subdomains:
                lines.append(f"  {s}")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    # ── PDF Helper Logic for ReportLab Layout Engine ──────────────────────────────
    def _add_bg_and_header(self, canvas_obj, doc):
        """Dynamic canvas callback executing corporate header/footer & watermarks."""
        W, H = A4
        canvas_obj.saveState()

        # Canvas Page Background Base
        canvas_obj.setFillColor(self.PDF_BG_DARK)
        canvas_obj.rect(0, 0, W, H, fill=1, stroke=0)

        # Header Plate Background Structure
        HEADER_H = 28 * mm
        canvas_obj.setFillColor(self.PDF_BG_PANEL)
        canvas_obj.rect(0, H - HEADER_H, W, HEADER_H, fill=1, stroke=0)

        # Top Section Accent Line
        canvas_obj.setStrokeColor(self.PDF_CYAN)
        canvas_obj.setLineWidth(1.5)
        canvas_obj.line(0, H - HEADER_H, W, H - HEADER_H)

        # Automated Asset Discovery & Image Loading for Brand Logo
        if os.path.exists(LOGO_PATH):
            try:
                logo_img = ImageReader(LOGO_PATH)
                canvas_obj.drawImage(logo_img, 16 * mm, H - 25 * mm, width=22 * mm, height=22 * mm, mask="auto", preserveAspectRatio=True)
            except Exception:
                pass
        
        canvas_obj.setFont("Helvetica-Bold", 20)
        canvas_obj.setFillColor(self.PDF_CYAN)
        canvas_obj.drawString(42 * mm, H - 15 * mm, "VulnMind AI")

        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(self.PDF_PURPLE)
        canvas_obj.drawString(42 * mm, H - 21 * mm, "ENTERPRISE SECURITY ASSESSMENT REPORT")

        # Architectural Color Borders 
        canvas_obj.setFillColor(self.PDF_PURPLE)
        canvas_obj.rect(0, 0, 3, H, fill=1, stroke=0)
        canvas_obj.setFillColor(self.PDF_CYAN_DIM)
        canvas_obj.rect(W - 3, 0, 3, H, fill=1, stroke=0)

        # Running Footer Section
        FOOTER_H = 10 * mm
        canvas_obj.setFillColor(self.PDF_BG_PANEL)
        canvas_obj.rect(0, 0, W, FOOTER_H, fill=1, stroke=0)
        canvas_obj.setStrokeColor(self.PDF_CYAN_DIM)
        canvas_obj.setLineWidth(0.8)
        canvas_obj.line(0, FOOTER_H, W, FOOTER_H)
        
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(self.PDF_MUTED)
        canvas_obj.drawString(8 * mm, 3.5 * mm, f"VulnMind AI Assessment | {self.timestamp.strftime('%Y-%m-%d %H:%M')} | Confidentiality Notice: Authorized Client Delivery Only")
        canvas_obj.drawRightString(W - 8 * mm, 3.5 * mm, f"Page {doc.page}")

        # Keep the watermark subtle so report content remains readable.
        try:
            canvas_obj.setFillAlpha(0.08)
        except Exception:
            pass

        if os.path.exists(WATERMARK_PATH):
            try:
                wm_img = ImageReader(WATERMARK_PATH)
                iw, ih = wm_img.getSize()
                scale = min(150 * mm / iw, 150 * mm / ih)
                canvas_obj.drawImage(wm_img, (W - iw*scale)/2, (H - ih*scale)/2, width=iw*scale, height=ih*scale, mask="auto", preserveAspectRatio=True)
            except Exception:
                pass
        else:
            canvas_obj.setFont("Helvetica-Bold", 140)
            canvas_obj.setFillColor(self.PDF_CYAN_DIM)
            canvas_obj.drawCentredString(W / 2, H / 2, "VULNMIND")

        canvas_obj.restoreState()

    def _make_pdf_styles(self):
        s = {}
        s["section"] = ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=10, textColor=self.PDF_CYAN, spaceAfter=4, spaceBefore=12)
        s["body"] = ParagraphStyle("body", fontName="Helvetica", fontSize=8, textColor=self.PDF_WHITE, leading=12)
        s["muted"] = ParagraphStyle("muted", fontName="Helvetica", fontSize=7.5, textColor=self.PDF_MUTED, leading=11)
        s["label"] = ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=7.5, textColor=self.PDF_CYAN)
        s["cell"] = ParagraphStyle("cell", fontName="Helvetica", fontSize=7, leading=10, textColor=self.PDF_WHITE, wordWrap="CJK", splitLongWords=True)
        s["cell_center"] = ParagraphStyle("cell_center", parent=s["cell"], alignment=TA_CENTER)
        s["cell_bold"] = ParagraphStyle("cell_bold", parent=s["cell"], fontName="Helvetica-Bold")
        s["disclaimer_title"] = ParagraphStyle("disclaimer_title", parent=s["cell_bold"], textColor=colors.HexColor("#fecaca"))
        s["disclaimer_body"] = ParagraphStyle("disclaimer_body", parent=s["cell"], textColor=colors.HexColor("#fef2f2"))
        return s

    def _wrap_rows(self, rows, styles, center_cols=None):
        center_cols = center_cols or set()
        wrapped = []
        for ri, row in enumerate(rows):
            wrapped_row = []
            for ci, val in enumerate(row):
                style = styles["cell_bold"] if ri == 0 else styles["cell"]
                if ci in center_cols:
                    style = styles["cell_center"]
                txt = "" if val is None else str(val)
                wrapped_row.append(Paragraph(html.escape(txt).replace("\n", "<br/>"), style))
            wrapped.append(wrapped_row)
        return wrapped

    def _get_table_style(self):
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.PDF_BG_PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), self.PDF_CYAN),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 7),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
            ("TOPPADDING", (0, 0), (-1, 0), 5),
            ("BACKGROUND", (0, 1), (-1, -1), colors.Color(1, 1, 1, alpha=0.12)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.Color(1, 1, 1, alpha=0.08), colors.Color(1, 1, 1, alpha=0.16)]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, self.PDF_BORDER),
            ("LINEBELOW", (0, 0), (-1, 0), 1.2, self.PDF_CYAN),
        ])

    def generate_pdf(self) -> str:
        """Generate PDF report using professional ReportLab templates."""
        path = os.path.join(REPORTS_DIR, f"report_{self.target.replace('/', '_')}_{self.report_id}.pdf")

        vulns = self.scan_data.get("vulnerabilities", [])
        ports = self.scan_data.get("ports", [])
        subdomains = self.scan_data.get("subdomains", [])
        ai_analysis = self.scan_data.get("ai_analysis", {})
        risk = self.scan_data.get("risk", {})

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=12 * mm,
            rightMargin=12 * mm,
            topMargin=33 * mm,
            bottomMargin=16 * mm,
        )

        ST = self._make_pdf_styles()
        story = []

        # ── Meta bar ──────────────────────────────────────────────────────────
        risk_score = risk.get("score", 0)
        risk_level = risk.get("level", "medium").upper()
        risk_color = self.PDF_SEV_COLORS.get(risk_level.lower(), self.PDF_SEV_COLORS["info"])

        meta_data = [
            ["TARGET", "DATE / TIME", "SCAN TYPE", "REPORT ID", "RISK SCORE"],
            [self.target, self.timestamp.strftime("%Y-%m-%d %H:%M"), self.scan_data.get("scan_type", "Full").title(), self.report_id, f"{risk_score}/100  {risk_level}"]
        ]
        meta_tbl = Table(self._wrap_rows(meta_data, ST, {0, 1, 2, 3, 4}), colWidths=[doc.width / 5] * 5)
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.PDF_BG_PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), self.PDF_CYAN),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, self.PDF_BORDER),
            ("TEXTCOLOR", (4, 1), (4, 1), risk_color),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 4 * mm))

        # ── Severity summary table card ─────────────────────────────────────────
        sev_counts = {}
        for v in vulns:
            s = v.get("severity", "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        summary_data = [
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OPEN PORTS", "SUBDOMAINS"],
            [str(sev_counts.get("critical", 0)), str(sev_counts.get("high", 0)), str(sev_counts.get("medium", 0)), str(sev_counts.get("low", 0)), str(sev_counts.get("info", 0)), str(len(ports)), str(len(subdomains))]
        ]
        sum_tbl = Table(self._wrap_rows(summary_data, ST, {0, 1, 2, 3, 4, 5, 6}), colWidths=[doc.width / 7] * 7)
        sum_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.PDF_BG_PANEL),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, self.PDF_BORDER),
            ("FONTSIZE", (0, 1), (-1, 1), 14),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (0, 1), self.PDF_SEV_COLORS["critical"]),
            ("TEXTCOLOR", (1, 0), (1, 1), self.PDF_SEV_COLORS["high"]),
            ("TEXTCOLOR", (2, 0), (2, 1), self.PDF_SEV_COLORS["medium"]),
            ("TEXTCOLOR", (3, 0), (3, 1), self.PDF_SEV_COLORS["low"]),
            ("TEXTCOLOR", (4, 0), (4, 1), self.PDF_SEV_COLORS["info"]),
        ]))
        story.append(sum_tbl)
        story.append(Spacer(1, 4 * mm))

        # ── Executive Summary ──────────────────────────────────────────────────
        story.append(Paragraph("● EXECUTIVE SUMMARY", ST["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=self.PDF_CYAN_DIM, spaceAfter=4))
        story.append(Paragraph(ai_analysis.get("executive_summary", "Automated scan execution finalized."), ST["muted"]))
        story.append(Spacer(1, 4 * mm))

        # Priority actions subtable
        priority = ai_analysis.get("priority_actions", [])
        if priority:
            pa_data = [["#", "PRIORITY REMEDIATION ACTION STEPS"]] + [[str(i), a] for i, a in enumerate(priority, 1)]
            pa_tbl = Table(self._wrap_rows(pa_data, ST, {0}), colWidths=[14 * mm, doc.width - 14 * mm])
            pa_tbl.setStyle(self._get_table_style())
            story.append(pa_tbl)
            story.append(Spacer(1, 4 * mm))

        # ── Vulnerabilities Primary Matrix ─────────────────────────────────────
        story.append(Paragraph(f"● VULNERABILITIES DETECTED ({len(vulns)} FINDINGS)", ST["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=self.PDF_CYAN_DIM, spaceAfter=4))

        sorted_vulns = sorted(
            vulns,
            key=lambda x: self.PDF_SEV_ORDER.index(x.get("severity", "info").lower())
            if x.get("severity", "info").lower() in self.PDF_SEV_ORDER else 99
        )

        vuln_header = ["#", "SEVERITY", "VULNERABILITY NAME", "TYPE", "CVSS", "CVE", "CWE / MITRE", "AFFECTED TARGET URL"]
        vuln_rows = [vuln_header]
        for i, v in enumerate(sorted_vulns, 1):
            cves = ", ".join(v.get("cve_ids", [])[:2]) or "—"
            cwes = ", ".join(v.get("cwe_ids", [])[:1]) or "—"
            mitre = ", ".join(v.get("mitre_attack", [])[:1])
            cwe_mitre = f"{cwes}\n{mitre}" if mitre else cwes
            vuln_rows.append([str(i), v.get("severity", "info").upper(), v.get("name", "Unknown"), v.get("type", "—"), f"{v.get('cvss_score', 0):.1f}", cves, cwe_mitre, v.get("affected_url", "—")])

        col_w = [10*mm, 17*mm, 48*mm, 21*mm, 13*mm, 18*mm, 22*mm, doc.width - 169*mm]
        vuln_tbl = Table(self._wrap_rows(vuln_rows, ST, {0, 1, 4}), colWidths=col_w, repeatRows=1)
        
        # Color code severity badges inside reportlab matrix cells
        v_styles = self._get_table_style()
        extra_cmds = []
        for ri, row in enumerate(vuln_rows[1:], 1):
            sc = self.PDF_SEV_COLORS.get(str(row[1]).lower(), self.PDF_SEV_COLORS["info"])
            extra_cmds += [
                ("BACKGROUND", (1, ri), (1, ri), sc),
                ("ALIGN", (1, ri), (1, ri), "CENTER"),
                ("FONTNAME", (1, ri), (1, ri), "Helvetica-Bold"),
            ]
        vuln_tbl.setStyle(TableStyle(v_styles._cmds + extra_cmds))
        story.append(vuln_tbl)
        story.append(Spacer(1, 5 * mm))

        # ── Comprehensive Description & Remediation Section ───────────────────
        story.append(Paragraph("● INDEPTH FINDINGS ANALYSIS & MITIGATION SPECIFICS", ST["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=self.PDF_CYAN_DIM, spaceAfter=4))
        
        rem_col_w = [10*mm, 17*mm, 63*mm, doc.width - 90*mm]
        rem_rows = [["#", "SEV", "DETAILED FINDING DESCRIPTION", "TECHNICAL REMEDIATION STRATEGY"]]
        for i, v in enumerate(sorted_vulns, 1):
            rem_rows.append([str(i), v.get("severity", "info").upper(), v.get("description", v.get("name", "—")), v.get("remediation", "—")])
            
        rem_tbl = Table(self._wrap_rows(rem_rows, ST, {0, 1}), colWidths=rem_col_w, repeatRows=1)
        rem_extra = []
        for ri, row in enumerate(rem_rows[1:], 1):
            sc = self.PDF_SEV_COLORS.get(str(row[1]).lower(), self.PDF_SEV_COLORS["info"])
            rem_extra += [
                ("BACKGROUND", (1, ri), (1, ri), sc),
                ("ALIGN", (1, ri), (1, ri), "CENTER"),
                ("FONTNAME", (1, ri), (1, ri), "Helvetica-Bold"),
            ]
        rem_tbl.setStyle(TableStyle(self._get_table_style()._cmds + rem_extra))
        story.append(rem_tbl)

        # ── Infrastructure Security - Open Ports & Running Services ───────────
        if ports:
            story.append(Spacer(1, 5 * mm))
            story.append(Paragraph(f"● PORT ANALYSIS & INVENTORY ({len(ports)} SERVICES DETECTED)", ST["section"]))
            story.append(HRFlowable(width="100%", thickness=0.5, color=self.PDF_CYAN_DIM, spaceAfter=4))
            port_col_w = [16*mm, 18*mm, 18*mm, 35*mm, 50*mm, doc.width - 137*mm]
            port_rows = [["PORT", "PROTOCOL", "STATE", "SERVICE", "PRODUCT / VERSION", "RISK METRIC"]]
            risky_ports = {21, 23, 445, 3389, 5900, 1433, 3306}
            for p in sorted(ports, key=lambda x: x.get("port", 0)):
                rl = "HIGH" if p.get("port") in risky_ports else "LOW"
                port_rows.append([str(p.get("port", "")), p.get("protocol", "tcp").upper(), p.get("state", "open").upper(), p.get("service", "—"), f"{p.get('product','') or ''} {p.get('version','') or ''}".strip() or "—", rl])
            
            port_tbl = Table(self._wrap_rows(port_rows, ST, {0, 1, 2, 5}), colWidths=port_col_w, repeatRows=1)
            port_extra = []
            for ri, row in enumerate(port_rows[1:], 1):
                rc = self.PDF_SEV_COLORS["high"] if row[5] == "HIGH" else self.PDF_SEV_COLORS["low"]
                port_extra += [
                    ("TEXTCOLOR", (5, ri), (5, ri), rc),
                    ("FONTNAME", (5, ri), (5, ri), "Helvetica-Bold"),
                ]
            port_tbl.setStyle(TableStyle(self._get_table_style()._cmds + port_extra))
            story.append(port_tbl)

        # ── Reconnaissance Discovery - Domain Perimeter Map ─────────────────
        if subdomains:
            story.append(Spacer(1, 5 * mm))
            story.append(Paragraph(f"● PERIMETER DISCOVERY & MAP ({len(subdomains)} SUBDOMAINS)", ST["section"]))
            story.append(HRFlowable(width="100%", thickness=0.5, color=self.PDF_CYAN_DIM, spaceAfter=4))
            per_row = 3
            sub_col_w = [doc.width / per_row] * per_row
            sub_rows = [["DISCOVERED EXTERNAL TARGET ALIASES"] * per_row]
            chunk = []
            for s in subdomains[:60]:
                chunk.append(s)
                if len(chunk) == per_row:
                    sub_rows.append(chunk); chunk = []
            if chunk:
                sub_rows.append(chunk + [""] * (per_row - len(chunk)))
            sub_tbl = Table(self._wrap_rows(sub_rows, ST), colWidths=sub_col_w, repeatRows=1)
            sub_tbl.setStyle(self._get_table_style())
            story.append(sub_tbl)

        # ── AI Generated Findings Analysis (New Requested Block) ─────────────
        story.append(Spacer(1, 5 * mm))
        story.append(Paragraph("● AI GENERATED FINDINGS ANALYSIS & BEST PRACTICES", ST["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=self.PDF_CYAN_DIM, spaceAfter=4))
        
        recs = ai_analysis.get("recommendations", [])
        ai_data = [["TYPE", "INTELLIGENCE BRIEFING & RISK POSTURE STRATEGY"]]
        ai_data.append(["Risk Summary", f"Overall target risk is calculated as {risk_level} with a value indicator score of {risk_score}/100. Perimeter monitoring is advised."])
        ai_data.append(["Security Impact", "Exposed system artifacts and application code metadata significantly degrade system isolation barriers, allowing lateral profiling access."])
        
        if recs:
            ai_data.append(["Remediation Priority", f"Address {sev_counts.get('critical', 0)} Critical and {sev_counts.get('high', 0)} High severity issues immediately as highlighted in your strategic action list."])
            ai_data.append(["Best Practices", " ".join([f"• {r}" for r in recs])])
        else:
            ai_data.append(["Best Practices", "Enforce strict security control layers, continuously audit endpoint visibility parameters, and monitor infrastructure telemetry profiles regularly."])
            
        ai_tbl = Table(self._wrap_rows(ai_data, ST, {0}), colWidths=[32 * mm, doc.width - 32 * mm], repeatRows=1)
        ai_tbl.setStyle(self._get_table_style())
        story.append(ai_tbl)

        # ── Legal Disclaimer Banner ───────────────────────────────────────────
        story.append(Spacer(1, 6 * mm))
        disc_data = [
            ["⚠  LEGAL DISCLAIMER & COMPLIANCE REQUIREMENTS"],
            ["This report was generated automatically via VulnMind AI for authenticated, authorized infrastructure and penetration security validation tasks only. Unauthorized processing or execution using data elements herein constitutes violation parameters across international electronic security statutes. Treat structural mappings inside as strict client enterprise confidential material."]
        ]
        disc_rows = [
            [Paragraph(html.escape(disc_data[0][0]), ST["disclaimer_title"])],
            [Paragraph(html.escape(disc_data[1][0]), ST["disclaimer_body"])],
        ]
        disc_tbl = Table(disc_rows, colWidths=[doc.width])
        disc_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#1a0000")),
            ("TEXTCOLOR", (0, 0), (0, 0), colors.HexColor("#dc2626")),
            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#0d0000")),
            ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#fca5a5")),
            ("BOX", (0, 0), (0, -1), 1, colors.HexColor("#dc2626")),
            ("TOPPADDING", (0, 0), (0, -1), 4),
            ("BOTTOMPADDING", (0, 0), (0, -1), 4),
            ("LEFTPADDING", (0, 0), (0, -1), 6),
        ]))
        story.append(disc_tbl)

        # Build execution flow attaching the unified dynamic headers & footers
        doc.build(story, onFirstPage=self._add_bg_and_header, onLaterPages=self._add_bg_and_header)
        return path


# Demo execution test suite mapping
if __name__ == "__main__":
    demo_scan_dataset = {
        "target": "uptoskills.com",
        "scan_type": "Full",
        "risk": {"score": 33, "level": "medium"},
        "ai_analysis": {
            "executive_summary": "The automated environment review discovered structural exposures across parameters.",
            "priority_actions": [
                "Isolate configuration metadata elements from public root visibility immediately.",
                "Enforce strict TLS 1.2+ configuration criteria blocks."
            ],
            "recommendations": [
                "Implement proactive perimeter edge routing firewalls.",
                "Verify metadata validation loops across external facing portals."
            ],
        },
        "vulnerabilities": [
            {"name": "Sensitive File Exposed: /.git/config", "severity": "critical", "cvss_score": 9.0, "type": "Information Disclosure", "affected_url": "https://uptoskills.com/.git/config", "description": "Git structural configuration parameters visible online.", "remediation": "Restrict web exposure immediately."},
            {"name": "Weak Protocol Configured: TLS 1.0", "severity": "medium", "cvss_score": 5.0, "type": "Cryptographic Defect", "affected_url": "https://uptoskills.com", "description": "Legacy transport protocol variants detected.", "remediation": "Upgrade configuration definitions."}
        ],
        "ports": [{"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "Apache"}],
        "subdomains": ["api.uptoskills.com", "portal.uptoskills.com"]
    }
    
    generator = ReportGenerator(demo_scan_dataset)
    generated_outputs = generator.generate_all()
    print("Execution Finished! Generated Reports Map:", json.dumps(generated_outputs, indent=2))
