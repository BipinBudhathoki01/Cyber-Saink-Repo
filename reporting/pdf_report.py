from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from datetime import datetime
import textwrap

def write_pdf(report_path: str, target_url: str, summary: str, findings: list[dict]):
    c = canvas.Canvas(report_path, pagesize=A4)
    width, height = A4

    y = height - 2*cm
    c.setFont("Helvetica-Bold", 16)
    c.drawString(2*cm, y, "DAST Report: Automated Vulnerability Assessment")
    y -= 0.8*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Web Security Hardening & Surface-Level Scan")
    y -= 1.0*cm

    c.setFont("Helvetica", 10)
    c.drawString(2*cm, y, f"Target: {target_url}")
    y -= 0.5*cm
    c.drawString(2*cm, y, f"Generated: {datetime.utcnow().isoformat()}Z")
    y -= 1.0*cm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Executive Summary")
    y -= 0.6*cm
    c.setFont("Helvetica", 10)
    
    # Simple text wrapping
    lines = textwrap.wrap(summary, width=90)
    for line in lines:
        c.drawString(2*cm, y, line)
        y -= 0.45*cm
        if y < 2*cm:
            c.showPage()
            y = height - 2*cm
            c.setFont("Helvetica", 10)

    y -= 0.8*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Findings")
    y -= 0.7*cm

    c.setFont("Helvetica", 10)
    for f in findings:
        # Title
        c.setFont("Helvetica-Bold", 10)
        c.drawString(2*cm, y, f"[{f.get('severity','?')}] {f.get('title','')}")
        y -= 0.45*cm
        c.setFont("Helvetica", 10)
        
        block = [
            f"URL: {f.get('affected_url','')}",
            f"Category: {f.get('category','')}",
            f"Evidence: {f.get('evidence','')}",
            f"Recommendation: {f.get('recommendation','')}",
        ]
        
        for line in block:
            # simple truncation to fit line
            c.drawString(2*cm, y, line[:110])
            y -= 0.45*cm
        
        y -= 0.2*cm
        c.line(2*cm, y, width - 2*cm, y)
        y -= 0.6*cm
        
        if y < 3*cm:
            c.showPage()
            y = height - 2*cm

    c.save()
