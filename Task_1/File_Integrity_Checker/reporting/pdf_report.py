"""
PDF Incident Report Generator using ReportLab
"""
import os
import time
from typing import List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(
    target_dir: str,
    verdict_list: List[Dict[str, Any]],
    output_filename: str = "fim_incident_report.pdf"
) -> str:
    """Generate a high-quality PDF incident report."""
    target_dir = os.path.abspath(target_dir)
    out_path = os.path.join(target_dir, output_filename)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    doc = SimpleDocTemplate(
        out_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold',
        spaceAfter=6
    )
    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12
    )
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        fontName='Helvetica-Bold',
        spaceBefore=12,
        spaceAfter=8
    )
    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#334155')
    )
    cell_bold_style = ParagraphStyle(
        'TableCellBold',
        parent=cell_style,
        fontName='Helvetica-Bold'
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("🛡️ Agentic AI SOC Analyst - Incident Report", title_style))
    story.append(Paragraph(f"<b>Target Directory:</b> {target_dir} | <b>Generated:</b> {now_str} | <b>Integrity HMAC:</b> Verified", meta_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=14))

    # Metric Counters
    malicious_count = sum(1 for v in verdict_list if v.get("verdict") == "MALICIOUS")
    suspicious_count = sum(1 for v in verdict_list if v.get("verdict") == "SUSPICIOUS")
    benign_count = sum(1 for v in verdict_list if v.get("verdict") == "BENIGN")

    metric_data = [
        [
            Paragraph("<font size=14 color='#dc2626'><b>MALICIOUS</b></font><br/><font size=16 color='#dc2626'><b>{}</b></font>".format(malicious_count), styles['Normal']),
            Paragraph("<font size=14 color='#d97706'><b>SUSPICIOUS</b></font><br/><font size=16 color='#d97706'><b>{}</b></font>".format(suspicious_count), styles['Normal']),
            Paragraph("<font size=14 color='#16a34a'><b>BENIGN</b></font><br/><font size=16 color='#16a34a'><b>{}</b></font>".format(benign_count), styles['Normal']),
            Paragraph("<font size=14 color='#0284c7'><b>TOTAL SCAN</b></font><br/><font size=16 color='#0284c7'><b>{}</b></font>".format(len(verdict_list)), styles['Normal'])
        ]
    ]
    t_metric = Table(metric_data, colWidths=[130, 130, 130, 130])
    t_metric.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_metric)
    story.append(Spacer(1, 14))

    # Findings Table
    story.append(Paragraph("Detailed Security Findings & MITRE ATT&CK Mapping", section_style))

    table_data = [[
        Paragraph("<b>Target File</b>", cell_bold_style),
        Paragraph("<b>Verdict</b>", cell_bold_style),
        Paragraph("<b>MITRE ATT&CK</b>", cell_bold_style),
        Paragraph("<b>Reasoning / Evidence</b>", cell_bold_style),
        Paragraph("<b>Action</b>", cell_bold_style)
    ]]

    for v in verdict_list:
        verdict = v.get("verdict", "BENIGN")
        v_color = "#dc2626" if verdict == "MALICIOUS" else ("#d97706" if verdict == "SUSPICIOUS" else "#16a34a")
        
        table_data.append([
            Paragraph(f"<code>{v.get('target_file')}</code>", cell_style),
            Paragraph(f"<font color='{v_color}'><b>{verdict}</b></font>", cell_style),
            Paragraph(v.get('mitre_tactic', 'None'), cell_style),
            Paragraph(v.get('reasoning', ''), cell_style),
            Paragraph(v.get('recommended_action', 'none'), cell_style)
        ])

    t_findings = Table(table_data, colWidths=[100, 65, 115, 185, 55])
    t_findings.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    
    # Fix header text colors for PDF white text
    t_findings.setStyle(TableStyle([
        ('TEXTCOLOR', (0,0), (-1,0), colors.white)
    ]))

    story.append(t_findings)

    # Build Document
    doc.build(story)
    return out_path
