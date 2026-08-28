# engine/pdf_report.py
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable
)


# Color palette - high contrast, professional
CYAN = HexColor('#06b6d4')
FUCHSIA = HexColor('#d946ef')
EMERALD = HexColor('#10b981')
AMBER = HexColor('#f59e0b')
RED = HexColor('#dc3545')
GOLD = HexColor('#fbbf24')

# Dark theme (for headers, tables)
BG_DARK = HexColor('#0f172a')      # slate-900
BG_CARD = HexColor('#1e293b')      # slate-800
BG_ROW1 = HexColor('#1e293b')      # slate-800
BG_ROW2 = HexColor('#334155')      # slate-700
BORDER = HexColor('#475569')       # slate-600

# Light theme (for key-value rows)
BG_LIGHT = HexColor('#f8fafc')     # slate-50
BG_LIGHT_ALT = HexColor('#f1f5f9') # slate-100
TEXT_DARK = HexColor('#0f172a')    # slate-900
TEXT_MUTED = HexColor('#475569')   # slate-600
TEXT_LIGHT = HexColor('#f8fafc')   # slate-50
WHITE = HexColor('#ffffff')


def severity_color(sev):
    sev = str(sev).upper()
    if sev == 'CRITICAL':
        return RED
    elif sev == 'HIGH':
        return AMBER
    elif sev == 'MEDIUM':
        return GOLD
    elif sev == 'LOW':
        return EMERALD
    return HexColor('#64748b')  # slate-500


def category_color(cat):
    return FUCHSIA if cat == 'threat' else CYAN


def risk_color(score):
    if score >= 75:
        return RED
    elif score >= 50:
        return AMBER
    elif score >= 25:
        return GOLD
    return EMERALD


def has_data(data):
    """Check if dict/list has meaningful data"""
    if not data:
        return False
    if isinstance(data, list):
        return len(data) > 0
    if isinstance(data, dict):
        return any(v not in (None, '', 'N/A', 'NOT SET', 'NOT DETECTED', 0, []) for v in data.values())
    return str(data) not in ('N/A', 'NOT SET', 'NOT DETECTED', '', 'None')


def safe_str(val, fallback='N/A'):
    if val is None:
        return fallback
    s = str(val).strip()
    return s if s else fallback


def generate_pdf_report(scan, shodan_dict, geo_dict, vt_dict, dns_dict, findings_list,
                        exposure_color, threat_color, target_is_ip, display_score_level,
                        display_score_color, display_verdict,
                        chart_findings_by_severity, chart_findings_by_category, chart_cves_by_severity):
    """
    Generate a clean, professional PDF report for a scan result.
    Returns bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=22*mm,
        leftMargin=22*mm,
        topMargin=22*mm,
        bottomMargin=22*mm,
        title=f"ThreatLens Intelligence Report - {scan.target}",
        author="ThreatLens SOC Platform"
    )

    styles = getSampleStyleSheet()
    
    # Styles - all with explicit colors for contrast
    styles.add(ParagraphStyle(
        'ReportTitle', parent=styles['Title'],
        fontName='Helvetica-Bold', fontSize=26,
        textColor=WHITE, spaceAfter=2, alignment=TA_LEFT, leading=30
    ))
    styles.add(ParagraphStyle(
        'ReportSubtitle', parent=styles['Normal'],
        fontName='Helvetica', fontSize=11,
        textColor=HexColor('#94a3b8'), spaceAfter=4, alignment=TA_LEFT, leading=15
    ))
    styles.add(ParagraphStyle(
        'SectionTitle', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=14,
        textColor=CYAN, spaceBefore=18, spaceAfter=6, leading=18
    ))
    styles.add(ParagraphStyle(
        'BodyClean', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9.5,
        textColor=TEXT_DARK, leading=14, alignment=TA_JUSTIFY
    ))
    styles.add(ParagraphStyle(
        'BodySmall', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5,
        textColor=TEXT_MUTED, leading=12, alignment=TA_LEFT
    ))
    styles.add(ParagraphStyle(
        'MonoText', parent=styles['Normal'],
        fontName='Courier', fontSize=8.5,
        textColor=TEXT_DARK, leading=12
    ))
    styles.add(ParagraphStyle(
        'MonoBold', parent=styles['Normal'],
        fontName='Courier-Bold', fontSize=8.5,
        textColor=TEXT_DARK, leading=12
    ))
    styles.add(ParagraphStyle(
        'FindingTitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=10,
        textColor=WHITE, leading=14, spaceAfter=2
    ))
    styles.add(ParagraphStyle(
        'FindingDesc', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9,
        textColor=TEXT_DARK, leading=13, spaceAfter=4, leftIndent=4
    ))
    styles.add(ParagraphStyle(
        'Recommendation', parent=styles['Normal'],
        fontName='Helvetica-Oblique', fontSize=8.5,
        textColor=CYAN, leading=12, spaceAfter=6, leftIndent=4
    ))
    styles.add(ParagraphStyle(
        'Label', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9,
        textColor=TEXT_MUTED, leading=13
    ))
    styles.add(ParagraphStyle(
        'Value', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=9,
        textColor=TEXT_DARK, leading=13
    ))
    styles.add(ParagraphStyle(
        'ValueMono', parent=styles['Normal'],
        fontName='Courier-Bold', fontSize=8.5,
        textColor=TEXT_DARK, leading=12
    ))
    styles.add(ParagraphStyle(
        'FooterText', parent=styles['Normal'],
        fontName='Helvetica', fontSize=7.5,
        textColor=TEXT_MUTED, alignment=TA_CENTER, leading=10
    ))
    styles.add(ParagraphStyle(
        'TableHeader', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=8.5,
        textColor=WHITE, leading=11
    ))
    styles.add(ParagraphStyle(
        'TableCell', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5,
        textColor=TEXT_DARK, leading=11
    ))
    styles.add(ParagraphStyle(
        'TableCellBold', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=8.5,
        textColor=TEXT_DARK, leading=11
    ))

    story = []

    def add_section(title):
        story.append(Paragraph(title, styles['SectionTitle']))
        story.append(HRFlowable(width="100%", thickness=1.5, color=CYAN))
        story.append(Spacer(1, 6))

    def add_kv(label, value, mono=False, value_color=None):
        """Add a key-value row"""
        vs = styles['ValueMono'] if mono else styles['Value']
        if value_color:
            vs = ParagraphStyle('VC', parent=vs, textColor=value_color)
        data = [[Paragraph(label, styles['Label']), Paragraph(safe_str(value), vs)]]
        t = Table(data, colWidths=[doc.width*0.32, doc.width*0.68])
        t.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ('BACKGROUND', (0,0), (-1,-1), WHITE),
        ]))
        story.append(t)

    # ===== HEADER =====
    story.append(Paragraph('THREATLENS', styles['ReportTitle']))
    story.append(Paragraph('INTELLIGENCE REPORT', styles['ReportSubtitle']))
    story.append(HRFlowable(width="100%", thickness=2, color=CYAN))
    story.append(Spacer(1, 8))

    target_type = 'IP Address' if target_is_ip else 'Domain'
    type_color = '#0ea5e9' if target_is_ip else '#d946ef'
    score_val = scan.risk_score
    score_lvl = display_score_level
    score_clr = display_score_color if display_score_color else risk_color(score_val)

    header_data = [[
        Paragraph(f'<b>Target:</b> <font color="{type_color}">{scan.target}</font>  |  <b>Type:</b> <font color="{type_color}">{target_type}</font>', styles['ReportSubtitle']),
        Paragraph(f'<b>Risk Score:</b> <font color="{score_clr}">{score_val}/100 [{score_lvl}]</font>', 
                  ParagraphStyle('ScoreRight', parent=styles['ReportSubtitle'], alignment=TA_RIGHT))
    ]]
    ht = Table(header_data, colWidths=[doc.width*0.65, doc.width*0.35])
    ht.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE'), ('BOTTOMPADDING', (0,0), (-1,-1), 6)]))
    story.append(ht)
    story.append(Spacer(1, 4))

    scan_date = scan.scan_date.strftime('%Y-%m-%d %H:%M UTC') if scan.scan_date else 'N/A'
    meta_data = [[
        Paragraph(f'<b>Scan Date:</b> {scan_date}', styles['ReportSubtitle']),
        Paragraph(f'<b>Profile:</b> {safe_str(display_verdict or scan.profile)}', styles['ReportSubtitle']),
    ]]
    mt = Table(meta_data, colWidths=[doc.width*0.5, doc.width*0.5])
    mt.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE'), ('BOTTOMPADDING', (0,0), (-1,-1), 4)]))
    story.append(mt)
    story.append(Spacer(1, 12))

    # ===== EXPOSURE vs THREAT PROFILE =====
    exp_idx = scan.exposure_index or 0
    thr_idx = scan.threat_index or 0
    exp_band = safe_str(scan.exposure_band, 'LOW')
    thr_band = safe_str(scan.threat_band, 'LOW')

    add_section('EXPOSURE vs THREAT PROFILE')
    
    # Use clean key-value layout instead of table
    add_kv('Exposure Index', f'{exp_idx}/100', value_color=HexColor(exposure_color))
    add_kv('Exposure Band', exp_band, value_color=HexColor(exposure_color))
    add_kv('Threat Index', f'{thr_idx}/100', value_color=HexColor(threat_color))
    add_kv('Threat Band', thr_band, value_color=HexColor(threat_color))
    story.append(Spacer(1, 10))

    # ===== ORIGIN & NETWORK =====
    if has_data(geo_dict):
        add_section('ORIGIN & NETWORK')
        
        add_kv('Resolved IP', safe_str(geo_dict.get('query')), mono=True)
        add_kv('Country', safe_str(geo_dict.get('country')))
        add_kv('City', safe_str(geo_dict.get('city')))
        add_kv('ISP', safe_str(geo_dict.get('isp')))
        add_kv('Organization', safe_str(geo_dict.get('org')))
        story.append(Spacer(1, 10))

    # ===== INFRASTRUCTURE =====
    if has_data(shodan_dict):
        add_section('INFRASTRUCTURE & PORTS')
        
        if has_data(shodan_dict.get('organization')):
            add_kv('Organization', safe_str(shodan_dict.get('organization')))
        if has_data(shodan_dict.get('hostnames')):
            add_kv('Hostnames', ', '.join(shodan_dict['hostnames']), mono=True)
        if has_data(shodan_dict.get('os')):
            add_kv('Operating System', safe_str(shodan_dict.get('os')))
        if has_data(shodan_dict.get('ports')):
            ports_str = ', '.join(map(str, shodan_dict['ports']))
            add_kv('Open Ports', ports_str, mono=True)
        story.append(Spacer(1, 10))

    # ===== KNOWN VULNERABILITIES =====
    vulns = shodan_dict.get('enriched_vulns', [])
    if vulns:
        add_section('KNOWN VULNERABILITIES')
        
        # Summary line
        sev_counts = {}
        for v in vulns:
            s = str(v.get('severity', 'UNKNOWN')).upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        summary_parts = []
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in sev_counts:
                summary_parts.append(f'<font color="{severity_color(s)}">{sev_counts[s]} {s}</font>')
        story.append(Paragraph(' • '.join(summary_parts) if summary_parts else 'None', styles['BodySmall']))
        story.append(Spacer(1, 6))
        
        # Top 15 CVEs table (light theme)
        vuln_data = [[
            Paragraph('<b>CVE ID</b>', ParagraphStyle('VH', parent=styles['Label'], textColor=WHITE)),
            Paragraph('<b>CVSS</b>', ParagraphStyle('VH', parent=styles['Label'], textColor=WHITE, alignment=TA_CENTER)),
            Paragraph('<b>Severity</b>', ParagraphStyle('VH', parent=styles['Label'], textColor=WHITE, alignment=TA_CENTER)),
            Paragraph('<b>Description</b>', ParagraphStyle('VH', parent=styles['Label'], textColor=WHITE)),
        ]]
        for v in vulns[:15]:
            cve_id = safe_str(v.get('cve_id'))
            score = safe_str(v.get('score'))
            sev = str(v.get('severity', 'UNKNOWN')).upper()
            desc = safe_str(v.get('description'))[:140]
            sev_clr = severity_color(sev)
            vuln_data.append([
                Paragraph(cve_id, styles['MonoBold']),
                Paragraph(score, ParagraphStyle('VC', parent=styles['TableCell'], alignment=TA_CENTER)),
                Paragraph(sev, ParagraphStyle('VS', parent=styles['TableCellBold'], textColor=sev_clr, alignment=TA_CENTER)),
                Paragraph(desc, styles['TableCell']),
            ])
        
        vt = Table(vuln_data, colWidths=[doc.width*0.15, doc.width*0.07, doc.width*0.1, doc.width*0.68])
        vt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_DARK),
            ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
            ('GRID', (0,0), (-1,-1), 0.4, BORDER),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, BG_LIGHT_ALT]),
        ]))
        story.append(vt)
        if len(vulns) > 15:
            story.append(Paragraph(f'<i>... and {len(vulns) - 15} more CVEs</i>', styles['BodySmall']))
        story.append(Spacer(1, 12))

    # ===== REPUTATION =====
    vt_mal = int(vt_dict.get('malicious', 0) or 0)
    vt_susp = int(vt_dict.get('suspicious', 0) or 0)
    vt_harm = int(vt_dict.get('harmless', 0) or 0)
    vt_undet = int(vt_dict.get('undetected', 0) or 0)
    
    if vt_mal + vt_susp + vt_harm + vt_undet > 0:
        add_section('THREAT TELEMETRY (VirusTotal)')
        
        add_kv('Malicious', str(vt_mal), value_color=RED if vt_mal else TEXT_MUTED)
        add_kv('Suspicious', str(vt_susp), value_color=AMBER if vt_susp else TEXT_MUTED)
        add_kv('Harmless', str(vt_harm), value_color=EMERALD)
        add_kv('Undetected', str(vt_undet))
        story.append(Spacer(1, 10))

# ===== CORRELATION FINDINGS =====
    if findings_list:
        story.append(PageBreak())
        add_section('CORRELATION ENGINE FINDINGS')
        
        for f in findings_list:
            sev = str(f.get('severity', 'LOW'))
            cat = str(f.get('category', 'exposure'))
            title = safe_str(f.get('title'))
            desc = safe_str(f.get('description'))
            rec = safe_str(f.get('recommendation'))
            
            sev_clr = severity_color(sev)
            cat_clr = category_color(cat)
            
            # Finding header as clean inline with colored badges
            header_text = f'<b>{title}</b>  <font color="{sev_clr}"><b>[{sev}]</b></font>  <font color="{cat_clr}"><b>[{cat.upper()}]</b></font>'
            
            # Keep each finding together on one page
            finding_elements = [
                Paragraph(header_text, styles['FindingTitle']),
                Paragraph(desc, styles['FindingDesc']),
            ]
            if rec and rec != 'N/A':
                finding_elements.append(Paragraph(f'→ Recommendation: {rec}', styles['Recommendation']))
            finding_elements.append(Spacer(1, 8))
            
            story.append(KeepTogether(finding_elements))
    else:
        add_section('CORRELATION ENGINE FINDINGS')
        story.append(Paragraph('No risk indicators detected for this target.', styles['BodyClean']))
        story.append(Spacer(1, 10))

    # ===== DNS & EMAIL SPOOFING (domain only) =====
    if not target_is_ip and has_data(dns_dict):
        add_section('DNS & EMAIL SPOOFING PROTECTION')
        
        spf = safe_str(dns_dict.get('spf'))
        dmarc = safe_str(dns_dict.get('dmarc'))
        dkim = safe_str(dns_dict.get('dkim'))
        spoof_protected = dns_dict.get('spoofing_protected', False)
        
        add_kv('SPF', 'Configured' if spf != 'NOT SET' else 'Missing', value_color=EMERALD if spf != 'NOT SET' else RED)
        add_kv('DKIM', 'Detected' if dkim == 'DETECTED' else 'Not Detected', value_color=EMERALD if dkim == 'DETECTED' else TEXT_MUTED)
        add_kv('DMARC', 'Configured' if dmarc != 'NOT SET' else 'Missing', value_color=EMERALD if dmarc != 'NOT SET' else RED)
        add_kv('Spoofing Protection', 'Protected' if spoof_protected else 'Vulnerable', value_color=EMERALD if spoof_protected else RED)
        story.append(Spacer(1, 12))

    # ===== FOOTER =====
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 8))
    footer_text = f"Generated by ThreatLens SOC Platform • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} • Report ID: {scan.id}"
    story.append(Paragraph(footer_text, styles['FooterText']))

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.read()