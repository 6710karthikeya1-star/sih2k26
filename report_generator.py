import json
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from db_manager import get_connection

class InvestigationReportGenerator:
    def __init__(self):
        self.conn = get_connection()

    def fetch_full_actor_record(self, actor_id: str) -> dict:
        cur = self.conn.cursor()
        
        cur.execute("SELECT * FROM threat_actors WHERE actor_id = ?;", (actor_id,))
        actor_row = cur.fetchone()
        if not actor_row:
            raise ValueError(f"Actor with ID {actor_id} not found.")

        cur.execute("SELECT alias_name, source_platform FROM actor_aliases WHERE actor_id = ?;", (actor_id,))
        aliases = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT currency, address FROM crypto_wallets WHERE actor_id = ?;", (actor_id,))
        wallets = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT handle_type, handle_value FROM contact_handles WHERE actor_id = ?;", (actor_id,))
        handles = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT ip_address, leak_source FROM ip_addresses WHERE actor_id = ?;", (actor_id,))
        ips = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT source_url, sha256_checksum, crawled_at FROM raw_evidence_log LIMIT 5;")
        evidence = [dict(r) for r in cur.fetchall()]

        return {
            "actor_profile": dict(actor_row),
            "aliases": aliases,
            "crypto_wallets": wallets,
            "contact_handles": handles,
            "leaked_ips": ips,
            "forensic_evidence": evidence,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

    def export_pdf(self, actor_id: str, filename: str = None) -> str:
        data = self.fetch_full_actor_record(actor_id)
        actor = data["actor_profile"]
        filename = filename or f"report_actor_{actor_id[:8]}.pdf"

        doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle('TitleStyle', fontName='Helvetica-Bold', fontSize=18, leading=22, textColor=colors.HexColor("#1a252f"))
        h2_style = ParagraphStyle('H2Style', fontName='Helvetica-Bold', fontSize=12, leading=16, textColor=colors.HexColor("#2980b9"))
        body_style = ParagraphStyle('BodyStyle', fontName='Helvetica', fontSize=9, leading=12, textColor=colors.HexColor("#2c3e50"))

        story.append(Paragraph("NTRO - THREAT INTEL DOSSIER", title_style))
        story.append(Paragraph(f"Forensic Intelligence Case File: ACTOR-{actor_id}", body_style))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2980b9"), spaceAfter=12))

        profile_data = [
            [Paragraph("<b>Primary Target Label:</b>", body_style), Paragraph(str(actor.get('primary_label', 'Unknown')), body_style)],
            [Paragraph("<b>Target Master UUID:</b>", body_style), Paragraph(str(actor.get('actor_id', actor_id)), body_style)],
            [Paragraph("<b>Attribution Risk Score:</b>", body_style), Paragraph(f"{actor.get('risk_score', 90)} / 100", body_style)]
        ]
        t_prof = Table(profile_data, colWidths=[160, 380])
        t_prof.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8f9fa")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#bdc3c7")),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_prof)
        story.append(Spacer(1, 14))

        if data["leaked_ips"]:
            story.append(Paragraph("Discovered Clearnet IP Leaks", h2_style))
            story.append(Spacer(1, 4))
            ip_rows = [[Paragraph("<b>Leaked IP Address</b>", body_style), Paragraph("<b>Source</b>", body_style)]]
            for ip in data["leaked_ips"]:
                ip_rows.append([Paragraph(f"<font color='red'><b>{ip['ip_address']}</b></font>", body_style), Paragraph(str(ip.get('leak_source', 'Tor')), body_style)])
            t_ip = Table(ip_rows, colWidths=[160, 380])
            t_ip.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fee2e2")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#ef4444")),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(t_ip)
            story.append(Spacer(1, 14))

        doc.build(story)
        return filename
