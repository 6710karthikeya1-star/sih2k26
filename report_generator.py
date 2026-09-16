import json
import pandas as pd
from datetime import datetime
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
        actor = cur.fetchone()
        if not actor:
            raise ValueError(f"Actor with ID {actor_id} not found.")

        cur.execute("SELECT alias_name, source_platform, first_seen FROM actor_aliases WHERE actor_id = ?;", (actor_id,))
        aliases = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT currency, address, first_seen FROM crypto_wallets WHERE actor_id = ?;", (actor_id,))
        wallets = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT handle_type, handle_value FROM contact_handles WHERE actor_id = ?;", (actor_id,))
        handles = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT ip_address, leak_source, first_seen FROM ip_addresses WHERE actor_id = ?;", (actor_id,))
        ips = [dict(r) for r in cur.fetchall()]

        cur.execute('''
            SELECT DISTINCT e.source_url, e.sha256_checksum, e.crawled_at 
            FROM raw_evidence_log e
            JOIN actor_aliases a ON a.evidence_id = e.evidence_id
            WHERE a.actor_id = ?;
        ''', (actor_id,))
        evidence = [dict(r) for r in cur.fetchall()]

        return {
            "actor_profile": dict(actor),
            "aliases": aliases,
            "crypto_wallets": wallets,
            "contact_handles": handles,
            "leaked_ips": ips,
            "forensic_evidence": evidence,
            "generated_at": datetime.utcnow().isoformat() + "Z"
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

        story.append(Paragraph("NTRO / SIH26151 - THREAT INTEL DOSSIER", title_style))
        story.append(Paragraph(f"Forensic Intelligence Case File: ACTOR-{actor_id}", body_style))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2980b9"), spaceAfter=12))

        # Actor Profile Summary
        profile_data = [
            [Paragraph("<b>Primary Target Label:</b>", body_style), Paragraph(str(actor['primary_label']), body_style)],
            [Paragraph("<b>Target Master UUID:</b>", body_style), Paragraph(str(actor['actor_id']), body_style)],
            [Paragraph("<b>Attribution Risk Score:</b>", body_style), Paragraph(f"{actor.get('risk_score', 1)} / 100", body_style)],
            [Paragraph("<b>First / Last Seen (UTC):</b>", body_style), Paragraph(f"{actor['first_observed']}  |  {actor['last_observed']}", body_style)]
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

        # De-anonymized IPs
        if data["leaked_ips"]:
            story.append(Paragraph("Discovered Clearnet IP Leaks", h2_style))
            story.append(Spacer(1, 4))
            ip_rows = [[Paragraph("<b>Leaked IP Address</b>", body_style), Paragraph("<b>Source URL</b>", body_style)]]
            for ip in data["leaked_ips"]:
                ip_rows.append([Paragraph(f"<font color='red'><b>{ip['ip_address']}</b></font>", body_style), Paragraph(ip['leak_source'], body_style)])
            t_ip = Table(ip_rows, colWidths=[160, 380])
            t_ip.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fee2e2")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#ef4444")),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(t_ip)
            story.append(Spacer(1, 14))

        # Linked Identities Table
        story.append(Paragraph("De-anonymized Aliases & Channels", h2_style))
        story.append(Spacer(1, 4))
        alias_rows = [[Paragraph("<b>Alias</b>", body_style), Paragraph("<b>Platform</b>", body_style), Paragraph("<b>Timestamp</b>", body_style)]]
        for a in data["aliases"]:
            alias_rows.append([Paragraph(a['alias_name'], body_style), Paragraph(a['source_platform'], body_style), Paragraph(str(a['first_seen']), body_style)])
        t_alias = Table(alias_rows, colWidths=[150, 150, 240])
        t_alias.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#ecf0f1")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#bdc3c7")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_alias)
        story.append(Spacer(1, 14))

        # Wallets
        story.append(Paragraph("Identified Cryptocurrency Wallets", h2_style))
        story.append(Spacer(1, 4))
        wallet_rows = [[Paragraph("<b>Currency</b>", body_style), Paragraph("<b>Address</b>", body_style)]]
        for w in data["crypto_wallets"]:
            wallet_rows.append([Paragraph(w['currency'], body_style), Paragraph(w['address'], body_style)])
        t_wall = Table(wallet_rows, colWidths=[80, 460])
        t_wall.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#ecf0f1")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#bdc3c7")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_wall)

        doc.build(story)
        return filename
