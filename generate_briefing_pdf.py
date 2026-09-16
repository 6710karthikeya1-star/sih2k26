from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def build_pdf(filename="SIH_Pipeline_Steps_1_to_4_Briefing.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    styles = getSampleStyleSheet()
    story = []

    # Custom Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1a252f")
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#7f8c8d")
    )
    h2_style = ParagraphStyle(
        'SecHead',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2980b9")
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#2c3e50")
    )

    # Title Banner
    story.append(Paragraph("Smart India Hackathon (SIH26151: NTRO)", title_style))
    story.append(Paragraph("System Architecture & Completed Implementation Walkthrough (Steps 1 - 4)", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2980b9"), spaceAfter=15))

    # Executive Summary Table
    summary_data = [
        [Paragraph("<b>Step</b>", body_style), Paragraph("<b>Module Name</b>", body_style), Paragraph("<b>Core Capability Delivered</b>", body_style)],
        [Paragraph("Step 1", body_style), Paragraph("Evidence Collection", body_style), Paragraph("Scrapes BTC, ETH, XMR wallets, handles, PGP keys; logs SHA-256 hashes.", body_style)],
        [Paragraph("Step 2", body_style), Paragraph("Storage & Entity Resolution", body_style), Paragraph("Multi-pivot correlation merging fragmented aliases into unified Actor UUIDs.", body_style)],
        [Paragraph("Step 3", body_style), Paragraph("Correlation Engine", body_style), Paragraph("Bipartite graph mapping (NetworkX) detecting co-conspirator syndicates.", body_style)],
        [Paragraph("Step 4", body_style), Paragraph("OPSEC & Infra Analysis", body_style), Paragraph("Murmur3 favicon hashing & HTML DOM skeleton checks identifying clone sites.", body_style)]
    ]
    t = Table(summary_data, colWidths=[55, 145, 330])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#ecf0f1")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#bdc3c7")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 15))

    # Detailed Step Explanations
    sections = [
        ("Step 1 - Evidence Collection (entity_extractor.py)",
         "Threat actors deliberately disguise their traces. This module parses raw, unstructured HTML from dark web platforms. "
         "Using regular expressions and DOM sanitization, it extracts Bitcoin (Legacy/Bech32), Ethereum, Monero addresses, PGP key blocks, "
         "and communication handles (Jabber, Telegram, TOX). To ensure court admissibility, every capture generates a cryptographic "
         "SHA-256 content checksum and UTC timestamp to prove data integrity."),

        ("Step 2 - Evidence Storage & Deterministic Resolution (resolution_pipeline.py)",
         "Criminals operate under rotating pseudonyms across separate forums (e.g., DreadOps on Dread vs. ApexBreach on Exploit). "
         "This module manages a relational schema and executes multi-pivot entity resolution. When new evidence arrives, it evaluates "
         "overlapping wallets, handles, or PGP keys. If any identifier matches, the engine links the new alias directly to the existing master "
         "Actor UUID, preventing fragmented profiles and establishing shared attribution automatically."),

        ("Step 3 - Evidence Correlation Engine (correlation_engine.py)",
         "Identities are rarely isolated in single-step relationships. Using NetworkX, this module constructs an undirected bipartite network "
         "connecting actors to their shared financial and communication footprints. Connected component algorithms automatically cluster "
         "co-conspirators into criminal syndicates, while shortest-path algorithms trace forensic linkages across multiple hops."),

        ("Step 4 - OPSEC & Infrastructure Analysis (opsec_analyzer.py)",
         "Even when threat actors change usernames and contact information, they often reuse web infrastructure. This module profiles "
         "onion sites through two technical vectors: (1) Shodan-standard MurmurHash3 favicon hashing, and (2) HTML DOM skeleton structural "
         "hashing. By matching these fingerprints across different .onion hidden services, the engine exposes backend template reuse and shared server hosting.")
    ]

    for title, desc in sections:
        story.append(Paragraph(title, h2_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 10))

    # Verification Note
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=10))
    story.append(Paragraph(
        "<b>Verification Status:</b> All 4 modules have been validated locally inside the project environment. "
        "Threat actor resolution was verified via FastAPI Swagger endpoints, network links were rendered in PyVis, and OPSEC leaks were identified between separate onion services.",
        body_style
    ))

    doc.build(story)
    print(f"[+] Summary briefing PDF generated successfully: {filename}")

if __name__ == "__main__":
    build_pdf()
