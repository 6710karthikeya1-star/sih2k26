from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_docs_pdf(filename="SIH_NTRO_Full_System_Documentation.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    styles = getSampleStyleSheet()
    story = []

    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#475569")
    )
    h1_style = ParagraphStyle(
        'H1Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        spaceBefore=10,
        spaceAfter=4
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=6,
        spaceAfter=2
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#334155")
    )
    code_style = ParagraphStyle(
        'CodeText',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    # Document Header
    story.append(Paragraph("NTRO Dark Web Threat Actor De-Anonymization System", title_style))
    story.append(Paragraph("Smart India Hackathon (SIH26151) | Complete Technical Documentation (Steps 1 - 8)", subtitle_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # Executive Summary
    story.append(Paragraph("<b>System Overview:</b> This platform is an automated end-to-end intelligence and forensic attribution engine built for intelligence analysts to de-anonymize threat actors operating on Tor hidden services (.onion). The architecture spans raw crawling, deterministic entity resolution, infrastructure fingerprinting, NLP stylometry, confidence scoring, real-time query dashboards, and evidentiary reporting.", body_style))
    story.append(Spacer(1, 8))

    # Summary Architecture Table
    summary_data = [
        [Paragraph("<b>Step</b>", body_style), Paragraph("<b>Module Name</b>", body_style), Paragraph("<b>Target Objective & Core Mechanism</b>", body_style)],
        [Paragraph("<b>Step 1</b>", body_style), Paragraph("Evidence Collection", body_style), Paragraph("Scrapes BTC, ETH, XMR addresses, handles, and PGP blocks; logs SHA-256 hashes.", body_style)],
        [Paragraph("<b>Step 2</b>", body_style), Paragraph("Storage & Resolution", body_style), Paragraph("Relational SQLite schema; multi-pivot merging into unified Threat Actor UUIDs.", body_style)],
        [Paragraph("<b>Step 3</b>", body_style), Paragraph("Correlation Engine", body_style), Paragraph("Bipartite graph mapping (NetworkX) detecting co-conspirator syndicates & multi-hop paths.", body_style)],
        [Paragraph("<b>Step 4</b>", body_style), Paragraph("OPSEC & Infra Analysis", body_style), Paragraph("Murmur3 favicon hashing & DOM tree skeleton analysis exposing shared hidden servers.", body_style)],
        [Paragraph("<b>Step 5</b>", body_style), Paragraph("AI Stylometric Analysis", body_style), Paragraph("Character n-gram TF-IDF & Cosine Similarity correlating forum writing patterns.", body_style)],
        [Paragraph("<b>Step 6</b>", body_style), Paragraph("Attribution & Scoring", body_style), Paragraph("Weighted heuristic engine scoring overall forensic linkage confidence (0 - 100).", body_style)],
        [Paragraph("<b>Step 7</b>", body_style), Paragraph("Analyst Dashboard", body_style), Paragraph("Interactive browser workspace with search, target inspection, and entity graph links.", body_style)],
        [Paragraph("<b>Step 8</b>", body_style), Paragraph("Forensic Case Export", body_style), Paragraph("Court-admissible PDF dossier, JSON payload, and CSV export with full chain of custody.", body_style)]
    ]
    t = Table(summary_data, colWidths=[45, 125, 370])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Module Walkthroughs
    modules = [
        ("Step 1: Evidence Collection (entity_extractor.py)",
         "Parses unstructured HTML payloads from darknet posts using regular expressions. Extracts Legacy and Bech32 Bitcoin, "
         "Ethereum, standard and sub-address Monero, PGP public key blocks, and communications handles (Jabber, Telegram, TOX). "
         "To maintain court admissibility, each ingested payload generates an immutable SHA-256 checksum and UTC timestamp."),

        ("Step 2: Evidence Storage & Deterministic Resolution (resolution_pipeline.py)",
         "Manages the relational intelligence.db SQLite schema. Threat actors cycle aliases across forums (e.g., DreadOps vs. ApexBreach). "
         "The resolution pipeline executes multi-pivot lookups across crypto wallets, contact handles, and PGP blocks. When a matching "
         "identifier is found, the engine binds the new identity to the target's existing master UUID instead of creating duplicates."),

        ("Step 3: Evidence Correlation Engine (correlation_engine.py)",
         "Models threat data as an undirected bipartite graph using NetworkX, connecting threat actors to shared financial and "
         "communication identifiers. Implements connected components analysis to identify criminal rings and shortest-path graph "
         "traversals to establish multi-hop forensic chains linking actors who have not directly communicated."),

        ("Step 4: OPSEC & Infrastructure Analysis (opsec_analyzer.py)",
         "Identifies backend operational security leaks across hidden services without relying on textual data. Computes Shodan-compatible "
         "32-bit MurmurHash3 signatures from base64 favicon bytes and extracts SHA-256 DOM skeleton tag trees. Identical hashes across "
         "distinct .onion addresses prove shared site administration or clone kit reuse."),

        ("Step 5: AI-Based Stylometric Analysis (stylometry_analyzer.py)",
         "Performs linguistic profiling on anonymous forum text. Extracts lexical features (sentence length, punctuation density, "
         "capitalization ratios) and builds Character n-gram TF-IDF vector embeddings (3-5 char ranges). Computes Cosine Similarity "
         "to identify syntax habits, spelling patterns, and idiosyncratic typing styles across aliases."),

        ("Step 6: Attribution & Confidence Scoring Engine (confidence_scorer.py)",
         "Aggregates disparate findings into an auditable confidence score (0 - 100): PGP Match (+40), Crypto Address (+35), "
         "Direct Handle (+25), Infrastructure/Favicon Match (+20), and Stylometric Match (+20). Updates threat_actors.risk_score "
         "and generates a human-readable audit trail explaining the evidence weight."),

        ("Step 7: Investigation Dashboard (api.py)",
         "A unified FastAPI web workspace accessible at /dashboard. Allows investigators to search threat actors, view risk indicators, "
         "inspect unified cross-market aliases and crypto trails, examine raw forensic hashes, and download reports with one click."),

        ("Step 8: Report Generation & Export (report_generator.py)",
         "Pulls the complete target case file and exports structured JSON, CSV tables, and tamper-proof PDF dossiers containing "
         "case headers, alias timelines, financial footprint tables, and forensic chain-of-custody checksums.")
    ]

    for title, desc in modules:
        story.append(Paragraph(title, h1_style))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 4))

    # Operational Runbook / Commands
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))
    story.append(Paragraph("System Operational Runbook (Execution Commands)", h1_style))

    runbook_data = [
        [Paragraph("<b>Action</b>", body_style), Paragraph("<b>PowerShell Command</b>", body_style)],
        [Paragraph("1. Initialize DB & Seed Data", body_style), Paragraph("python db_manager.py ; python main.py", code_style)],
        [Paragraph("2. Run Graph Correlation", body_style), Paragraph("python correlation_engine.py", code_style)],
        [Paragraph("3. Run OPSEC & Infra Check", body_style), Paragraph("python opsec_analyzer.py", code_style)],
        [Paragraph("4. Run Stylometry & Scoring", body_style), Paragraph("python stylometry_analyzer.py ; python confidence_scorer.py", code_style)],
        [Paragraph("5. Export Reports (PDF/CSV)", body_style), Paragraph("python report_generator.py", code_style)],
        [Paragraph("6. Launch Analyst Dashboard", body_style), Paragraph("uvicorn api:app --reload  -->  http://127.0.0.1:8000/dashboard", code_style)]
    ]
    t_run = Table(runbook_data, colWidths=[140, 400])
    t_run.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_run)

    doc.build(story)
    print(f"[+] Complete System Documentation PDF generated: {filename}")

if __name__ == "__main__":
    generate_docs_pdf()
