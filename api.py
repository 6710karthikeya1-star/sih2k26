from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os
from db_manager import get_connection
from report_generator import InvestigationReportGenerator

app = FastAPI(title="NTRO Dark Web Intel System", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/actors")
def list_actors():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT 
            a.actor_id, 
            a.primary_label, 
            a.risk_score, 
            COUNT(DISTINCT al.alias_id) AS alias_count,
            COUNT(DISTINCT cw.wallet_id) AS wallet_count,
            COUNT(DISTINCT ip.ip_id) AS ip_leak_count
        FROM threat_actors a
        LEFT JOIN actor_aliases al ON a.actor_id = al.actor_id
        LEFT JOIN crypto_wallets cw ON a.actor_id = cw.actor_id
        LEFT JOIN ip_addresses ip ON a.actor_id = ip.actor_id
        GROUP BY a.actor_id
        ORDER BY a.last_observed DESC;
    ''')
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows

@app.get("/api/v1/actors/{actor_id}")
def get_actor_detail(actor_id: str):
    rep = InvestigationReportGenerator()
    try:
        return rep.fetch_full_actor_record(actor_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Actor not found")

@app.get("/api/v1/reports/{actor_id}/pdf")
def download_pdf_report(actor_id: str):
    rep = InvestigationReportGenerator()
    try:
        pdf_path = rep.export_pdf(actor_id)
        return FileResponse(pdf_path, media_type="application/pdf", filename=os.path.basename(pdf_path))
    except ValueError:
        raise HTTPException(status_code=404, detail="Actor not found")

@app.get("/dashboard", response_class=HTMLResponse)
def investigation_dashboard():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NTRO Dark Web Intel Dashboard</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background:#0f172a; color:#f8fafc; padding:24px; }
        header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #334155; padding-bottom:16px; margin-bottom:24px; }
        h1 { font-size:22px; color:#38bdf8; }
        .badge { background:#dc2626; padding:4px 10px; border-radius:6px; font-size:12px; font-weight:bold; }
        .grid { display:grid; grid-template-columns: 1fr 2fr; gap:20px; }
        .card { background:#1e293b; border-radius:8px; border:1px solid #334155; padding:18px; }
        .card h2 { font-size:15px; margin-bottom:12px; color:#94a3b8; text-transform:uppercase; }
        table { width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }
        th, td { padding:10px; text-align:left; border-bottom:1px solid #334155; }
        th { color:#94a3b8; font-weight:600; }
        .risk-pill { padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px; background:#ef4444; color:#fff; }
        .ip-badge { background:#b91c1c; color:#fff; padding:2px 6px; border-radius:4px; font-weight:bold; font-size:11px; }
        .btn { background:#0284c7; color:#fff; border:none; padding:6px 12px; border-radius:4px; cursor:pointer; font-size:12px; text-decoration:none; display:inline-block; }
        .btn:hover { background:#0369a1; }
        pre { background:#0f172a; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto; border:1px solid #334155; }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>NTRO Darknet Threat Attribution Platform</h1>
            <p style="color:#64748b; font-size:13px;">SIH26151: Real-Time De-Anonymization & Infrastructure Leaks</p>
        </div>
        <span class="badge">IP LEAK DETECTION ACTIVE</span>
    </header>
    
    <div class="grid">
        <div class="card">
            <h2>Resolved Targets</h2>
            <div id="target-list">Loading actors...</div>
        </div>
        <div class="card">
            <h2>Target Dossier & Forensic Chain of Custody</h2>
            <div id="target-detail"><p style="color:#64748b;">Select an actor to view linked profiles.</p></div>
        </div>
    </div>

    <script>
        async function loadActors() {
            const res = await fetch('/api/v1/actors');
            const actors = await res.json();
            let html = '<table><thead><tr><th>Primary Label</th><th>Risk</th><th>Aliases</th><th>IP Leaks</th><th>Action</th></tr></thead><tbody>';
            actors.forEach(a => {
                html += `<tr>
                    <td><b>${a.primary_label}</b></td>
                    <td><span class="risk-pill">${a.risk_score}/100</span></td>
                    <td>${a.alias_count}</td>
                    <td><span class="ip-badge">${a.ip_leak_count}</span></td>
                    <td><button class="btn" onclick="viewDetail('${a.actor_id}')">Inspect</button></td>
                </tr>`;
            });
            html += '</tbody></table>';
            document.getElementById('target-list').innerHTML = html;
            if(actors.length > 0) viewDetail(actors[0].actor_id);
        }

        async function viewDetail(actorId) {
            const res = await fetch(`/api/v1/actors/${actorId}`);
            const data = await res.json();
            let p = data.actor_profile;
            let ipHtml = data.leaked_ips.length > 0
                ? `<div style="background:#450a0a; border:1px solid #ef4444; border-radius:6px; padding:10px; margin:12px 0;">
                     <h4 style="color:#f87171; font-size:13px;">CRITICAL: Clearnet IP Leaks Discovered</h4>
                     <ul>${data.leaked_ips.map(ip => `<li style="margin-left:20px; font-size:12px; color:#fca5a5;"><b>${ip.ip_address}</b> (Source: ${ip.leak_source})</li>`).join('')}</ul>
                   </div>`
                : '';

            let html = `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                    <div>
                        <h3 style="color:#f8fafc; font-size:18px;">${p.primary_label}</h3>
                        <span style="font-size:11px; color:#64748b;">UUID: ${p.actor_id}</span>
                    </div>
                    <a href="/api/v1/reports/${p.actor_id}/pdf" target="_blank" class="btn" style="background:#10b981;">Download Case PDF</a>
                </div>
                ${ipHtml}
                <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Unified Cross-Market Aliases:</h4>
                <ul>${data.aliases.map(a => `<li style="margin-left:20px; font-size:12px;"><b>${a.alias_name}</b> (Platform: ${a.source_platform})</li>`).join('')}</ul>
                
                <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Discovered Crypto Wallets:</h4>
                <ul>${data.crypto_wallets.map(w => `<li style="margin-left:20px; font-size:12px;"><b>[${w.currency}]</b> ${w.address}</li>`).join('')}</ul>

                <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Contact Identifiers:</h4>
                <ul>${data.contact_handles.map(h => `<li style="margin-left:20px; font-size:12px;"><b>[${h.handle_type.toUpperCase()}]</b> ${h.handle_value}</li>`).join('')}</ul>

                <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Digital Evidence Chain of Custody:</h4>
                <pre>${JSON.stringify(data.forensic_evidence, null, 2)}</pre>
            `;
            document.getElementById('target-detail').innerHTML = html;
        }
        loadActors();
    </script>
</body>
</html>"""
