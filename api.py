from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
import uuid
from datetime import datetime, timezone
from db_manager import get_connection, init_database
from report_generator import InvestigationReportGenerator
from entity_extractor import ThreatEntityExtractor
from resolution_pipeline import EntityResolutionPipeline
import seed_demo_data

def ensure_seeded():
    try:
        init_database()
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threat_actors;")
        count = cur.fetchone()[0]
        conn.close()
        if count == 0:
            print("[AUTO-HEAL] No threat actors found. Seeding 4 default targets...")
            seed_demo_data.seed_multiple_targets()
    except Exception as e:
        print(f"[AUTO-HEAL LOG] {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_seeded()
    yield

app = FastAPI(title="NTRO Threat Attribution Engine", version="3.6.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy"}

@app.get("/api/v1/actors")
def list_actors():
    ensure_seeded()
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
    except Exception:
        raise HTTPException(status_code=404, detail="Actor not found")

@app.get("/api/v1/reports/{actor_id}/pdf")
def download_pdf_report(actor_id: str):
    rep = InvestigationReportGenerator()
    try:
        pdf_path = rep.export_pdf(actor_id)
        return FileResponse(pdf_path, media_type="application/pdf", filename=os.path.basename(pdf_path))
    except Exception:
        raise HTTPException(status_code=404, detail="Report generation failed")

@app.get("/api/v1/graph/data")
def get_graph_data():
    ensure_seeded()
    conn = get_connection()
    cur = conn.cursor()
    nodes = []
    edges = []

    cur.execute("SELECT actor_id, primary_label, risk_score FROM threat_actors;")
    for row in cur.fetchall():
        nodes.append({
            "id": f"actor_{row['actor_id']}",
            "label": f"TARGET: {row['primary_label']}",
            "color": "#ef4444",
            "shape": "diamond",
            "size": 28
        })

    cur.execute("SELECT actor_id, alias_name, source_platform FROM actor_aliases;")
    for row in cur.fetchall():
        a_node = f"alias_{row['alias_name']}"
        nodes.append({
            "id": a_node,
            "label": f"[{row['source_platform']}] {row['alias_name']}",
            "color": "#38bdf8",
            "shape": "dot",
            "size": 18
        })
        edges.append({"from": f"actor_{row['actor_id']}", "to": a_node, "label": "USES_ALIAS"})

    cur.execute("SELECT actor_id, currency, address FROM crypto_wallets;")
    for row in cur.fetchall():
        w_node = f"wallet_{row['address']}"
        nodes.append({
            "id": w_node,
            "label": f"{row['currency']}: {row['address'][:8]}...",
            "color": "#f59e0b",
            "shape": "triangle",
            "size": 16
        })
        edges.append({"from": f"actor_{row['actor_id']}", "to": w_node, "label": "TRANSACTS_VIA"})

    cur.execute("SELECT actor_id, handle_type, handle_value FROM contact_handles;")
    for row in cur.fetchall():
        c_node = f"contact_{row['handle_value']}"
        nodes.append({
            "id": c_node,
            "label": f"{row['handle_type'].upper()}: {row['handle_value']}",
            "color": "#10b981",
            "shape": "square",
            "size": 16
        })
        edges.append({"from": f"actor_{row['actor_id']}", "to": c_node, "label": "CONTACT_PIVOT"})

    cur.execute("SELECT actor_id, ip_address FROM ip_addresses;")
    for row in cur.fetchall():
        ip_node = f"ip_{row['ip_address']}"
        nodes.append({
            "id": ip_node,
            "label": f"LEAKED IP: {row['ip_address']}",
            "color": "#dc2626",
            "shape": "star",
            "size": 24
        })
        edges.append({"from": f"actor_{row['actor_id']}", "to": ip_node, "label": "INFRA_LEAK"})

    conn.close()
    return {"nodes": nodes, "edges": edges}

@app.post("/api/v1/ingest/live")
def live_ingest(payload: dict = Body(...)):
    raw_text = payload.get("text", "")
    alias = payload.get("alias", "Unknown_Alias")
    platform = payload.get("platform", "Live_Submission")
    source_url = payload.get("url", f"http://manual-inspect-{uuid.uuid4().hex[:6]}.onion/feed")

    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="Evidence text cannot be empty")

    try:
        extractor = ThreatEntityExtractor()
        resolver = EntityResolutionPipeline()

        extracted = extractor.extract_entities(raw_text, source_url)
        extracted["evidence_metadata"]["raw_html"] = raw_text
        actor_id = resolver.resolve_and_store(extracted, alias, platform)

        return {
            "status": "INGESTION_SUCCESS",
            "actor_id": actor_id,
            "sha256_checksum": extracted["evidence_metadata"]["sha256_checksum"],
            "extracted_entities": extracted
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")

@app.get("/dashboard", response_class=HTMLResponse)
def investigation_dashboard():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NTRO Threat Attribution & Entity Resolution Suite</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background:#0b1120; color:#f8fafc; padding:20px; }
        header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:16px; margin-bottom:20px; }
        h1 { font-size:22px; color:#38bdf8; display:flex; align-items:center; gap:8px; }
        .badge { background:#0284c7; padding:4px 10px; border-radius:4px; font-size:12px; font-weight:bold; }
        .tabs { display:flex; gap:10px; margin-bottom:18px; }
        .tab-btn { background:#1e293b; color:#94a3b8; border:1px solid #334155; padding:8px 16px; border-radius:6px; cursor:pointer; font-weight:600; font-size:13px; transition:0.2s; }
        .tab-btn.active { background:#0284c7; color:#fff; border-color:#38bdf8; }
        .grid { display:grid; grid-template-columns: 1fr 2fr; gap:20px; }
        .card { background:#111827; border-radius:8px; border:1px solid #1f2937; padding:18px; }
        .card h2 { font-size:14px; margin-bottom:12px; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; }
        table { width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }
        th, td { padding:10px; text-align:left; border-bottom:1px solid #1f2937; }
        th { color:#94a3b8; font-weight:600; }
        .risk-pill { padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px; background:#ef4444; color:#fff; }
        .ip-badge { background:#b91c1c; color:#fff; padding:2px 6px; border-radius:4px; font-weight:bold; font-size:11px; }
        .btn { background:#0284c7; color:#fff; border:none; padding:6px 12px; border-radius:4px; cursor:pointer; font-size:12px; text-decoration:none; display:inline-block; font-weight:600; }
        .btn:hover { background:#0369a1; }
        .step-next-btn { background: linear-gradient(135deg, #0284c7, #2563eb); border:1px solid #38bdf8; color:#fff; padding:10px 18px; border-radius:6px; font-size:13px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:8px; margin-top:16px; }
        .step-next-btn:hover { background: linear-gradient(135deg, #0369a1, #1d4ed8); }
        pre { background:#030712; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto; border:1px solid #1f2937; color:#38bdf8; min-height: 180px; white-space: pre-wrap; }
        #network-graph { width: 100%; height: 620px; background:#030712; border-radius:8px; border:1px solid #1f2937; }
        textarea, input { width:100%; background:#030712; border:1px solid #334155; color:#fff; padding:10px; border-radius:6px; font-size:13px; margin-bottom:10px; }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>🛡️ NTRO Threat Attribution Engine</h1>
            <p style="color:#64748b; font-size:13px;">Automated Darknet De-Anonymization, Multi-Pivot Entity Resolution & Infrastructure Fingerprinting</p>
        </div>
        <span class="badge">NIST SP 800-86 FORENSIC READY</span>
    </header>

    <div class="tabs">
        <button id="tab-dossier-btn" class="tab-btn active" onclick="switchView('dossier')">1. Target Dossier View</button>
        <button id="tab-graph-btn" class="tab-btn" style="display:none;" onclick="switchView('graph')">2. Interactive Syndicate Network Graph</button>
        <button id="tab-sandbox-btn" class="tab-btn" style="display:none;" onclick="switchView('sandbox')">3. Live Evidence Ingestion Sandbox</button>
    </div>
    
    <div id="view-dossier" class="grid">
        <div class="card">
            <h2>Resolved Targets</h2>
            <div id="target-list">Loading actors...</div>
        </div>
        <div class="card">
            <h2>Target Dossier & Forensic Chain of Custody</h2>
            <div id="target-detail"><p style="color:#64748b;">Select an actor to view linked profiles.</p></div>
        </div>
    </div>

    <div id="view-graph" style="display:none;" class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:10px;">
            <div>
                <h2>Bipartite Intelligence Graph (Multi-Hop De-Anonymization Clusters)</h2>
                <span style="font-size:12px; color:#94a3b8;">🔴 Target Diamond &nbsp;|&nbsp; 🔵 Alias &nbsp;|&nbsp; 🟡 Crypto &nbsp;|&nbsp; 🟢 Contact &nbsp;|&nbsp; ⭐ Leaked Origin IP</span>
            </div>
            <button class="step-next-btn" onclick="openStep3()">
                Proceed to Step 3: Test New Evidence in Live Sandbox ➔
            </button>
        </div>
        <div id="network-graph"></div>
    </div>

    <div id="view-sandbox" style="display:none;" class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
            <h2>Live Dark Web Ingestion Terminal (Evaluate in Real-Time)</h2>
            <button class="btn" style="background:#334155;" onclick="switchView('dossier')">
                ⬅ Return to Step 1: Target Dossier
            </button>
        </div>
        <p style="color:#94a3b8; font-size:13px; margin-bottom:14px;">Paste any unstructured darknet post below to watch our engine extract cryptographic pivots, compute SHA-256 integrity, and resolve aliases live:</p>
        
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:14px;">
            <div>
                <input id="input-alias" placeholder="Suspect Handle (e.g., PhantomRaven)" />
                <input id="input-platform" placeholder="Marketplace / Forum (e.g., Dread Forum)" />
                <textarea id="input-text" rows="8" placeholder="Enter post text with BTC address, Jabber ID, or proxy IP leak..."></textarea>
                <button class="btn" style="width:100%; padding:10px;" onclick="submitLiveEvidence()">⚡ Execute Live Ingestion & Resolution</button>
            </div>
            <div>
                <h3 style="font-size:13px; color:#94a3b8; margin-bottom:8px;">Live Engine Terminal Output</h3>
                <pre id="sandbox-output">// Awaiting input...</pre>
            </div>
        </div>
    </div>

    <script>
        let currentActors = [];
        let network = null;

        function openStep2() {
            document.getElementById('tab-graph-btn').style.display = 'inline-block';
            switchView('graph');
        }

        function openStep3() {
            document.getElementById('tab-sandbox-btn').style.display = 'inline-block';
            switchView('sandbox');
        }

        function switchView(tab) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('view-dossier').style.display = (tab === 'dossier') ? 'grid' : 'none';
            document.getElementById('view-graph').style.display = (tab === 'graph') ? 'block' : 'none';
            document.getElementById('view-sandbox').style.display = (tab === 'sandbox') ? 'block' : 'none';

            if(tab === 'dossier') document.getElementById('tab-dossier-btn').classList.add('active');
            if(tab === 'graph') {
                document.getElementById('tab-graph-btn').classList.add('active');
                renderGraph();
            }
            if(tab === 'sandbox') document.getElementById('tab-sandbox-btn').classList.add('active');
        }

        async function loadActors() {
            try {
                const res = await fetch('/api/v1/actors');
                currentActors = await res.json();
                if (!Array.isArray(currentActors) || currentActors.length === 0) {
                    document.getElementById('target-list').innerHTML = '<p style="color:#38bdf8; padding:8px;">Syncing targets from ledger...</p>';
                    setTimeout(loadActors, 1500);
                    return;
                }
                let html = '<table><thead><tr><th>Primary Label</th><th>Risk</th><th>Aliases</th><th>IP Leaks</th><th>Action</th></tr></thead><tbody>';
                currentActors.forEach(a => {
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
                if(currentActors.length > 0 && currentActors[0].actor_id !== 'error') {
                    viewDetail(currentActors[0].actor_id);
                }
            } catch(err) {
                document.getElementById('target-list').innerHTML = `<p style="color:#f87171; padding:8px;">Reconnecting to backend: ${err.message}</p>`;
                setTimeout(loadActors, 2000);
            }
        }

        async function viewDetail(actorId) {
            try {
                const res = await fetch(`/api/v1/actors/${actorId}`);
                const data = await res.json();
                let p = data.actor_profile;
                let ipHtml = (data.leaked_ips && data.leaked_ips.length > 0)
                    ? `<div style="background:#450a0a; border:1px solid #ef4444; border-radius:6px; padding:10px; margin:12px 0;">
                     <h4 style="color:#f87171; font-size:13px;">CRITICAL: Clearnet IP Leaks Discovered</h4>
                     <ul>${data.leaked_ips.map(ip => `<li style="margin-left:20px; font-size:12px; color:#fca5a5;"><b>${ip.ip_address}</b> (Source:${ip.leak_source})</li>`).join('')}</ul>
                   </div>`
                : '';

                let html = `
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                        <div>
                            <h3 style="color:#f8fafc; font-size:18px;">${p.primary_label}</h3>
                            <span style="font-size:11px; color:#64748b;">Master Target UUID: ${p.actor_id}</span>
                        </div>
                        <a href="/api/v1/reports/${p.actor_id}/pdf" target="_blank" class="btn" style="background:#10b981;">Download Case PDF</a>
                    </div>
                    ${ipHtml}
                    <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Unified Cross-Market Aliases:</h4>
                    <ul>${data.aliases.map(a => `<li style="margin-left:20px; font-size:12px;"><b>${a.alias_name}</b> (Platform:${a.source_platform})</li>`).join('')}</ul>
                    
                    <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Discovered Crypto Wallets:</h4>
                    <ul>${data.crypto_wallets.map(w => `<li style="margin-left:20px; font-size:12px;"><b>[${w.currency}]</b>${w.address}</li>`).join('')}</ul>

                    <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Contact Identifiers:</h4>
                    <ul>${data.contact_handles.map(h => `<li style="margin-left:20px; font-size:12px;"><b>[${h.handle_type.toUpperCase()}]</b>${h.handle_value}</li>`).join('')}</ul>

                    <h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Digital Evidence Chain of Custody (SHA-256):</h4>
                    <pre>${JSON.stringify(data.forensic_evidence, null, 2)}</pre>

                    <div style="text-align:right;">
                        <button class="step-next-btn" onclick="openStep2()">
                            Proceed to Step 2: Interactive Syndicate Graph ➔
                        </button>
                    </div>
                `;
                document.getElementById('target-detail').innerHTML = html;
            } catch(err) {
                console.error("View detail error:", err);
            }
        }

        async function renderGraph() {
            const res = await fetch('/api/v1/graph/data');
            const data = await res.json();
            const container = document.getElementById('network-graph');
            const graphData = {
                nodes: new vis.DataSet(data.nodes),
                edges: new vis.DataSet(data.edges)
            };
            
            const options = {
                physics: {
                    solver: 'barnesHut',
                    barnesHut: {
                        gravitationalConstant: -22000,
                        centralGravity: 0.12,
                        springLength: 240,
                        springConstant: 0.04,
                        damping: 0.09,
                        avoidOverlap: 1
                    },
                    stabilization: { iterations: 150 }
                },
                nodes: {
                    font: { color: "#f8fafc", size: 13, face: 'monospace' },
                    borderWidth: 2
                },
                edges: {
                    color: { color: "#475569", highlight: "#38bdf8" },
                    font: { color: "#94a3b8", size: 11, align: 'middle' },
                    smooth: { type: 'continuous' }
                },
                interaction: {
                    hover: true,
                    navigationButtons: true,
                    keyboard: true
                }
            };
            network = new vis.Network(container, graphData, options);
        }

        async function submitLiveEvidence() {
            const text = document.getElementById('input-text').value;
            const alias = document.getElementById('input-alias').value;
            const platform = document.getElementById('input-platform').value;
            const outBox = document.getElementById('sandbox-output');

            if (!text.trim()) {
                outBox.innerText = "[!] Please enter evidence text in the textarea.";
                return;
            }

            outBox.innerText = "[*] Sending payload to backend ingestion engine...\n[*] Computing SHA-256 & cross-referencing pivots...";
            try {
                const res = await fetch('/api/v1/ingest/live', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text, alias, platform })
                });
                const result = await res.json();
                if (!res.ok) {
                    outBox.innerText = `[ERROR ${res.status}] ` + JSON.stringify(result, null, 2);
                } else {
                    outBox.innerText = "[SUCCESS] Evidence Ingested & Resolved!\n\n" + JSON.stringify(result, null, 2);
                    loadActors();
                }
            } catch (err) {
                outBox.innerText = `[NETWORK/FETCH ERROR]: ${err.message}`;
            }
        }

        loadActors();
    </script>
</body>
</html>"""
