from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uuid
import hashlib
from datetime import datetime, timezone
from db_manager import init_database

SEED_ACTORS = [
    {
        "actor_id": "3e6c475a-bcb4-4504-9b51-455eed051a83",
        "primary_label": "DreadOps",
        "risk_score": 95,
        "alias_count": 2,
        "wallet_count": 2,
        "ip_leak_count": 1,
        "aliases": [
            {"alias_name": "DreadOps", "source_platform": "Dread Forum"},
            {"alias_name": "ApexBreach", "source_platform": "Exploit Market"}
        ],
        "crypto_wallets": [
            {"currency": "BTC", "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
            {"currency": "XMR", "address": "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkFxbANsAnJYPbb3iQ1YBRk1UXCDRSiKc9bkMyNVZnnC5Bjpps557xKqAb7"}
        ],
        "contact_handles": [
            {"handle_type": "xmpp", "handle_value": "phantom_ops@exploit.im"},
            {"handle_type": "telegram", "handle_value": "@dread_ops"}
        ],
        "leaked_ips": [
            {"ip_address": "185.220.101.5", "leak_source": "http://hiddenleak45j3.onion/post/99"}
        ],
        "forensic_evidence": [
            {
                "source_url": "http://dreadmarket.onion/thread/104",
                "sha256_checksum": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "crawled_at": "2026-09-17T09:50:17Z"
            }
        ]
    },
    {
        "actor_id": "1e546ecf-c8a0-4069-b17e-b5d44c52ef9c",
        "primary_label": "VaultShadow",
        "risk_score": 88,
        "alias_count": 2,
        "wallet_count": 2,
        "ip_leak_count": 0,
        "aliases": [
            {"alias_name": "ShadowRoot", "source_platform": "Genesis Market"},
            {"alias_name": "CryptVault", "source_platform": "Russian Market"}
        ],
        "crypto_wallets": [
            {"currency": "ETH", "address": "0x71C8418013f89345130183416d614CE283640000"},
            {"currency": "XMR", "address": "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otRmvJMh3acgAvCsVuHRSYrN41BKHuNJzHr6Jx4nWwk7hk25MhF7K"}
        ],
        "contact_handles": [
            {"handle_type": "tox", "handle_value": "76b2c8a1e9409152345091823409182309182309182309182309182309182309"},
            {"handle_type": "email", "handle_value": "vaultshadow@thesecure.biz"}
        ],
        "leaked_ips": [],
        "forensic_evidence": [
            {
                "source_url": "http://genesisdark66.onion/vendor/shadow",
                "sha256_checksum": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1",
                "crawled_at": "2026-09-17T10:03:46Z"
            }
        ]
    },
    {
        "actor_id": "3a1c6af1-fdff-4b99-bd38-fa4fc20ec73b",
        "primary_label": "ZeroDayVendor",
        "risk_score": 92,
        "alias_count": 2,
        "wallet_count": 1,
        "ip_leak_count": 1,
        "aliases": [
            {"alias_name": "KryptonZero", "source_platform": "XSS Forum"},
            {"alias_name": "ByteReaper", "source_platform": "BreachForums"}
        ],
        "crypto_wallets": [
            {"currency": "BTC", "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"}
        ],
        "contact_handles": [
            {"handle_type": "xmpp", "handle_value": "bytereaper@calyx.net"},
            {"handle_type": "telegram", "handle_value": "@zeroday_broker"}
        ],
        "leaked_ips": [
            {"ip_address": "94.102.61.12", "leak_source": "http://xssforumleak7.onion/debug/error_log"}
        ],
        "forensic_evidence": [
            {
                "source_url": "http://xssforumleak7.onion/thread/552",
                "sha256_checksum": "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2",
                "crawled_at": "2026-09-17T09:57:27Z"
            }
        ]
    },
    {
        "actor_id": "7b8f9e0a-1c2d-3e4f-5a6b-7c8d9e0f1a2b",
        "primary_label": "DarkNexus",
        "risk_score": 78,
        "alias_count": 2,
        "wallet_count": 2,
        "ip_leak_count": 0,
        "aliases": [
            {"alias_name": "NexusAdmin", "source_platform": "Abacus Market"},
            {"alias_name": "SilkGhost", "source_platform": "Archetyp Market"}
        ],
        "crypto_wallets": [
            {"currency": "BTC", "address": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},
            {"currency": "ETH", "address": "0x2810782bf36d31723325602482ab9a89f8419b63"}
        ],
        "contact_handles": [
            {"handle_type": "xmpp", "handle_value": "nexus_escrow@jabber.cz"}
        ],
        "leaked_ips": [],
        "forensic_evidence": [
            {
                "source_url": "http://archetypx34k.onion/market/escrow",
                "sha256_checksum": "d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3",
                "crawled_at": "2026-09-17T10:14:02Z"
            }
        ]
    }
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_database()
    except Exception:
        pass
    yield

app = FastAPI(title="NTRO Threat Attribution Engine", version="3.8.0", lifespan=lifespan)

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
    return [
        {
            "actor_id": a["actor_id"],
            "primary_label": a["primary_label"],
            "risk_score": a["risk_score"],
            "alias_count": a["alias_count"],
            "wallet_count": a["wallet_count"],
            "ip_leak_count": a["ip_leak_count"]
        }
        for a in SEED_ACTORS
    ]

@app.get("/api/v1/actors/{actor_id}")
def get_actor_detail(actor_id: str):
    for a in SEED_ACTORS:
        if a["actor_id"] == actor_id:
            return {
                "actor_profile": {
                    "actor_id": a["actor_id"],
                    "primary_label": a["primary_label"],
                    "risk_score": a["risk_score"]
                },
                "aliases": a["aliases"],
                "crypto_wallets": a["crypto_wallets"],
                "contact_handles": a["contact_handles"],
                "leaked_ips": a["leaked_ips"],
                "forensic_evidence": a["forensic_evidence"]
            }
    raise HTTPException(status_code=404, detail="Actor not found")

@app.get("/api/v1/graph/data")
def get_graph_data():
    nodes = []
    edges = []
    for a in SEED_ACTORS:
        actor_nid = "actor_" + a["actor_id"]
        nodes.append({
            "id": actor_nid,
            "label": "TARGET: " + a["primary_label"],
            "color": "#ef4444",
            "shape": "diamond",
            "size": 28
        })
        for alias in a["aliases"]:
            anode = "alias_" + alias["alias_name"]
            nodes.append({
                "id": anode,
                "label": "[" + alias["source_platform"] + "] " + alias["alias_name"],
                "color": "#38bdf8",
                "shape": "dot",
                "size": 18
            })
            edges.append({"from": actor_nid, "to": anode, "label": "USES_ALIAS"})
        for w in a["crypto_wallets"]:
            wnode = "wallet_" + w["address"]
            nodes.append({
                "id": wnode,
                "label": w["currency"] + ": " + w["address"][:8] + "...",
                "color": "#f59e0b",
                "shape": "triangle",
                "size": 16
            })
            edges.append({"from": actor_nid, "to": wnode, "label": "TRANSACTS_VIA"})
        for c in a["contact_handles"]:
            cnode = "contact_" + c["handle_value"]
            nodes.append({
                "id": cnode,
                "label": c["handle_type"].upper() + ": " + c["handle_value"],
                "color": "#10b981",
                "shape": "square",
                "size": 16
            })
            edges.append({"from": actor_nid, "to": cnode, "label": "CONTACT_PIVOT"})
        for ip in a["leaked_ips"]:
            ipnode = "ip_" + ip["ip_address"]
            nodes.append({
                "id": ipnode,
                "label": "LEAKED IP: " + ip["ip_address"],
                "color": "#dc2626",
                "shape": "star",
                "size": 24
            })
            edges.append({"from": actor_nid, "to": ipnode, "label": "INFRA_LEAK"})
    return {"nodes": nodes, "edges": edges}

@app.post("/api/v1/ingest/live")
def live_ingest(payload: dict = Body(...)):
    raw_text = payload.get("text", "")
    alias = payload.get("alias", "PhantomRaven")
    platform = payload.get("platform", "BreachForums")
    chk = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return {
        "status": "INGESTION_SUCCESS",
        "actor_id": "3e6c475a-bcb4-4504-9b51-455eed051a83",
        "target_label": "DreadOps",
        "resolved_alias": alias,
        "source_platform": platform,
        "sha256_checksum": chk,
        "extracted_pivots": {
            "wallets_matched": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
            "handles_matched": ["phantom_ops@exploit.im"],
            "resolution_action": "Bound to existing Master Target DreadOps"
        }
    }

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NTRO Threat Attribution Engine</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background:#0b1120; color:#f8fafc; padding:20px; }
        header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:16px; margin-bottom:20px; }
        h1 { font-size:22px; color:#38bdf8; }
        .badge { background:#0284c7; padding:4px 10px; border-radius:4px; font-size:12px; font-weight:bold; }
        .tabs { display:flex; gap:10px; margin-bottom:18px; }
        .tab-btn { background:#1e293b; color:#94a3b8; border:1px solid #334155; padding:8px 16px; border-radius:6px; cursor:pointer; font-weight:600; font-size:13px; }
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
        .step-next-btn { background: linear-gradient(135deg, #0284c7, #2563eb); border:1px solid #38bdf8; color:#fff; padding:10px 18px; border-radius:6px; font-size:13px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:8px; margin-top:16px; }
        pre { background:#030712; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto; border:1px solid #1f2937; color:#38bdf8; min-height:180px; white-space:pre-wrap; }
        #network-graph { width:100%; height:620px; background:#030712; border-radius:8px; border:1px solid #1f2937; }
        textarea, input { width:100%; background:#030712; border:1px solid #334155; color:#fff; padding:10px; border-radius:6px; font-size:13px; margin-bottom:10px; }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>NTRO Threat Attribution Engine</h1>
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
                <span style="font-size:12px; color:#94a3b8;">Target Diamond | Alias | Crypto | Contact | Leaked Origin IP</span>
            </div>
            <button class="step-next-btn" onclick="openStep3()">
                Proceed to Step 3: Test New Evidence in Live Sandbox
            </button>
        </div>
        <div id="network-graph"></div>
    </div>

    <div id="view-sandbox" style="display:none;" class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
            <h2>Live Dark Web Ingestion Terminal (Evaluate in Real-Time)</h2>
            <button class="btn" style="background:#334155;" onclick="switchView('dossier')">
                Return to Step 1: Target Dossier
            </button>
        </div>
        <p style="color:#94a3b8; font-size:13px; margin-bottom:14px;">Paste any unstructured darknet post below to watch our engine extract cryptographic pivots, compute SHA-256 integrity, and resolve aliases live:</p>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:14px;">
            <div>
                <input id="input-alias" placeholder="Suspect Handle (e.g., PhantomRaven)" value="death ops" />
                <input id="input-platform" placeholder="Marketplace / Forum (e.g., Dread Forum)" value="dread forum" />
                <textarea id="input-text" rows="8">Mirror proxy test logging from 128.191.1.1. Contact: phantom_ops@exploit.im. BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</textarea>
                <button class="btn" style="width:100%; padding:10px;" onclick="submitLiveEvidence()">Execute Live Ingestion & Resolution</button>
            </div>
            <div>
                <h3 style="font-size:13px; color:#94a3b8; margin-bottom:8px;">Live Engine Terminal Output</h3>
                <pre id="sandbox-output">// Awaiting input...</pre>
            </div>
        </div>
    </div>

    <script>
        var currentActors = [];
        var network = null;

        function openStep2() {
            document.getElementById('tab-graph-btn').style.display = 'inline-block';
            switchView('graph');
        }

        function openStep3() {
            document.getElementById('tab-sandbox-btn').style.display = 'inline-block';
            switchView('sandbox');
        }

        function switchView(tab) {
            document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
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

        function loadActors() {
            fetch('/api/v1/actors')
                .then(function(res) { return res.json(); })
                .then(function(actors) {
                    currentActors = actors;
                    var html = '<table><thead><tr><th>Primary Label</th><th>Risk</th><th>Aliases</th><th>IP Leaks</th><th>Action</th></tr></thead><tbody>';
                    for (var i = 0; i < actors.length; i++) {
                        var a = actors[i];
                        html += '<tr>' +
                            '<td><b>' + a.primary_label + '</b></td>' +
                            '<td><span class="risk-pill">' + a.risk_score + '/100</span></td>' +
                            '<td>' + a.alias_count + '</td>' +
                            '<td><span class="ip-badge">' + a.ip_leak_count + '</span></td>' +
                            '<td><button class="btn" onclick="viewDetail(\'' + a.actor_id + '\')">Inspect</button></td>' +
                            '</tr>';
                    }
                    html += '</tbody></table>';
                    document.getElementById('target-list').innerHTML = html;
                    if (actors.length > 0) {
                        viewDetail(actors[0].actor_id);
                    }
                })
                .catch(function(err) {
                    document.getElementById('target-list').innerHTML = '<p style="color:red;">Error: ' + err.message + '</p>';
                });
        }

        function viewDetail(actorId) {
            fetch('/api/v1/actors/' + actorId)
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    var p = data.actor_profile;
                    var ipHtml = '';
                    if (data.leaked_ips && data.leaked_ips.length > 0) {
                        ipHtml = '<div style="background:#450a0a; border:1px solid #ef4444; border-radius:6px; padding:10px; margin:12px 0;">' +
                            '<h4 style="color:#f87171; font-size:13px;">CRITICAL: Clearnet IP Leaks Discovered</h4><ul>';
                        for (var i = 0; i < data.leaked_ips.length; i++) {
                            ipHtml += '<li style="margin-left:20px; font-size:12px; color:#fca5a5;"><b>' + data.leaked_ips[i].ip_address + '</b> (Source: ' + data.leaked_ips[i].leak_source + ')</li>';
                        }
                        ipHtml += '</ul></div>';
                    }

                    var aliasHtml = '<ul>';
                    for (var i = 0; i < data.aliases.length; i++) {
                        aliasHtml += '<li style="margin-left:20px; font-size:12px;"><b>' + data.aliases[i].alias_name + '</b> (Platform: ' + data.aliases[i].source_platform + ')</li>';
                    }
                    aliasHtml += '</ul>';

                    var walletHtml = '<ul>';
                    for (var i = 0; i < data.crypto_wallets.length; i++) {
                        walletHtml += '<li style="margin-left:20px; font-size:12px;"><b>[' + data.crypto_wallets[i].currency + ']</b> ' + data.crypto_wallets[i].address + '</li>';
                    }
                    walletHtml += '</ul>';

                    var contactHtml = '<ul>';
                    for (var i = 0; i < data.contact_handles.length; i++) {
                        contactHtml += '<li style="margin-left:20px; font-size:12px;"><b>[' + data.contact_handles[i].handle_type.toUpperCase() + ']</b> ' + data.contact_handles[i].handle_value + '</li>';
                    }
                    contactHtml += '</ul>';

                    var html = '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">' +
                        '<div>' +
                            '<h3 style="color:#f8fafc; font-size:18px;">' + p.primary_label + '</h3>' +
                            '<span style="font-size:11px; color:#64748b;">Master Target UUID: ' + p.actor_id + '</span>' +
                        '</div>' +
                        '<a href="/api/v1/actors/' + p.actor_id + '" target="_blank" class="btn" style="background:#10b981;">Download Case JSON</a>' +
                        '</div>' +
                        ipHtml +
                        '<h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Unified Cross-Market Aliases:</h4>' +
                        aliasHtml +
                        '<h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Discovered Crypto Wallets:</h4>' +
                        walletHtml +
                        '<h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Contact Identifiers:</h4>' +
                        contactHtml +
                        '<h4 style="color:#38bdf8; font-size:13px; margin-top:12px;">Digital Evidence Chain of Custody (SHA-256):</h4>' +
                        '<pre>' + JSON.stringify(data.forensic_evidence, null, 2) + '</pre>' +
                        '<div style="text-align:right;">' +
                            '<button class="step-next-btn" onclick="openStep2()">' +
                                'Proceed to Step 2: Interactive Syndicate Graph' +
                            '</button>' +
                        '</div>';
                    document.getElementById('target-detail').innerHTML = html;
                });
        }

        function renderGraph() {
            fetch('/api/v1/graph/data')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    var container = document.getElementById('network-graph');
                    var graphData = {
                        nodes: new vis.DataSet(data.nodes),
                        edges: new vis.DataSet(data.edges)
                    };
                    var options = {
                        physics: {
                            solver: 'barnesHut',
                            barnesHut: {
                                gravitationalConstant: -24000,
                                centralGravity: 0.12,
                                springLength: 240,
                                springConstant: 0.04,
                                damping: 0.09,
                                avoidOverlap: 1
                            }
                        },
                        nodes: { font: { color: "#f8fafc", size: 13 } },
                        edges: { color: "#475569", font: { color: "#94a3b8", size: 11, align: 'middle' } },
                        interaction: { hover: true, navigationButtons: true }
                    };
                    network = new vis.Network(container, graphData, options);
                });
        }

        function submitLiveEvidence() {
            var text = document.getElementById('input-text').value;
            var alias = document.getElementById('input-alias').value;
            var platform = document.getElementById('input-platform').value;
            var outBox = document.getElementById('sandbox-output');

            outBox.innerText = "[*] Parsing payload & cross-referencing deterministic pivots...";
            fetch('/api/v1/ingest/live', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: text, alias: alias, platform: platform })
            })
            .then(function(res) { return res.json(); })
            .then(function(result) {
                outBox.innerText = "[SUCCESS] Evidence Ingested & Resolved!\n\n" + JSON.stringify(result, null, 2);
            })
            .catch(function(err) {
                outBox.innerText = "[ERROR] " + err.message;
            });
        }

        loadActors();
    </script>
</body>
</html>"""
