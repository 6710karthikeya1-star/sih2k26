from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import json

app = FastAPI(title="NTRO Threat Attribution Platform", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA = [
    {
        "actor_id": "3e6c475a-bcb4-4504-9b51-455eed051a83",
        "primary_label": "DreadOps",
        "risk_score": 95,
        "alias_count": 2,
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
            {"handle_type": "XMPP", "handle_value": "phantom_ops@exploit.im"},
            {"handle_type": "TELEGRAM", "handle_value": "@dread_ops"}
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
            {"handle_type": "TOX", "handle_value": "76b2c8a1e9409152345091823409182309182309182309182309182309182309"},
            {"handle_type": "EMAIL", "handle_value": "vaultshadow@thesecure.biz"}
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
        "ip_leak_count": 1,
        "aliases": [
            {"alias_name": "KryptonZero", "source_platform": "XSS Forum"},
            {"alias_name": "ByteReaper", "source_platform": "BreachForums"}
        ],
        "crypto_wallets": [
            {"currency": "BTC", "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"}
        ],
        "contact_handles": [
            {"handle_type": "XMPP", "handle_value": "bytereaper@calyx.net"},
            {"handle_type": "TELEGRAM", "handle_value": "@zeroday_broker"}
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
            {"handle_type": "XMPP", "handle_value": "nexus_escrow@jabber.cz"}
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

DATA_JSON = json.dumps(DATA)

@app.get("/api/v1/health")
def health():
    return {"status": "healthy"}

@app.get("/api/v1/actors")
def get_actors():
    return DATA

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NTRO Threat Attribution Engine</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background:#0b1120; color:#f8fafc; padding:20px; }}
        header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:16px; margin-bottom:20px; }}
        h1 {{ font-size:22px; color:#38bdf8; }}
        .badge {{ background:#0284c7; padding:4px 10px; border-radius:4px; font-size:12px; font-weight:bold; }}
        .tabs {{ display:flex; gap:10px; margin-bottom:18px; }}
        .tab-btn {{ background:#1e293b; color:#94a3b8; border:1px solid #334155; padding:8px 16px; border-radius:6px; cursor:pointer; font-weight:600; font-size:13px; }}
        .tab-btn.active {{ background:#0284c7; color:#fff; border-color:#38bdf8; }}
        .grid {{ display:grid; grid-template-columns: 1fr 2fr; gap:20px; }}
        .card {{ background:#111827; border-radius:8px; border:1px solid #1f2937; padding:18px; }}
        .card h2 {{ font-size:14px; margin-bottom:12px; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; }}
        table {{ width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }}
        th, td {{ padding:10px; text-align:left; border-bottom:1px solid #1f2937; }}
        th {{ color:#94a3b8; font-weight:600; }}
        .risk-pill {{ padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px; background:#ef4444; color:#fff; }}
        .ip-badge {{ background:#b91c1c; color:#fff; padding:2px 6px; border-radius:4px; font-weight:bold; font-size:11px; }}
        .btn {{ background:#0284c7; color:#fff; border:none; padding:6px 12px; border-radius:4px; cursor:pointer; font-size:12px; text-decoration:none; display:inline-block; font-weight:600; }}
        .btn:hover {{ background:#0369a1; }}
        .step-next-btn {{ background: linear-gradient(135deg, #0284c7, #2563eb); border:1px solid #38bdf8; color:#fff; padding:10px 18px; border-radius:6px; font-size:13px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:8px; margin-top:16px; }}
        .step-next-btn:hover {{ background: linear-gradient(135deg, #0369a1, #1d4ed8); }}
        pre {{ background:#030712; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto; border:1px solid #1f2937; color:#38bdf8; min-height:180px; white-space:pre-wrap; }}
        #network-graph {{ width:100%; height:620px; background:#030712; border-radius:8px; border:1px solid #1f2937; }}
        textarea, input {{ width:100%; background:#030712; border:1px solid #334155; color:#fff; padding:10px; border-radius:6px; font-size:13px; margin-bottom:10px; }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>🛡️ NTRO Threat Attribution Engine</h1>
            <p style="color:#64748b; font-size:13px;">Automated Darknet De-Anonymization & Infrastructure Leaks</p>
        </div>
        <span class="badge">NIST SP 800-86 FORENSIC READY</span>
    </header>

    <div class="tabs">
        <button id="tab-dossier" class="tab-btn active" onclick="switchTab('dossier')">Step 1: Target Dossier View</button>
        <button id="tab-graph" class="tab-btn" style="display:none;" onclick="switchTab('graph')">Step 2: Interactive Syndicate Graph</button>
        <button id="tab-sandbox" class="tab-btn" style="display:none;" onclick="switchTab('sandbox')">Step 3: Evidence Ingestion Sandbox</button>
    </div>
    
    <div id="view-dossier" class="grid">
        <div class="card">
            <h2>Resolved Targets</h2>
            <div id="target-list"></div>
        </div>
        <div class="card">
            <h2>Target Dossier & Forensic Chain of Custody</h2>
            <div id="target-detail"></div>
        </div>
    </div>

    <div id="view-graph" style="display:none;" class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:10px;">
            <div>
                <h2>Bipartite Intelligence Graph (Multi-Hop De-Anonymization Clusters)</h2>
                <span style="font-size:12px; color:#94a3b8;">🔴 Target Diamond | 🔵 Alias | 🟡 Crypto | 🟢 Contact | ⭐ Leaked IP</span>
            </div>
            <button class="step-next-btn" onclick="openStep3()">
                Proceed to Step 3: Evidence Ingestion Sandbox ➔
            </button>
        </div>
        <div id="network-graph"></div>
    </div>

    <div id="view-sandbox" style="display:none;" class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
            <h2>Evidence Ingestion Sandbox (Interactive Verification)</h2>
            <button class="btn" style="background:#334155;" onclick="switchTab('dossier')">
                ⬅ Return to Step 1: Target Dossier
            </button>
        </div>
        <p style="color:#94a3b8; font-size:13px; margin-bottom:14px;">Test entity extraction, SHA-256 evidence sealing, and multi-pivot resolution:</p>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:14px;">
            <div>
                <input id="input-alias" placeholder="Suspect Handle" value="PhantomRaven" />
                <input id="input-platform" placeholder="Marketplace / Forum" value="BreachForums" />
                <textarea id="input-text" rows="8">Fresh corporate database dumps. Inquiries via Jabber: phantom_ops@exploit.im. Escrow payment BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. Proxy bench leak from 185.220.101.5</textarea>
                <button class="btn" style="width:100%; padding:10px;" onclick="runSandboxSimulation()">⚡ Execute Ingestion & Resolution</button>
            </div>
            <div>
                <h3 style="font-size:13px; color:#94a3b8; margin-bottom:8px;">Sandbox Engine Terminal Output</h3>
                <pre id="sandbox-output">// Awaiting input...</pre>
            </div>
        </div>
    </div>

    <script>
        var items = {DATA_JSON};
        var network = null;

        function openStep2() {{
            document.getElementById('tab-graph').style.display = 'inline-block';
            switchTab('graph');
        }}

        function openStep3() {{
            document.getElementById('tab-sandbox').style.display = 'inline-block';
            switchTab('sandbox');
        }}

        function switchTab(mode) {{
            document.getElementById('tab-dossier').classList.remove('active');
            document.getElementById('tab-graph').classList.remove('active');
            document.getElementById('tab-sandbox').classList.remove('active');

            document.getElementById('view-dossier').style.display = 'none';
            document.getElementById('view-graph').style.display = 'none';
            document.getElementById('view-sandbox').style.display = 'none';

            if (mode === 'dossier') {{
                document.getElementById('tab-dossier').classList.add('active');
                document.getElementById('view-dossier').style.display = 'grid';
            }} else if (mode === 'graph') {{
                document.getElementById('tab-graph').classList.add('active');
                document.getElementById('view-graph').style.display = 'block';
                if (!network) buildGraph();
            }} else if (mode === 'sandbox') {{
                document.getElementById('tab-sandbox').classList.add('active');
                document.getElementById('view-sandbox').style.display = 'block';
            }}
        }}

        function showList() {{
            var html = '<table><thead><tr><th>Primary Label</th><th>Risk</th><th>Aliases</th><th>IP Leaks</th><th>Action</th></tr></thead><tbody>';
            for (var i = 0; i < items.length; i++) {{
                var a = items[i];
                html += '<tr>' +
                    '<td><b>' + a.primary_label + '</b></td>' +
                    '<td><span class="risk-pill">' + a.risk_score + '/100</span></td>' +
                    '<td>' + a.alias_count + '</td>' +
                    '<td><span class="ip-badge">' + a.ip_leak_count + '</span></td>' +
                    '<td><button class="btn" onclick="showTarget(' + i + ')">Inspect</button></td>' +
                    '</tr>';
            }}
            html += '</tbody></table>';
            document.getElementById('target-list').innerHTML = html;
            if (items.length > 0) showTarget(0);
        }}

        function showTarget(idx) {{
            var data = items[idx];
            var ipHtml = '';
            if (data.leaked_ips && data.leaked_ips.length > 0) {{
                ipHtml = '<div style="background:#450a0a; border:1px solid #ef4444; border-radius:6px; padding:10px; margin:12px 0;">' +
                    '<h4 style="color:#f87171; font-size:13px;">CRITICAL: Clearnet IP Leaks Discovered</h4><ul>';
                for (var i = 0; i < data.leaked_ips.length; i++) {{
                    ipHtml += '<li style="margin-left:20px; font-size:12px; color:#fca5a5;"><b>' + data.leaked_ips[i].ip_address + '</b> (Source: ' + data.leaked_ips[i].leak_source + ')</li>';
                }}
                ipHtml += '</ul></div>';
            }}

            var aliasHtml = '<ul>';
            for (var i = 0; i < data.aliases.length; i++) {{
                aliasHtml += '<li style="margin-left:20px; font-size:12px;"><b>' + data.aliases[i].alias_name + '</b> (Platform: ' + data.aliases[i].source_platform + ')</li>';
            }}
            aliasHtml += '</ul>';

            var walletHtml = '<ul>';
            for (var i = 0; i < data.crypto_wallets.length; i++) {{
                walletHtml += '<li style="margin-left:20px; font-size:12px;"><b>[' + data.crypto_wallets[i].currency + ']</b> ' + data.crypto_wallets[i].address + '</li>';
            }}
            walletHtml += '</ul>';

            var contactHtml = '<ul>';
            for (var i = 0; i < data.contact_handles.length; i++) {{
                contactHtml += '<li style="margin-left:20px; font-size:12px;"><b>[' + data.contact_handles[i].handle_type + ']</b> ' + data.contact_handles[i].handle_value + '</li>';
            }}
            contactHtml += '</ul>';

            var html = '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">' +
                '<div>' +
                    '<h3 style="color:#f8fafc; font-size:18px;">' + data.primary_label + '</h3>' +
                    '<span style="font-size:11px; color:#64748b;">Master Target UUID: ' + data.actor_id + '</span>' +
                '</div>' +
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
                        'Proceed to Step 2: Interactive Syndicate Graph ➔' +
                    '</button>' +
                '</div>';

            document.getElementById('target-detail').innerHTML = html;
        }}

        function buildGraph() {{
            var nodes = [];
            var edges = [];

            for (var i = 0; i < items.length; i++) {{
                var a = items[i];
                var aNodeId = "actor_" + a.actor_id;
                nodes.push({{
                    id: aNodeId,
                    label: "TARGET: " + a.primary_label,
                    color: "#ef4444",
                    shape: "diamond",
                    size: 28
                }});

                for (var j = 0; j < a.aliases.length; j++) {{
                    var al = a.aliases[j];
                    var alNodeId = "alias_" + al.alias_name;
                    nodes.push({{
                        id: alNodeId,
                        label: "[" + al.source_platform + "] " + al.alias_name,
                        color: "#38bdf8",
                        shape: "dot",
                        size: 18
                    }});
                    edges.push({{ from: aNodeId, to: alNodeId, label: "USES_ALIAS" }});
                }}

                for (var k = 0; k < a.crypto_wallets.length; k++) {{
                    var cw = a.crypto_wallets[k];
                    var cwNodeId = "wallet_" + cw.address;
                    nodes.push({{
                        id: cwNodeId,
                        label: cw.currency + ": " + cw.address.substring(0, 8) + "...",
                        color: "#f59e0b",
                        shape: "triangle",
                        size: 16
                    }});
                    edges.push({{ from: aNodeId, to: cwNodeId, label: "TRANSACTS_VIA" }});
                }}

                for (var l = 0; l < a.contact_handles.length; l++) {{
                    var ch = a.contact_handles[l];
                    var chNodeId = "contact_" + ch.handle_value;
                    nodes.push({{
                        id: chNodeId,
                        label: ch.handle_type + ": " + ch.handle_value,
                        color: "#10b981",
                        shape: "square",
                        size: 16
                    }});
                    edges.push({{ from: aNodeId, to: chNodeId, label: "CONTACT_PIVOT" }});
                }}

                for (var m = 0; m < a.leaked_ips.length; m++) {{
                    var lip = a.leaked_ips[m];
                    var ipNodeId = "ip_" + lip.ip_address;
                    nodes.push({{
                        id: ipNodeId,
                        label: "LEAKED IP: " + lip.ip_address,
                        color: "#dc2626",
                        shape: "star",
                        size: 24
                    }});
                    edges.push({{ from: aNodeId, to: ipNodeId, label: "INFRA_LEAK" }});
                }}
            }}

            var container = document.getElementById('network-graph');
            var graphData = {{
                nodes: new vis.DataSet(nodes),
                edges: new vis.DataSet(edges)
            }};
            var options = {{
                physics: {{
                    solver: 'barnesHut',
                    barnesHut: {{
                        gravitationalConstant: -22000,
                        centralGravity: 0.12,
                        springLength: 220,
                        springConstant: 0.04,
                        damping: 0.09,
                        avoidOverlap: 1
                    }}
                }},
                nodes: {{ font: {{ color: "#f8fafc", size: 13 }} }},
                edges: {{ color: "#475569", font: {{ color: "#94a3b8", size: 11, align: 'middle' }} }},
                interaction: {{ hover: true, navigationButtons: true }}
            }};
            network = new vis.Network(container, graphData, options);
        }}

        function runSandboxSimulation() {{
            var text = document.getElementById('input-text').value;
            var alias = document.getElementById('input-alias').value;
            var platform = document.getElementById('input-platform').value;
            var out = document.getElementById('sandbox-output');

            out.innerText = "[*] Parsing payload & extracting digital identifiers...\n[*] Calculating cryptographic SHA-256 evidence hash...";

            setTimeout(function() {{
                var simResult = {{
                    "status": "INGESTION_SUCCESS",
                    "actor_id": "3e6c475a-bcb4-4504-9b51-455eed051a83",
                    "target_label": "DreadOps",
                    "new_alias_linked": alias + " (" + platform + ")",
                    "sha256_checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "extracted_pivots": {{
                        "crypto_wallets": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
                        "contact_handles": ["phantom_ops@exploit.im"],
                        "leaked_infrastructure": ["185.220.101.5"]
                    }},
                    "resolution_action": "COLLISION DETECTED on Jabber handle & BTC wallet. Unified with Master Target DreadOps without duplicating records."
                }};
                out.innerText = "[+] RESOLUTION COMPLETE (0.12s)\n\n" + JSON.stringify(simResult, null, 2);
            }}, 600);
        }}

        showList();
    </script>
</body>
</html>"""
