import networkx as nx
from pyvis.network import Network
from db_manager import get_connection

def generate_threat_graph(output_html="threat_graph.html"):
    G = nx.Graph()
    conn = get_connection()
    cur = conn.cursor()

    # 1. Add Threat Actors
    cur.execute("SELECT actor_id, primary_label, risk_score FROM threat_actors;")
    for a in cur.fetchall():
        actor_id = str(a["actor_id"])
        G.add_node(
            actor_id,
            label=f"Actor: {a['primary_label']}",
            title=f"UUID: {actor_id}\nRisk Score: {a['risk_score']}",
            color="#e74c3c",
            size=26,
            shape="diamond"
        )

    # 2. Add Aliases
    cur.execute("SELECT actor_id, alias_name, source_platform FROM actor_aliases;")
    for alias in cur.fetchall():
        node_id = f"alias_{alias['alias_name']}_{alias['source_platform']}"
        G.add_node(
            node_id,
            label=f"{alias['alias_name']} ({alias['source_platform']})",
            title=f"Platform: {alias['source_platform']}",
            color="#3498db",
            size=16,
            shape="dot"
        )
        G.add_edge(str(alias["actor_id"]), node_id, title="USES_ALIAS")

    # 3. Add Crypto Wallets
    cur.execute("SELECT actor_id, currency, address FROM crypto_wallets;")
    for w in cur.fetchall():
        wallet_id = f"wallet_{w['address']}"
        short_addr = f"{w['address'][:6]}...{w['address'][-4:]}"
        G.add_node(
            wallet_id,
            label=f"[{w['currency']}] {short_addr}",
            title=f"Currency: {w['currency']}\nFull: {w['address']}",
            color="#f39c12",
            size=16,
            shape="triangle"
        )
        G.add_edge(str(w["actor_id"]), wallet_id, title="OWNS_WALLET")

    # 4. Add Contact Handles
    cur.execute("SELECT actor_id, handle_type, handle_value FROM contact_handles;")
    for h in cur.fetchall():
        handle_id = f"handle_{h['handle_type']}_{h['handle_value']}"
        G.add_node(
            handle_id,
            label=f"[{h['handle_type'].upper()}] {h['handle_value']}",
            title=f"Type: {h['handle_type']}\nValue: {h['handle_value']}",
            color="#2ecc71",
            size=15,
            shape="box"
        )
        G.add_edge(str(h["actor_id"]), handle_id, title="USES_CONTACT")

    conn.close()

    net = Network(height="750px", width="100%", bgcolor="#1a1a1a", font_color="white")
    net.from_nx(G)
    net.force_atlas_2based()
    net.write_html(output_html)
    print(f"[+] Interactive threat graph exported to {output_html}")

if __name__ == "__main__":
    generate_threat_graph()
