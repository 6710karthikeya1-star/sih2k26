import networkx as nx
from db_manager import get_connection

class CorrelationEngine:
    def __init__(self):
        self.conn = get_connection()

    def build_bipartite_graph(self) -> nx.Graph:
        G = nx.Graph()
        cur = self.conn.cursor()

        # 1. Fetch Wallets
        cur.execute("SELECT actor_id, currency, address FROM crypto_wallets;")
        for row in cur.fetchall():
            actor = f"ACTOR:{row['actor_id']}"
            ident = f"WALLET:{row['currency']}:{row['address']}"
            G.add_node(actor, node_type="actor")
            G.add_node(ident, node_type="identifier", subtype="crypto")
            G.add_edge(actor, ident, relation="OWNS_WALLET")

        # 2. Fetch Contact Handles
        cur.execute("SELECT actor_id, handle_type, handle_value FROM contact_handles;")
        for row in cur.fetchall():
            actor = f"ACTOR:{row['actor_id']}"
            ident = f"HANDLE:{row['handle_type']}:{row['handle_value']}"
            G.add_node(actor, node_type="actor")
            G.add_node(ident, node_type="identifier", subtype="contact")
            G.add_edge(actor, ident, relation="USES_CONTACT")

        # 3. Fetch PGP Keys
        cur.execute("SELECT actor_id, key_block FROM pgp_keys;")
        for row in cur.fetchall():
            actor = f"ACTOR:{row['actor_id']}"
            ident = f"PGP:{hash(row['key_block'])}"
            G.add_node(actor, node_type="actor")
            G.add_node(ident, node_type="identifier", subtype="pgp")
            G.add_edge(actor, ident, relation="SIGNS_PGP")

        return G

    def detect_syndicates_and_clusters(self):
        G = self.build_bipartite_graph()
        clusters = list(nx.connected_components(G))

        print(f"[*] Correlation Engine: Analyzed {len(G.nodes())} total nodes across {len(clusters)} isolated cluster(s).")
        
        results = []
        for idx, cluster in enumerate(clusters, start=1):
            actors = [n for n in cluster if n.startswith("ACTOR:")]
            identifiers = [n for n in cluster if not n.startswith("ACTOR:")]

            cluster_info = {
                "cluster_id": idx,
                "actor_count": len(actors),
                "actors": actors,
                "shared_identifiers": identifiers,
                "network_density": nx.density(G.subgraph(cluster))
            }
            results.append(cluster_info)
            print(f"    -> Cluster #{idx}: {len(actors)} Actor(s) tied together by {len(identifiers)} shared identifier(s).")

        return results

if __name__ == "__main__":
    engine = CorrelationEngine()
    engine.detect_syndicates_and_clusters()
