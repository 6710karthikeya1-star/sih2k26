import base64
import hashlib
import uuid
try:
    import mmh3
    def get_mmh3_hash(data):
        return str(mmh3.hash(data))
except ImportError:
    import pymmh3
    def get_mmh3_hash(data):
        return str(pymmh3.hash(data))

from bs4 import BeautifulSoup
from db_manager import get_connection

class OpsecAnalyzer:
    def __init__(self):
        self.conn = get_connection()

    @staticmethod
    def calculate_favicon_hash(favicon_bytes: bytes) -> str:
        b64 = base64.encodebytes(favicon_bytes)
        return get_mmh3_hash(b64)

    @staticmethod
    def compute_dom_structure_hash(html_content: str) -> str:
        soup = BeautifulSoup(html_content, "html.parser")
        tag_skeleton = "-".join([tag.name for tag in soup.find_all()])
        return hashlib.sha256(tag_skeleton.encode("utf-8")).hexdigest()

    def record_infrastructure(self, url: str, html_content: str, favicon_bytes: bytes, server_banner: str = "nginx/1.22.1"):
        fav_hash = self.calculate_favicon_hash(favicon_bytes)
        dom_hash = self.compute_dom_structure_hash(html_content)
        infra_id = str(uuid.uuid4())

        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO site_infrastructure 
                (infra_id, source_url, favicon_mmh3, dom_structural_hash, server_header)
                VALUES (?, ?, ?, ?, ?);
            """, (infra_id, url, fav_hash, dom_hash, server_banner))

        print(f"[OPSEC] Profiled site: {url}")
        print(f"        -> Favicon MMH3 Hash: {fav_hash}")
        print(f"        -> DOM Skeleton Hash: {dom_hash[:16]}...")
        return infra_id

    def find_shared_infrastructure(self):
        cur = self.conn.cursor()
        cur.execute("""
            SELECT favicon_mmh3, GROUP_CONCAT(source_url, ' | ') AS linked_sites, COUNT(*) as site_count
            FROM site_infrastructure
            GROUP BY favicon_mmh3
            HAVING site_count > 1;
        """)
        matches = cur.fetchall()

        if matches:
            print("\n[!] OPSEC LEAK DETECTED: Shared infrastructure identified across different .onion sites!")
            for m in matches:
                print(f"    * Shared Favicon MMH3 [{m['favicon_mmh3']}]:")
                for s in m['linked_sites'].split(' | '):
                    print(f"      - {s}")
        else:
            print("\n[*] No overlapping infrastructure discovered yet.")
        return matches

if __name__ == "__main__":
    analyzer = OpsecAnalyzer()

    MOCK_FAVICON = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x08\x00\x68\x05\x00\x00"
    SITE_A_HTML = "<html><head><title>Market A</title></head><body><div><form><input/></form></div></body></html>"
    SITE_B_HTML = "<html><head><title>Market B</title></head><body><div><form><input/></form></div></body></html>"

    print("[*] Ingesting Site A footprint...")
    analyzer.record_infrastructure("http://alpha72kxlop.onion", SITE_A_HTML, MOCK_FAVICON)

    print("\n[*] Ingesting Site B footprint...")
    analyzer.record_infrastructure("http://shadowbazaar99q.onion", SITE_B_HTML, MOCK_FAVICON)

    analyzer.find_shared_infrastructure()
