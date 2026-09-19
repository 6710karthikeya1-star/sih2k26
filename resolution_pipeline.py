import uuid
from datetime import datetime
from db_manager import get_connection

class EntityResolutionPipeline:
    def __init__(self):
        self.conn = get_connection()

    def log_raw_evidence(self, metadata: dict) -> str:
        cur = self.conn.cursor()
        evidence_id = str(uuid.uuid4())
        source_url = metadata.get("source_url", "http://manual-inspect.onion/feed")
        checksum = metadata.get("sha256_checksum", "")
        raw_html = metadata.get("raw_html", "Live evidence raw payload")
        crawled_at = metadata.get("crawled_at", datetime.utcnow().isoformat() + "Z")

        cur.execute("""
            INSERT INTO raw_evidence_log (evidence_id, source_url, sha256_checksum, raw_html, crawled_at)
            VALUES (?, ?, ?, ?, ?);
        """, (evidence_id, source_url, checksum, raw_html, crawled_at))
        self.conn.commit()
        return evidence_id

    def find_existing_actor_id(self, entities: dict) -> str | None:
        cur = self.conn.cursor()

        # 1. Match crypto addresses
        wallets = [w["address"] for w in entities.get("crypto_wallets", []) if "address" in w]
        for addr in wallets:
            cur.execute("SELECT actor_id FROM crypto_wallets WHERE address = ? LIMIT 1;", (addr,))
            row = cur.fetchone()
            if row:
                return row["actor_id"]

        # 2. Match contact handles
        for h in entities.get("contact_handles", []):
            cur.execute("SELECT actor_id FROM contact_handles WHERE handle_value = ? LIMIT 1;", (h["value"],))
            row = cur.fetchone()
            if row:
                return row["actor_id"]

        return None

    def resolve_and_store(self, extracted_payload: dict, alias_name: str, platform: str) -> str:
        metadata = extracted_payload.get("evidence_metadata", {})
        evidence_id = self.log_raw_evidence(metadata)

        matched_actor_id = self.find_existing_actor_id(extracted_payload)
        actor_id = matched_actor_id or str(uuid.uuid4())

        cur = self.conn.cursor()
        if not matched_actor_id:
            cur.execute("INSERT INTO threat_actors (actor_id, primary_label, risk_score) VALUES (?, ?, ?);", (actor_id, alias_name, 85))
        else:
            cur.execute("UPDATE threat_actors SET last_observed = CURRENT_TIMESTAMP WHERE actor_id = ?;", (actor_id,))

        # Store Alias
        if alias_name:
            cur.execute("""
                INSERT OR IGNORE INTO actor_aliases (alias_id, actor_id, alias_name, source_platform, evidence_id)
                VALUES (?, ?, ?, ?, ?);
            """, (str(uuid.uuid4()), actor_id, alias_name, platform, evidence_id))

        # Store Wallets
        for w in extracted_payload.get("crypto_wallets", []):
            cur.execute("""
                INSERT OR IGNORE INTO crypto_wallets (wallet_id, actor_id, currency, address, evidence_id)
                VALUES (?, ?, ?, ?, ?);
            """, (str(uuid.uuid4()), actor_id, w["currency"], w["address"], evidence_id))

        # Store Handles
        for h in extracted_payload.get("contact_handles", []):
            cur.execute("""
                INSERT OR IGNORE INTO contact_handles (contact_id, actor_id, handle_type, handle_value, evidence_id)
                VALUES (?, ?, ?, ?, ?);
            """, (str(uuid.uuid4()), actor_id, h["type"], h["value"], evidence_id))

        # Store Leaked IP Addresses
        for ip in extracted_payload.get("leaked_ips", []):
            cur.execute("""
                INSERT INTO ip_addresses (actor_id, ip_address, leak_source)
                VALUES (?, ?, ?);
            """, (actor_id, ip, metadata.get("source_url", "Live_Sandbox")))

        self.conn.commit()
        return actor_id
