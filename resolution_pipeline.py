import uuid
from db_manager import get_connection

class EntityResolutionPipeline:
    def __init__(self):
        self.conn = get_connection()

    def resolve_and_store(self, extracted_payload: dict, alias_name: str, platform: str) -> str:
        cur = self.conn.cursor()
        evidence = extracted_payload["evidence_metadata"]
        
        # 1. Log Raw Evidence
        cur.execute("""
            INSERT OR IGNORE INTO raw_evidence_log (source_url, sha256_checksum, raw_content_ref)
            VALUES (?, ?, ?);
        """, (evidence["source_url"], evidence["sha256_checksum"], "content_inline"))
        
        cur.execute("SELECT evidence_id FROM raw_evidence_log WHERE sha256_checksum = ?;", (evidence["sha256_checksum"],))
        evidence_id = cur.fetchone()["evidence_id"]

        # 2. Pivot search across existing entities
        matched_actor_id = None
        for w in extracted_payload["crypto_wallets"]:
            cur.execute("SELECT actor_id FROM crypto_wallets WHERE address = ? LIMIT 1;", (w["address"],))
            row = cur.fetchone()
            if row:
                matched_actor_id = row["actor_id"]
                break

        if not matched_actor_id:
            for h in extracted_payload["contact_handles"]:
                cur.execute("SELECT actor_id FROM contact_handles WHERE handle_value = ? LIMIT 1;", (h["value"],))
                row = cur.fetchone()
                if row:
                    matched_actor_id = row["actor_id"]
                    break

        actor_id = matched_actor_id or str(uuid.uuid4())
        if not matched_actor_id:
            cur.execute("INSERT INTO threat_actors (actor_id, primary_label) VALUES (?, ?);", (actor_id, alias_name))
        
        # 3. Store Alias
        cur.execute("""
            INSERT OR IGNORE INTO actor_aliases (actor_id, alias_name, source_platform, evidence_id)
            VALUES (?, ?, ?, ?);
        """, (actor_id, alias_name, platform, evidence_id))

        # 4. Store Wallets & Handles
        for w in extracted_payload["crypto_wallets"]:
            cur.execute("INSERT OR IGNORE INTO crypto_wallets (actor_id, currency, address, evidence_id) VALUES (?, ?, ?, ?);",
                        (actor_id, w["currency"], w["address"], evidence_id))

        for h in extracted_payload["contact_handles"]:
            cur.execute("INSERT OR IGNORE INTO contact_handles (actor_id, handle_type, handle_value, evidence_id) VALUES (?, ?, ?, ?);",
                        (actor_id, h["type"], h["value"], evidence_id))

        # 5. Store Leaked IP Addresses
        for ip in extracted_payload.get("leaked_ips", []):
            cur.execute("INSERT INTO ip_addresses (actor_id, ip_address, leak_source) VALUES (?, ?, ?);",
                        (actor_id, ip, evidence["source_url"]))

        self.conn.commit()
        return actor_id
