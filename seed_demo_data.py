import uuid
from datetime import datetime
from db_manager import get_connection, init_database

def seed_multiple_targets():
    init_database()
    conn = get_connection()
    cur = conn.cursor()

    # Clear old data so there are no duplicate conflicts
    cur.execute("DELETE FROM ip_addresses;")
    cur.execute("DELETE FROM contact_handles;")
    cur.execute("DELETE FROM crypto_wallets;")
    cur.execute("DELETE FROM actor_aliases;")
    cur.execute("DELETE FROM raw_evidence_log;")
    cur.execute("DELETE FROM threat_actors;")

    targets = [
        {
            "id": str(uuid.uuid4()),
            "primary_label": "DreadOps",
            "risk_score": 95,
            "aliases": [
                ("DreadOps", "Dread Forum"),
                ("ApexBreach", "Exploit Market")
            ],
            "wallets": [
                ("BTC", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
                ("XMR", "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkFxbANsAnJYPbb3iQ1YBRk1UXCDRSiKc9bkMyNVZnnC5Bjpps557xKqAb7")
            ],
            "contacts": [
                ("xmpp", "phantom_ops@exploit.im"),
                ("telegram", "@dread_ops")
            ],
            "leaks": [
                ("185.220.101.5", "http://hiddenleak45j3.onion/post/99")
            ],
            "evidence": ("http://dreadmarket.onion/thread/104", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", "<html>DreadOps marketplace vendor escrow feed</html>")
        },
        {
            "id": str(uuid.uuid4()),
            "primary_label": "VaultShadow",
            "risk_score": 88,
            "aliases": [
                ("ShadowRoot", "Genesis Market"),
                ("CryptVault", "Russian Market")
            ],
            "wallets": [
                ("ETH", "0x71C8418013f89345130183416d614CE283640000"),
                ("XMR", "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otRmvJMh3acgAvCsVuHRSYrN41BKHuNJzHr6Jx4nWwk7hk25MhF7K")
            ],
            "contacts": [
                ("tox", "76b2c8a1e9409152345091823409182309182309182309182309182309182309182309182309"),
                ("email", "vaultshadow@thesecure.biz")
            ],
            "leaks": [],
            "evidence": ("http://genesisdark66.onion/vendor/shadow", "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1", "<html>ShadowRoot credential vault listing</html>")
        },
        {
            "id": str(uuid.uuid4()),
            "primary_label": "ZeroDayVendor",
            "risk_score": 92,
            "aliases": [
                ("KryptonZero", "XSS Forum"),
                ("ByteReaper", "BreachForums")
            ],
            "wallets": [
                ("BTC", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            ],
            "contacts": [
                ("xmpp", "bytereaper@calyx.net"),
                ("telegram", "@zeroday_broker")
            ],
            "leaks": [
                ("94.102.61.12", "http://xssforumleak7.onion/debug/error_log")
            ],
            "evidence": ("http://xssforumleak7.onion/thread/552", "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2", "<html>ByteReaper 0-day exploit payload proof</html>")
        },
        {
            "id": str(uuid.uuid4()),
            "primary_label": "DarkNexus",
            "risk_score": 78,
            "aliases": [
                ("NexusAdmin", "Abacus Market"),
                ("SilkGhost", "Archetyp Market")
            ],
            "wallets": [
                ("BTC", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
                ("ETH", "0x2810782bf36d31723325602482ab9a89f8419b63")
            ],
            "contacts": [
                ("xmpp", "nexus_escrow@jabber.cz")
            ],
            "leaks": [],
            "evidence": ("http://archetypx34k.onion/market/escrow", "d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3", "<html>DarkNexus identity escrow verification</html>")
        }
    ]

    now_utc = datetime.utcnow().isoformat() + "Z"

    for t in targets:
        cur.execute(
            "INSERT INTO threat_actors (actor_id, primary_label, risk_score) VALUES (?, ?, ?);",
            (t["id"], t["primary_label"], t["risk_score"])
        )
        ev_id = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO raw_evidence_log (evidence_id, source_url, sha256_checksum, raw_html, crawled_at) VALUES (?, ?, ?, ?, ?);",
            (ev_id, t["evidence"][0], t["evidence"][1], t["evidence"][2], now_utc)
        )

        for alias, platform in t["aliases"]:
            cur.execute(
                "INSERT INTO actor_aliases (alias_id, actor_id, alias_name, source_platform, evidence_id) VALUES (?, ?, ?, ?, ?);",
                (str(uuid.uuid4()), t["id"], alias, platform, ev_id)
            )
        for curr, addr in t["wallets"]:
            cur.execute(
                "INSERT INTO crypto_wallets (wallet_id, actor_id, currency, address, evidence_id) VALUES (?, ?, ?, ?, ?);",
                (str(uuid.uuid4()), t["id"], curr, addr, ev_id)
            )
        for htype, hval in t["contacts"]:
            cur.execute(
                "INSERT INTO contact_handles (contact_id, actor_id, handle_type, handle_value, evidence_id) VALUES (?, ?, ?, ?, ?);",
                (str(uuid.uuid4()), t["id"], htype, hval, ev_id)
            )
        for ip, src in t["leaks"]:
            cur.execute(
                "INSERT INTO ip_addresses (actor_id, ip_address, leak_source) VALUES (?, ?, ?);",
                (t["id"], ip, src)
            )

    conn.commit()
    conn.close()
    print("[+] Successfully seeded 4 distinct threat actor syndicates into database.")

if __name__ == "__main__":
    seed_multiple_targets()
