import sqlite3
import os

DB_FILE = "intelligence.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_database():
    conn = get_connection()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS threat_actors (
            actor_id TEXT PRIMARY KEY,
            primary_label TEXT NOT NULL,
            risk_score INTEGER DEFAULT 95,
            first_observed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_observed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS raw_evidence_log (
            evidence_id TEXT PRIMARY KEY,
            source_url TEXT NOT NULL,
            sha256_checksum TEXT NOT NULL,
            raw_html TEXT,
            crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS actor_aliases (
            alias_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            alias_name TEXT NOT NULL,
            source_platform TEXT NOT NULL,
            evidence_id TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_id) REFERENCES threat_actors (actor_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS crypto_wallets (
            wallet_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            currency TEXT NOT NULL,
            address TEXT NOT NULL,
            evidence_id TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_id) REFERENCES threat_actors (actor_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contact_handles (
            contact_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            handle_type TEXT NOT NULL,
            handle_value TEXT NOT NULL,
            evidence_id TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_id) REFERENCES threat_actors (actor_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ip_addresses (
            ip_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            leak_source TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_id) REFERENCES threat_actors (actor_id) ON DELETE CASCADE
        );
        """)
    conn.close()
    print("[+] Complete SQLite schema verified.")

if __name__ == "__main__":
    init_database()
