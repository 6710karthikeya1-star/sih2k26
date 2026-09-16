CREATE TABLE IF NOT EXISTS threat_actors (
    actor_id TEXT PRIMARY KEY,
    primary_label TEXT NOT NULL,
    risk_score INTEGER DEFAULT 1,
    first_observed DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_observed DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS raw_evidence_log (
    evidence_id TEXT PRIMARY KEY,
    source_url TEXT NOT NULL,
    sha256_checksum TEXT NOT NULL,
    raw_html TEXT NOT NULL,
    crawled_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS actor_aliases (
    alias_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES threat_actors(actor_id) ON DELETE CASCADE,
    alias_name TEXT NOT NULL,
    source_platform TEXT,
    evidence_id TEXT REFERENCES raw_evidence_log(evidence_id),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(alias_name, source_platform)
);

CREATE TABLE IF NOT EXISTS crypto_wallets (
    wallet_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES threat_actors(actor_id) ON DELETE CASCADE,
    currency TEXT NOT NULL,
    address TEXT UNIQUE NOT NULL,
    evidence_id TEXT REFERENCES raw_evidence_log(evidence_id),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pgp_keys (
    key_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES threat_actors(actor_id) ON DELETE CASCADE,
    key_block TEXT UNIQUE NOT NULL,
    evidence_id TEXT REFERENCES raw_evidence_log(evidence_id),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_handles (
    contact_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES threat_actors(actor_id) ON DELETE CASCADE,
    handle_type TEXT NOT NULL,
    handle_value TEXT NOT NULL,
    evidence_id TEXT REFERENCES raw_evidence_log(evidence_id),
    UNIQUE(handle_type, handle_value)
);

CREATE INDEX IF NOT EXISTS idx_crypto_addr ON crypto_wallets(address);
CREATE INDEX IF NOT EXISTS idx_contact_val ON contact_handles(handle_type, handle_value);
CREATE INDEX IF NOT EXISTS idx_evidence_sha ON raw_evidence_log(sha256_checksum);

CREATE TABLE IF NOT EXISTS site_infrastructure (
    infra_id TEXT PRIMARY KEY,
    source_url TEXT NOT NULL,
    favicon_mmh3 TEXT,
    dom_structural_hash TEXT,
    server_header TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_url)
);
