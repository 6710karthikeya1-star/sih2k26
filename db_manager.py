import sqlite3

DB_FILE = "intelligence.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    with open("schema.sql", "r") as f:
        schema = f.read()
    with get_connection() as conn:
        conn.executescript(schema)
    print("[+] Embedded Intelligence Database initialized successfully (intelligence.db).")

if __name__ == "__main__":
    init_database()
