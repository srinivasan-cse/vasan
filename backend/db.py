"""SQLite persistence layer (SQL schema is MySQL-portable)."""
import os, sqlite3

DB_PATH = os.environ.get("ZTACS_DB", os.path.join(os.path.dirname(__file__), "ztacs.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, mobile TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  trust REAL NOT NULL DEFAULT 0.1,
  state TEXT NOT NULL DEFAULT 'NORMAL', state_until REAL DEFAULT 0, state_reason TEXT DEFAULT '',
  consecutive_denials INTEGER DEFAULT 0, failed_logins INTEGER DEFAULT 0,
  otp_secret TEXT NOT NULL, otp_counter INTEGER DEFAULT 0, otp_expires REAL DEFAULT 0, otp_attempts INTEGER DEFAULT 0,
  created REAL NOT NULL, last_login REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created REAL, last_activity REAL, last_heartbeat REAL,
  status TEXT DEFAULT 'ACTIVE', reason TEXT DEFAULT '', ended REAL DEFAULT 0, ip TEXT, ua TEXT);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user_id INTEGER, session_id TEXT,
  action TEXT, prev_action TEXT, allowed INTEGER, reason TEXT, anomaly REAL, trust_before REAL, trust_after REAL, threshold REAL);
CREATE TABLE IF NOT EXISTS policies(
  permission TEXT PRIMARY KEY, base_threshold REAL, threshold REAL, sens REAL, role TEXT DEFAULT 'any',
  title TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS replay(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, permission TEXT, state TEXT, action INTEGER, reward REAL, next_state TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user_id INTEGER, username TEXT, severity TEXT, message TEXT, ack INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, event TEXT, user TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, filename TEXT NOT NULL,
  stored_name TEXT NOT NULL, size INTEGER NOT NULL, content_type TEXT NOT NULL, uploaded REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_logs_user ON logs(user_id, ts);
CREATE INDEX IF NOT EXISTS ix_files_user ON files(user_id, uploaded);
"""

def conn():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

def run(sql, args=(), fetch=None):
    """fetch: None -> lastrowid, 'one' -> dict|None, 'all' -> list[dict]"""
    c = conn()
    try:
        cur = c.execute(sql, args)
        if fetch == "one":
            r = cur.fetchone(); r = dict(r) if r else None
        elif fetch == "all":
            r = [dict(x) for x in cur.fetchall()]
        else:
            r = cur.lastrowid
        c.commit()
        return r
    finally:
        c.close()

def init():
    c = conn()
    try:
        c.executescript(SCHEMA); c.commit()
    finally:
        c.close()
