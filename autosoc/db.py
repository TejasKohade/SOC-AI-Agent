"""SQLite store shared by the SIEM, case management, mocks and vulnerability management."""
import json
import sqlite3
import threading
import time
import uuid

from . import config

_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts REAL, source TEXT, host TEXT, user TEXT, action TEXT,
  src_ip TEXT, dst_ip TEXT, raw TEXT, run_id TEXT, source_type TEXT, category TEXT);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, ts REAL, rule_id TEXT, rule_title TEXT, severity TEXT, mitre TEXT,
  host TEXT, user TEXT, src_ip TEXT, event_ids TEXT, case_id TEXT, run_id TEXT, cves TEXT,
  detector TEXT DEFAULT 'signature');
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, created REAL, updated REAL, title TEXT, status TEXT, severity TEXT,
  host TEXT, user TEXT, verdict TEXT, confidence REAL, mitre TEXT, playbook TEXT,
  summary TEXT, report TEXT, investigation TEXT, run_id TEXT, scenario TEXT, kind TEXT DEFAULT 'alert',
  llm_calls INTEGER DEFAULT 0, tool_calls INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, ts REAL, actor TEXT, kind TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, case_id TEXT, finding_id TEXT, playbook TEXT, step TEXT, tool TEXT,
  params TEXT, tier INTEGER, base_tier INTEGER, tier_reasons TEXT, status TEXT, approvals TEXT,
  rollback TEXT, result TEXT, created REAL, updated REAL, escalated INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS mock_state (
  id TEXT PRIMARY KEY, tool TEXT, op TEXT, target TEXT, params TEXT, ts REAL,
  active INTEGER, undone_ts REAL);
CREATE TABLE IF NOT EXISTS hosts_state (host TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, host TEXT, cve TEXT, port INTEGER, package TEXT, installed_version TEXT,
  state TEXT, cvss REAL, epss REAL, kev INTEGER, risk REAL, priority TEXT, sla_due REAL,
  first_seen REAL, last_seen REAL, ticket_id TEXT, summary TEXT, fix_plan TEXT, campaign TEXT,
  applicability TEXT, exception TEXT, history TEXT, sla_warned INTEGER DEFAULT 0,
  sla_breached INTEGER DEFAULT 0, proposal TEXT);
CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY, finding_id TEXT, title TEXT, assignee TEXT, due REAL, status TEXT,
  priority TEXT, body TEXT, created REAL, updated REAL, escalated INTEGER DEFAULT 0, notes TEXT);
CREATE TABLE IF NOT EXISTS llm_cache (key TEXT PRIMARY KEY, response TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, scenario TEXT, kind TEXT, passed INTEGER,
  detected INTEGER, verdict_ok INTEGER, playbook_ok INTEGER, duration REAL, details TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS injections (
  id TEXT PRIMARY KEY, ts REAL, origin TEXT, mitre TEXT, label TEXT, host TEXT, user TEXT,
  indicator TEXT, event_ids TEXT, source TEXT, matched_case TEXT, detected INTEGER DEFAULT 0,
  detect_latency REAL);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, created REAL, updated REAL, title TEXT, status TEXT, severity TEXT,
  severity_score REAL, host TEXT, user TEXT, mitre TEXT, case_ids TEXT, alert_ids TEXT,
  stages TEXT, rationale TEXT);
"""


def connect():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=False, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


_conn = None


def conn():
    global _conn
    with _lock:
        if _conn is None:
            _conn = connect()
            _conn.executescript(SCHEMA)
        return _conn


def reset_connection():
    """Drop the cached connection (used when tests point AUTOSOC_DB elsewhere)."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None


def execute(sql, params=()):
    with _lock:
        return conn().execute(sql, params)


def query(sql, params=()):
    with _lock:
        return [dict(r) for r in conn().execute(sql, params).fetchall()]


def one(sql, params=()):
    rows = query(sql, params)
    return rows[0] if rows else None


def insert(table, row: dict):
    row = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in row.items()}
    cols = ",".join(row)
    qs = ",".join("?" for _ in row)
    execute(f"INSERT OR REPLACE INTO {table} ({cols}) VALUES ({qs})", tuple(row.values()))


def update(table, key, key_value, fields: dict):
    fields = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in fields.items()}
    sets = ",".join(f"{k}=?" for k in fields)
    execute(f"UPDATE {table} SET {sets} WHERE {key}=?", (*fields.values(), key_value))


def loads(v, default=None):
    if v is None or v == "":
        return default
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default


def new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


_STATE_TABLES = ("events", "alerts", "cases", "audit", "actions", "mock_state", "hosts_state",
                 "findings", "tickets", "kv", "injections", "incidents")


def wipe():
    """Clear all runtime state, metrics included (keeps the schema and the LLM cache)."""
    with _lock:
        for t in _STATE_TABLES + ("metrics",):
            conn().execute(f"DELETE FROM {t}" + (" WHERE k NOT LIKE 'llm_exhausted:%'" if t == "kv" else ""))


def wipe_keep_metrics():
    """Fresh environment for the next scenario, keeping the metrics collected so far."""
    with _lock:
        for t in _STATE_TABLES:
            conn().execute(f"DELETE FROM {t}" + (" WHERE k NOT LIKE 'llm_exhausted:%'" if t == "kv" else ""))


# ---- simulated clock: VM SLA scenarios jump time forward without waiting ----

def now() -> float:
    row = one("SELECT v FROM kv WHERE k='clock_offset'")
    return time.time() + (float(row["v"]) if row else 0.0)


def advance_clock(seconds: float):
    row = one("SELECT v FROM kv WHERE k='clock_offset'")
    off = (float(row["v"]) if row else 0.0) + seconds
    execute("INSERT OR REPLACE INTO kv (k, v) VALUES ('clock_offset', ?)", (str(off),))


def audit(case_id, actor, kind, data):
    insert("audit", {"case_id": case_id, "ts": now(), "actor": actor, "kind": kind, "data": data})
