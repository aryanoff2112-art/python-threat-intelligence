"""Thin SQLite layer for indicators and alerts."""
import sqlite3
from pathlib import Path
from typing import Iterable

import pandas as pd

from config.config import DB_PATH

SCHEMA = Path(__file__).with_name("schema.sql")

ALERT_COLUMNS = [
    "run_id", "event_time", "src_ip", "dst_ip", "dst_port", "dst_domain",
    "risk_score", "severity", "anomaly_pct", "ioc_match", "ioc_source",
    "ioc_threat", "rules_triggered", "explanation", "ground_truth_label",
    "attack_type", "fingerprint",
]


def get_conn(path=None) -> sqlite3.Connection:
    path = Path(path or DB_PATH)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


MIGRATIONS = {"indicators": {"last_seen": "TEXT", "expires_at": "TEXT"},
              "alerts": {"fingerprint": "TEXT"}}


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables, and add columns introduced after a database was first created."""
    tables = ["indicators", "alerts"]
    existing = {t: {r[1] for r in conn.execute(f"PRAGMA table_info({t})")} for t in tables}
    for table, cols in MIGRATIONS.items():
        if existing[table]:                     # table exists from an older version
            for col, typ in cols.items():
                if col not in existing[table]:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    conn.executescript(SCHEMA.read_text())
    conn.commit()


def upsert_indicators(conn: sqlite3.Connection, iocs: Iterable[dict]) -> int:
    """Insert indicators; an existing (type, value, source) is refreshed (last_seen, expiry,
    confidence). Returns the number of NEW rows."""
    rows = [
        (i["ioc_type"], i["value"], i["source"], i.get("threat"), float(i.get("confidence", 0.5)),
         i.get("first_seen"), i.get("last_seen") or i.get("first_seen"), i.get("expires_at"))
        for i in iocs
    ]
    before = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    conn.executemany(
        "INSERT INTO indicators (ioc_type, value, source, threat, confidence, first_seen, last_seen, expires_at) "
        "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(ioc_type, value, source) DO UPDATE SET "
        "last_seen=COALESCE(excluded.last_seen, last_seen), expires_at=excluded.expires_at, "
        "confidence=excluded.confidence, threat=COALESCE(excluded.threat, threat)",
        rows,
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] - before


def load_indicators(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM indicators", conn)


def insert_alerts(conn: sqlite3.Connection, alerts: pd.DataFrame) -> int:
    """Insert alerts, silently skipping any whose fingerprint already exists (re-runs, duplicate
    flows). Returns the number actually inserted; len(alerts) - returned = duplicates skipped."""
    if alerts.empty:
        return 0
    df = alerts.reindex(columns=ALERT_COLUMNS)
    df = df.astype(object).where(df.notna(), None)
    before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.executemany(
        f"INSERT OR IGNORE INTO alerts ({','.join(ALERT_COLUMNS)}) "
        f"VALUES ({','.join('?' * len(ALERT_COLUMNS))})",
        df.itertuples(index=False, name=None),
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] - before


def fetch_alerts(conn, severity=None, run_id=None, limit=1000) -> pd.DataFrame:
    q, params = "SELECT * FROM alerts WHERE 1=1", []
    if severity:
        q += " AND severity = ?"; params.append(severity)
    if run_id:
        q += " AND run_id = ?"; params.append(run_id)
    q += " ORDER BY risk_score DESC LIMIT ?"; params.append(int(limit))
    return pd.read_sql_query(q, conn, params=params)


def latest_run_id(conn) -> str | None:
    row = conn.execute("SELECT run_id FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
    return row["run_id"] if row else None
