CREATE TABLE IF NOT EXISTS indicators (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type    TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url')),
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    threat      TEXT,
    confidence  REAL NOT NULL DEFAULT 0.5,
    first_seen  TEXT,
    last_seen   TEXT,
    expires_at  TEXT,
    UNIQUE (ioc_type, value, source)
);
CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators (value);

CREATE TABLE IF NOT EXISTS alerts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id             TEXT NOT NULL,
    event_time         TEXT,
    src_ip             TEXT,
    dst_ip             TEXT,
    dst_port           INTEGER,
    dst_domain         TEXT,
    risk_score         REAL NOT NULL,
    severity           TEXT NOT NULL,
    anomaly_pct        REAL,
    ioc_match          INTEGER NOT NULL DEFAULT 0,
    ioc_source         TEXT,
    ioc_threat         TEXT,
    rules_triggered    TEXT,
    explanation        TEXT,
    ground_truth_label INTEGER,
    attack_type        TEXT,
    fingerprint        TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_sev ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alert_run ON alerts (run_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_fp ON alerts (fingerprint);
