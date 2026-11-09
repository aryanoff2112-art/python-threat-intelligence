import pandas as pd
import pytest

pytest.importorskip("flask")  # skipped (not errored) if Flask is absent; CI installs it

from api.app import create_app
from database import db


def _app(tmp_path):
    path = tmp_path / "t.db"
    conn = db.get_conn(path); db.init_db(conn)
    db.upsert_indicators(conn, [{"ioc_type": "ip", "value": "203.0.113.5", "source": "urlhaus",
                                 "threat": "malware_download", "confidence": 0.9}])
    db.insert_alerts(conn, pd.DataFrame([{"run_id": "r1", "src_ip": "10.0.0.1", "dst_ip": "203.0.113.5",
                                          "risk_score": 77.0, "severity": "high", "ioc_match": 1}]))
    return create_app(path).test_client()


def test_endpoints(tmp_path):
    c = _app(tmp_path)
    assert c.get("/health").json == {"status": "ok"}
    assert c.get("/alerts?severity=high").json[0]["dst_ip"] == "203.0.113.5"
    assert c.get("/alerts/1").status_code == 200 and c.get("/alerts/99").status_code == 404
    assert c.get("/stats").json["alerts_by_severity"] == {"high": 1}
    assert c.get("/ioc/check?value=203.0.113.5").json["malicious"] is True
    assert c.get("/ioc/check?value=198.51.100.1").json["malicious"] is False
    assert c.get("/ioc/check").status_code == 400


def test_duplicate_indicators_ignored(tmp_path):
    conn = db.get_conn(tmp_path / "d.db"); db.init_db(conn)
    ioc = {"ioc_type": "ip", "value": "203.0.113.5", "source": "x", "confidence": 0.5}
    assert db.upsert_indicators(conn, [ioc]) == 1 and db.upsert_indicators(conn, [ioc]) == 0
