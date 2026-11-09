"""Robustness / security tests: malformed input, invalid IPs, expired indicators, malformed API
responses, corrupted bundles, duplicate alerts and unexpected feature values."""
import json
from unittest import mock

import numpy as np
import pandas as pd
import pytest
import requests

import main
from alerts.alert_engine import build_alerts, fingerprint
from database import db
from detection.bundle import BundleError, load_bundle, save_bundle
from detection.preprocessing import DataFormatError, clean, load_flows_many, standardize_columns
from detection.synthetic import generate
from intelligence import http as feedhttp
from intelligence.http import FeedAuthError, FeedError, FeedRateLimitError
from intelligence.ioc_matcher import IOCMatcher, normalize_ip
from intelligence.otx_collector import fetch_otx, parse_pulses
from intelligence.urlhaus_collector import parse_urlhaus_csv
from tests.test_bundle_and_cli import _fitted

HDR = ("dst_port,flow_duration,fwd_packets,bwd_packets,fwd_bytes,bwd_bytes,"
       "flow_bytes_s,flow_packets_s,syn_flags,rst_flags")
GOOD = "80,1000,2,2,100,200,300.0,4.0,1,0"


def _csv(tmp_path, text, name="f.csv", mode="w"):
    p = tmp_path / name
    (p.write_bytes if mode == "wb" else p.write_text)(text)
    return p


# ------------------------------------------------------------- malformed CSV files
def test_empty_file_and_header_only_are_rejected(tmp_path):
    with pytest.raises(DataFormatError):
        load_flows_many([_csv(tmp_path, "")])
    with pytest.raises(DataFormatError):
        load_flows_many([_csv(tmp_path, HDR + "\n", "h.csv")])


def test_binary_garbage_and_missing_columns_are_rejected(tmp_path):
    with pytest.raises(DataFormatError):
        load_flows_many([_csv(tmp_path, bytes(range(256)) * 50, "g.csv", "wb")])
    with pytest.raises(DataFormatError, match="Missing required"):
        load_flows_many([_csv(tmp_path, "a,b\n1,2\n", "m.csv")])
    with pytest.raises(DataFormatError, match="not found"):
        load_flows_many([tmp_path / "nope.csv"])


def test_ragged_rows_fail_by_default_and_can_be_skipped(tmp_path):
    p = _csv(tmp_path, f"{HDR}\n{GOOD}\n80,1,2,3,4,5,6,7,8,9,EXTRA,FIELDS\n{GOOD.replace('80', '81')}\n")
    with pytest.raises(DataFormatError, match="malformed CSV"):
        load_flows_many([p])
    assert len(load_flows_many([p], skip_bad_lines=True)) == 2


def test_non_numeric_negative_and_out_of_range_values_are_dropped_and_counted(tmp_path):
    rows = [GOOD, "abc,1,1,1,1,1,1,1,1,1", "80,-5,1,1,1,1,1,1,1,1", "70000,1,1,1,1,1,1,1,1,1",
            "80,1,1,1,1,1,Infinity,1,1,1", "81,1,1,1,1,1,1,1,1,1"]
    df = load_flows_many([_csv(tmp_path, HDR + "\n" + "\n".join(rows) + "\n")])
    rep = df.attrs["clean_report"]
    assert len(df) == 2 and rep["non_numeric_or_inf_or_nan"] == 2 and rep["negative_or_port_out_of_range"] == 2


def test_cli_exits_cleanly_on_malformed_input(tmp_path):
    pipe, _, _ = _fitted()
    bundle = save_bundle(pipe, tmp_path / "bundle")
    for text in ("garbage\n", HDR + "\n", f"{HDR}\n{GOOD}\n1,2,3\n"):
        bad = _csv(tmp_path, text, "bad.csv")
        with pytest.raises(SystemExit, match="Input error"):
            main.main(["detect", "--flows", str(bad), "--db", str(tmp_path / "d.db"), "--bundle", str(bundle)])


# ------------------------------------------------------------------- invalid IP addresses
def _flows_with_ips(ips):
    n = len(ips)
    return pd.DataFrame({"src_ip": ips, "dst_ip": ["10.0.0.9"] * n, "dst_port": [80] * n, "flow_duration": [1.0] * n,
                         "fwd_packets": [1] * n, "bwd_packets": [1] * n, "fwd_bytes": [1.0] * n, "bwd_bytes": [1.0] * n,
                         "flow_bytes_s": [1.0] * n, "flow_packets_s": [1.0] * n, "syn_flags": [0] * n, "rst_flags": [0] * n,
                         "fwd_bytes_extra": range(n)})


def test_invalid_flow_ips_are_dropped_and_valid_ones_canonicalised():
    df = clean(_flows_with_ips(["10.0.0.1", "999.1.1.1", "abc", "", "1.2.3", "::gggg", "2001:DB8:0:0::1", None]))
    assert df["src_ip"].tolist() == ["10.0.0.1", "2001:db8::1"] and df.attrs["clean_report"]["invalid_src_ip"] == 6


def test_ipv6_matches_regardless_of_case_or_compression():
    ind = pd.DataFrame([{"ioc_type": "ip", "value": "2001:DB8:0:0:0:0:0:1", "source": "x", "threat": "t",
                         "confidence": 0.9, "first_seen": None}])
    m = IOCMatcher(ind)
    assert m.lookup("2001:db8::1") and m.lookup("2001:0db8::0001") and m.lookup("2001:db8::2") is None


def test_invalid_ioc_ips_never_enter_the_matcher_or_collectors():
    ind = pd.DataFrame([{"ioc_type": "ip", "value": v, "source": "x", "threat": "t", "confidence": 0.9, "first_seen": None}
                        for v in ("999.9.9.9", "not-an-ip", "203.0.113.5")])
    m = IOCMatcher(ind)
    assert len(m) == 1 and m.stats["invalid"] == 2
    assert normalize_ip("010.0.0.1") is None and normalize_ip("1.2.3.4 ") == "1.2.3.4"
    got = parse_pulses([{"indicators": [{"type": "IPv4", "indicator": "300.1.1.1"}]}])
    assert got == []


# ------------------------------------------------------------------ expired / stale indicators
def _ind(value, **kw):
    return {"ioc_type": "ip", "value": value, "source": kw.pop("source", "urlhaus"), "threat": "t",
            "confidence": 0.9, "first_seen": None, "last_seen": None, "expires_at": None, **kw}


def test_expired_stale_and_undated_indicators():
    ind = pd.DataFrame([
        _ind("203.0.113.1", expires_at="2026-01-01T00:00:00Z"),                  # expired
        _ind("203.0.113.2", expires_at="2027-01-01T00:00:00Z", last_seen="2026-06-01"),  # still valid
        _ind("203.0.113.3", last_seen="2025-01-01"),                              # stale for urlhaus (30d)
        _ind("203.0.113.4"),                                                      # undated: cannot be aged
        _ind("203.0.113.5", source="otx", last_seen="2026-03-01"),                # otx allows 365d
    ])
    m = IOCMatcher(ind, as_of="2026-11-08")
    assert m.lookup("203.0.113.1") is None and m.lookup("203.0.113.3") is None
    assert m.lookup("203.0.113.4") and m.lookup("203.0.113.5")
    assert m.lookup("203.0.113.2") is None       # valid expiry, but last_seen is 5 months old (>30d urlhaus)
    assert m.stats["expired"] == 1 and m.stats["stale"] == 2 and m.stats["undated"] == 1
    assert IOCMatcher(ind, as_of="2026-11-08", max_age_days={}).lookup("203.0.113.3")   # disabled when unset


def test_expiry_flows_through_the_database(tmp_path):
    conn = db.get_conn(tmp_path / "x.db"); db.init_db(conn)
    db.upsert_indicators(conn, [{"ioc_type": "ip", "value": "203.0.113.9", "source": "otx", "confidence": 0.7,
                                 "expires_at": "2026-01-01T00:00:00Z"}])
    assert len(IOCMatcher(db.load_indicators(conn), as_of="2026-11-08")) == 0
    assert len(IOCMatcher(db.load_indicators(conn), as_of="2025-12-01")) == 1


def test_old_database_is_migrated_in_place(tmp_path):
    conn = db.get_conn(tmp_path / "old.db")
    conn.executescript("CREATE TABLE indicators (id INTEGER PRIMARY KEY, ioc_type TEXT, value TEXT, source TEXT,"
                       " threat TEXT, confidence REAL, first_seen TEXT, UNIQUE(ioc_type,value,source));"
                       "CREATE TABLE alerts (id INTEGER PRIMARY KEY, run_id TEXT, risk_score REAL, severity TEXT);")
    db.init_db(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(indicators)")} | {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert {"last_seen", "expires_at", "fingerprint"} <= cols


def test_reingesting_refreshes_last_seen_instead_of_duplicating(tmp_path):
    conn = db.get_conn(tmp_path / "r.db"); db.init_db(conn)
    base = {"ioc_type": "ip", "value": "203.0.113.7", "source": "otx", "confidence": 0.7}
    assert db.upsert_indicators(conn, [{**base, "last_seen": "2026-01-01"}]) == 1
    assert db.upsert_indicators(conn, [{**base, "last_seen": "2026-11-01"}]) == 0
    assert conn.execute("SELECT last_seen FROM indicators").fetchone()[0] == "2026-11-01"


# ------------------------------------------------------------------ malformed API responses
@pytest.mark.parametrize("pulses", [None, "x", 5, {}, [None, 1, "s"], [{"indicators": "nope"}],
                                    [{"indicators": [None, 3, {"type": "IPv4"}, {"type": "IPv4", "indicator": 7},
                                                     {"type": "URL", "indicator": "x" * 5000},
                                                     {"type": "domain", "indicator": "ok.example", "is_active": 0}]}]])
def test_otx_parser_survives_any_garbage(pulses):
    stats = {}
    assert parse_pulses(pulses, stats=stats) == [] and stats["rejected"]


def test_urlhaus_parser_survives_garbage_and_rejects_unsafe_rows():
    for bad in (None, 123, b"bytes", "", "\x00\x01\x02", "# only comments\n"):
        assert parse_urlhaus_csv(bad) == []
    stats = {}
    text = "\n".join([
        '"1","2026-01-01","http://ok.example/a","online","2026-01-02","malware_download","","l","r"',
        '"2","2026-01-01","ftp://x/y","online","","","","l","r"',
        '"3","2026-01-01","http://bad port.example/","online","","","","l","r"',
        '"4","2026-01-01","http://h.example:99999/","online","","","","l","r"',
        '"5","2026-01-01","http://' + "a" * 3000 + '.example/","online","","","","l","r"',
        '"6","2026-01-01"']) 
    got = parse_urlhaus_csv(text, stats=stats)
    assert {i["value"] for i in got} == {"http://ok.example/a", "ok.example"}
    assert stats["rejected"] == {"not_http_url": 2, "oversized_or_control_chars": 2, "bad_port": 1}


class _Resp:
    def __init__(self, status=200, body=b"{}", headers=None, payload=None):
        self.status_code, self.content, self.headers, self._p = status, body, headers or {}, payload

    def json(self):
        if self._p is None:
            raise ValueError("not json")
        return self._p


def test_http_401_is_not_retried_and_never_leaks_the_key():
    with mock.patch("intelligence.http.requests.get", return_value=_Resp(401)) as g:
        with pytest.raises(FeedAuthError) as e:
            feedhttp.get_with_retries("https://x", headers={"X-OTX-API-KEY": "SECRET123"}, sleep=lambda s: None)
    assert g.call_count == 1 and "SECRET123" not in str(e.value)


def test_http_429_honours_retry_after_then_gives_up():
    waits = []
    with mock.patch("intelligence.http.requests.get", return_value=_Resp(429, headers={"Retry-After": "7"})) as g:
        with pytest.raises(FeedRateLimitError):
            feedhttp.get_with_retries("https://x", max_retries=2, sleep=waits.append)
    assert g.call_count == 3 and waits == [7.0, 7.0]


def test_http_recovers_from_transient_5xx_and_timeouts():
    seq = [_Resp(503), requests.Timeout("slow"), _Resp(200, b"ok")]
    with mock.patch("intelligence.http.requests.get", side_effect=seq):
        assert feedhttp.get_with_retries("https://x", sleep=lambda s: None).content == b"ok"
    with mock.patch("intelligence.http.requests.get", side_effect=requests.ConnectionError("down")) as g:
        with pytest.raises(FeedError):
            feedhttp.get_with_retries("https://x", max_retries=1, sleep=lambda s: None)
    assert g.call_count == 2


def test_http_refuses_redirects_and_oversized_bodies():
    with mock.patch("intelligence.http.requests.get", return_value=_Resp(302, headers={"Location": "https://evil"})):
        with pytest.raises(FeedError, match="redirect"):
            feedhttp.get_with_retries("https://x", sleep=lambda s: None)
    with mock.patch("intelligence.http.requests.get", return_value=_Resp(200, b"x" * 100)):
        with pytest.raises(FeedError, match="larger"):
            feedhttp.get_with_retries("https://x", max_bytes=10, sleep=lambda s: None)


def test_otx_fetch_rejects_bad_json_structure_and_missing_key():
    with mock.patch("intelligence.otx_collector.OTX_API_KEY", ""):
        with pytest.raises(FeedAuthError):
            fetch_otx()
    with mock.patch("intelligence.otx_collector.OTX_API_KEY", "k"):
        with mock.patch("intelligence.otx_collector.get_with_retries", return_value=_Resp(payload=None)):
            with pytest.raises(FeedError, match="non-JSON"):
                fetch_otx()
        with mock.patch("intelligence.otx_collector.get_with_retries", return_value=_Resp(payload=[1, 2])):
            with pytest.raises(FeedError, match="unexpected JSON"):
                fetch_otx()
        ok = _Resp(payload={"results": [{"name": "p", "indicators": [{"type": "IPv4", "indicator": "203.0.113.5"}]}], "next": None})
        with mock.patch("intelligence.otx_collector.get_with_retries", return_value=ok):
            assert fetch_otx()[0]["value"] == "203.0.113.5"


def test_otx_pagination_cannot_redirect_the_api_key_to_another_host():
    evil = _Resp(payload={"results": [], "next": "https://evil.example/steal"})
    with mock.patch("intelligence.otx_collector.OTX_API_KEY", "k"):
        with mock.patch("intelligence.otx_collector.get_with_retries", return_value=evil) as g:
            with pytest.raises(FeedError, match="outside"):
                fetch_otx()
    assert g.call_count == 1


# ------------------------------------------------------------------ corrupted model bundles
def _bundle(tmp_path):
    pipe, te, matcher = _fitted()
    return save_bundle(pipe, tmp_path / "b"), te, matcher


def _edit_manifest(path, fn):
    mp = path / "manifest.json"; m = json.loads(mp.read_text()); fn(m); mp.write_text(json.dumps(m))


def test_bundle_missing_or_garbled_manifest(tmp_path):
    with pytest.raises(BundleError, match="not found"):
        load_bundle(tmp_path / "nothing")
    path, _, _ = _bundle(tmp_path)
    (path / "manifest.json").write_text("{ not json")
    with pytest.raises(BundleError, match="valid JSON"):
        load_bundle(path)
    (path / "manifest.json").write_text("[1,2,3]")
    with pytest.raises(BundleError, match="JSON object"):
        load_bundle(path)
    (path / "manifest.json").unlink()
    with pytest.raises(BundleError, match="manifest.json"):
        load_bundle(path)


@pytest.mark.parametrize("mutate", [
    lambda m: m.pop("risk"), lambda m: m["anomaly_model"].pop("score_threshold"),
    lambda m: m["risk"].__setitem__("alert_threshold", "high"),
    lambda m: m["risk"].__setitem__("alert_threshold", float("nan")),
    lambda m: m["rules"]["thresholds"].__setitem__("PORT_SCAN", None),
    lambda m: m["input_schema"].__setitem__("feature_columns", []),
    lambda m: m["input_schema"].__setitem__("aggregate_mode", "weird"),
    lambda m: m.__setitem__("files", {"x": "y"}),
    lambda m: m["risk"]["scorer"].__setitem__("method", "evil"),
])
def test_bundle_rejects_structurally_invalid_manifests(tmp_path, mutate):
    path, _, _ = _bundle(tmp_path)
    _edit_manifest(path, mutate)
    with pytest.raises(BundleError):
        load_bundle(path)


def test_bundle_with_valid_checksum_but_unpicklable_or_wrong_model(tmp_path):
    import hashlib
    path, _, _ = _bundle(tmp_path)
    junk = b"not a pickle at all"
    (path / "isolation_forest.joblib").write_bytes(junk)
    _edit_manifest(path, lambda m: m["files"].__setitem__("isolation_forest.joblib", hashlib.sha256(junk).hexdigest()))
    with pytest.raises(BundleError, match="corrupted"):
        load_bundle(path)
    import joblib
    joblib.dump({"a": 1}, path / "isolation_forest.joblib")
    _edit_manifest(path, lambda m: m["files"].__setitem__(
        "isolation_forest.joblib", hashlib.sha256((path / "isolation_forest.joblib").read_bytes()).hexdigest()))
    with pytest.raises(BundleError, match="Isolation Forest"):
        load_bundle(path)


def test_bundle_with_bad_reference_scores(tmp_path):
    import hashlib
    path, _, _ = _bundle(tmp_path)
    for arr in (np.array([]), np.array([1.0, np.nan])):
        np.save(path / "reference_scores.npy", arr)
        _edit_manifest(path, lambda m: m["files"].__setitem__(
            "reference_scores.npy", hashlib.sha256((path / "reference_scores.npy").read_bytes()).hexdigest()))
        with pytest.raises(BundleError, match="reference_scores"):
            load_bundle(path)


# ------------------------------------------------------------------------- duplicate alerts
def test_rerunning_detect_on_the_same_traffic_creates_no_duplicate_alerts(tmp_path):
    flows, iocs = generate(n_benign=3000, seed=5)
    unseen, _ = generate(n_benign=1500, seed=6)
    flows.to_csv(tmp_path / "lab.csv", index=False); iocs.to_csv(tmp_path / "i.csv", index=False)
    unseen.drop(columns=["label", "attack_type"]).to_csv(tmp_path / "new.csv", index=False)
    dbp, mdir = str(tmp_path / "t.db"), str(tmp_path / "m")
    main.main(["ingest", "--source", "file", "--file", str(tmp_path / "i.csv"), "--db", dbp])
    main.main(["evaluate", "--flows", str(tmp_path / "lab.csv"), "--db", dbp, "--models-dir", mdir,
               "--results-dir", str(tmp_path / "r")])
    args = ["detect", "--flows", str(tmp_path / "new.csv"), "--db", dbp, "--models-dir", mdir]
    main.main(args)
    first = db.get_conn(dbp).execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    main.main(args)
    assert first > 0 and db.get_conn(dbp).execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == first


def test_duplicate_flows_in_one_batch_collapse_to_one_alert(tmp_path):
    pipe, te, _ = _fitted()
    scored = pipe.score(te)
    top = scored.sort_values("risk_score", ascending=False).head(5)
    doubled = pd.concat([top, top], ignore_index=True)
    alerts = build_alerts(doubled, min_score=0.0, run_id="r1")
    conn = db.get_conn(tmp_path / "d.db"); db.init_db(conn)
    assert len(alerts) == 10 and db.insert_alerts(conn, alerts) == 5
    assert db.insert_alerts(conn, build_alerts(doubled, min_score=0.0, run_id="a-different-run")) == 0


def test_fingerprint_is_stable_and_discriminating():
    base = {"event_time": "t", "src_ip": "a", "dst_ip": "b", "dst_port": 80, "dst_domain": None,
            "flow_duration": 5.0, "fwd_packets": 1, "bwd_packets": 1, "fwd_bytes": 1.0, "bwd_bytes": 1.0}
    assert fingerprint(base) == fingerprint(dict(base))
    assert fingerprint(base) != fingerprint({**base, "dst_port": 81})


# ------------------------------------------------------------------ unexpected feature values
def test_scoring_survives_extreme_nan_inf_and_negative_values():
    pipe, te, _ = _fitted()
    weird = te.head(8).copy()
    weird.loc[weird.index[0], ["fwd_bytes", "flow_bytes_s"]] = [1e300, 1e308]
    weird.loc[weird.index[1], "flow_packets_s"] = np.inf
    weird.loc[weird.index[2], "fwd_packets"] = -5
    weird.loc[weird.index[3], "flow_duration"] = np.nan
    weird.loc[weird.index[4], "dst_port"] = 10 ** 9
    weird.loc[weird.index[5], ["fwd_bytes", "bwd_bytes", "flow_duration"]] = 0
    out = pipe.score(weird)
    assert len(out) == 8 and np.isfinite(out[["anomaly_raw", "risk_score"]].to_numpy()).all()
    assert out["risk_score"].between(0, 100).all()


def test_single_row_batch_works_and_empty_batch_fails_clearly():
    pipe, te, _ = _fitted()
    assert len(pipe.score(te.head(1))) == 1
    with pytest.raises(ValueError, match="empty batch"):
        pipe.score(te.iloc[:0])


def test_clean_drops_what_scoring_should_never_see(tmp_path):
    df = standardize_columns(pd.DataFrame({
        "Destination Port": [80, 70000, -1, 80], "Flow Duration": [1, 1, 1, np.inf],
        "Total Fwd Packets": [1] * 4, "Total Backward Packets": [1] * 4, "Total Length of Fwd Packets": [1] * 4,
        "Total Length of Bwd Packets": [1] * 4, "Flow Bytes/s": [1.0] * 4, "Flow Packets/s": [1.0] * 4,
        "SYN Flag Count": [0] * 4, "RST Flag Count": [0] * 4, "Label": ["BENIGN"] * 4}))
    assert len(clean(df)) == 1
