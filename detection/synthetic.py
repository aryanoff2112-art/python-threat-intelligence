"""Synthetic flow generator so the whole project runs offline.

IMPORTANT: results on this data are for pipeline validation only. Attack patterns
are simplified, so metrics will not transfer to real traffic. Report real
numbers from CIC-IDS2017/2018 in your write-up.

Addresses use RFC 5737 documentation ranges and `.example` domains, so nothing
here points at real infrastructure.
"""
import numpy as np
import pandas as pd

from config.config import RANDOM_STATE


def _frame(rng, src, dst, dport, dur, fp, bp, fb, bb, rst, ts, dom, label, atype):
    n = len(src)
    dur = np.maximum(np.asarray(dur, float), 1.0)
    fp, bp = np.maximum(np.asarray(fp, int), 1), np.maximum(np.asarray(bp, int), 0)
    fb, bb = np.asarray(fb, float), np.asarray(bb, float)
    secs = dur / 1e6
    return pd.DataFrame({
        "timestamp": ts, "src_ip": src, "dst_ip": dst, "dst_port": np.asarray(dport, int),
        "dst_domain": dom, "flow_duration": dur, "fwd_packets": fp, "bwd_packets": bp,
        "fwd_bytes": fb, "bwd_bytes": bb,
        "flow_bytes_s": (fb + bb) / secs, "flow_packets_s": (fp + bp) / secs,
        "syn_flags": np.ones(n, int), "rst_flags": np.asarray(rst, int),
        "label": np.full(n, label, int), "attack_type": [atype] * n,
    })


def generate(n_benign=20000, attack_frac=0.06, seed=RANDOM_STATE):
    """Return (flows_df, iocs_df)."""
    rng = np.random.default_rng(seed)
    internal = [f"10.0.0.{i}" for i in range(1, 101)]          # the "100 computers"
    ext_ok = [f"198.51.100.{i}" for i in range(1, 255)]
    c2_ips = [f"203.0.113.{i}" for i in range(1, 61)]
    c2_domains = [f"c2-{i}.bad-update.example" for i in range(1, 11)]
    ok_domains = [f"service{i}.corp-cdn.example" for i in range(1, 51)]
    t0 = pd.Timestamp("2026-01-01")
    rand_ts = lambda n: t0 + pd.to_timedelta(rng.uniform(0, 86400, n), unit="s")

    # ---- benign traffic ----
    n = n_benign
    fp = 1 + rng.poisson(rng.lognormal(1.8, 0.8, n))
    bp = 1 + rng.poisson(rng.lognormal(2.0, 0.8, n))
    fb = fp * rng.lognormal(5.0, 0.8, n)
    bb = bp * rng.lognormal(6.3, 0.9, n)
    dur = rng.lognormal(12.5, 1.8, n)
    heavy = rng.random(n) < 0.02                      # legitimate backups/uploads
    fb[heavy] *= rng.lognormal(5.0, 0.8, heavy.sum())
    dur[heavy] *= 5
    burst = rng.random(n) < 0.01                      # legitimate bursty traffic
    fp[burst] *= 15; bp[burst] *= 15; dur[burst] /= 5
    external = rng.random(n) < 0.85
    dst = np.where(external, rng.choice(ext_ok, n), rng.choice(internal, n))
    dom = np.where(external, rng.choice(ok_domains, n), None)
    ports = rng.choice([80, 443, 443, 443, 53, 22, 25, 3389, 8080, 445], n)
    frames = [_frame(rng, rng.choice(internal, n), dst, ports, dur, fp, bp, fb, bb,
                     rng.random(n) < 0.03, rand_ts(n), dom, 0, "benign")]

    # ---- attacks (each campaign originates from one compromised host) ----
    n_att = int(n_benign * attack_frac)
    plan = {"port_scan": 0.25, "brute_force": 0.20, "dos": 0.15, "exfiltration": 0.15, "c2_beacon": 0.25}
    for atype, share in plan.items():
        remaining = int(n_att * share)
        while remaining > 0:
            src_host = rng.choice(internal)
            base = t0 + pd.to_timedelta(rng.uniform(0, 80000), unit="s")
            if atype == "port_scan":
                k = min(remaining, 40); target = rng.choice(internal)
                f = _frame(rng, [src_host] * k, [target] * k, rng.choice(10000, k, replace=False) + 1,
                           rng.lognormal(8, 0.6, k), rng.integers(1, 3, k), rng.integers(0, 2, k),
                           rng.integers(40, 120, k), rng.integers(0, 60, k), rng.random(k) < 0.7,
                           base + pd.to_timedelta(rng.uniform(0, 120, k), unit="s"), [None] * k, 1, atype)
            elif atype == "brute_force":
                k = min(remaining, 40); target = rng.choice(internal)
                f = _frame(rng, [src_host] * k, [target] * k, rng.choice([22, 3389], k),
                           rng.lognormal(11, 0.5, k), rng.integers(6, 13, k), rng.integers(5, 11, k),
                           rng.integers(300, 900, k), rng.integers(300, 900, k), rng.random(k) < 0.5,
                           base + pd.to_timedelta(rng.uniform(0, 300, k), unit="s"), [None] * k, 1, atype)
            elif atype == "dos":
                k = min(remaining, 60); target = rng.choice(ext_ok)
                pk = rng.lognormal(5, 0.5, k).astype(int)
                f = _frame(rng, [src_host] * k, [target] * k, [80] * k, rng.lognormal(10, 0.6, k),
                           pk, rng.integers(0, 3, k), pk * 60, rng.integers(0, 200, k), np.zeros(k),
                           base + pd.to_timedelta(rng.uniform(0, 60, k), unit="s"), [None] * k, 1, atype)
            elif atype == "exfiltration":
                k = min(remaining, 10)
                f = _frame(rng, [src_host] * k, rng.choice(c2_ips + ext_ok, k), rng.choice([443, 8080], k),
                           rng.lognormal(15, 0.7, k), rng.integers(2000, 8000, k), rng.integers(50, 300, k),
                           rng.lognormal(15.0, 0.7, k), rng.integers(2000, 20000, k), np.zeros(k),
                           base + pd.to_timedelta(rng.uniform(0, 3600, k), unit="s"), [None] * k, 1, atype)
            else:  # c2_beacon: looks benign behaviourally; only intel can catch it
                k = min(remaining, 40); target = rng.choice(c2_ips)
                f = _frame(rng, [src_host] * k, [target] * k, rng.choice([443, 8080], k),
                           rng.normal(5e5, 5e4, k), rng.integers(3, 6, k), rng.integers(3, 6, k),
                           rng.normal(400, 40, k), rng.normal(900, 90, k), np.zeros(k),
                           base + pd.to_timedelta(np.arange(k) * 600 + rng.uniform(-30, 30, k), unit="s"),
                           [rng.choice(c2_domains)] * k, 1, atype)
            frames.append(f)
            remaining -= k

    flows = pd.concat(frames, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
    flows.insert(0, "flow_id", np.arange(len(flows)))

    # ---- threat feed: deliberately INCOMPLETE (60% of C2 infra known) + decoys ----
    rows = [{"ioc_type": "ip", "value": v, "source": "sample_feed", "threat": "c2", "confidence": 0.8}
            for v in c2_ips[:36]]
    rows += [{"ioc_type": "domain", "value": d, "source": "sample_feed", "threat": "c2", "confidence": 0.8}
             for d in c2_domains[:6]]
    rows += [{"ioc_type": "url", "value": f"http://{d}/gate.php", "source": "sample_feed",
              "threat": "c2", "confidence": 0.8} for d in c2_domains[:6]]
    rows += [{"ioc_type": "ip", "value": f"192.0.2.{i}", "source": "sample_feed",
              "threat": "malware_download", "confidence": 0.8} for i in range(1, 101)]
    return flows, pd.DataFrame(rows)
