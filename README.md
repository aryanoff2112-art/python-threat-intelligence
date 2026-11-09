# Python-Based Threat Intelligence and Network Anomaly Detection

A defensive security research prototype that fuses **three independent evidence sources** into one explainable
risk score, with alerting, a REST API and a dashboard.

> **Scope:** a research prototype, not a SIEM or autonomous malware detector. An anomaly is a lead for
> investigation, not proof of an attack.
>
> **Real-world validation status: NOT YET DONE.** All numbers in this README come from a synthetic generator written
> by the same author as the detector. They validate that the pipeline works; they do **not** show it detects real
> attacks. The CIC-IDS2017 protocol and tooling are ready (`docs/CICIDS2017_EXPERIMENT.md`); the run itself is the next milestone.

## The three evidence sources (be able to explain this without the code)

| Source | Question it answers | Strength | Blind spot |
|---|---|---|---|
| **Threat intelligence (IOC match)** | Has this IP/domain/URL been reported malicious, recently? | Very high precision; catches traffic that looks perfectly normal (e.g. C2 beaconing) | Only knows what feeds know; stale or incomplete feeds; says nothing about novel infrastructure |
| **Behavioural anomaly (Isolation Forest)** | Is this flow unusual compared with normal traffic? | Needs no attack labels, so it can flag attack types it has never seen | Unusual is not malicious (backups, bursts); misses attacks that mimic normal behaviour |
| **Calibrated rules** | Does this match a known suspicious pattern (scan fan-out, high packet rate, large upload, RST storms)? | Transparent, explainable, cheap | Fixed patterns; thresholds only as good as the benign data they were calibrated on |

They fail in *different* ways, which is why combining them helps, and each alert states which signals fired and why.
(In the synthetic run: C2 beaconing is invisible to the two behavioural signals and caught only by intel; scans and exfiltration are the reverse.)

## Two separate workflows

| | `evaluate` | `detect` |
|---|---|---|
| Input | **labelled** flows | **unlabelled** traffic (labels never read) |
| Does | temporal split, fit, calibrate on validation, measure on test, save a **model bundle** | load a saved bundle, fresh IOCs from the DB, score, store de-duplicated alerts |

```bash
python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python main.py demo               # synthetic: generate -> ingest feed -> evaluate -> detect on unseen unlabelled flows
python -m pytest -q
python main.py evaluate --flows data/raw/*.csv --db data/cic_eval.db       # real data, see docs/
python main.py detect --flows new.csv [--context earlier.csv] [--bundle models/bundle-...]
python scripts/verify_checksums.py data/raw/GeneratedLabelledFlows.md5 --dir data/raw
python scripts/verify_live_feeds.py        # YOU run this with real keys (see below)
streamlit run dashboard/app.py ; python -m api.app
```

## Architecture

```
labelled flows -> evaluate -> 60/20/20 temporal split (window-aligned + embargo) -> fit IF + rule thresholds (train)
                                       -> calibrate risk weights + alert threshold (validation) -> metrics (test) -> versioned bundle
unlabelled flows -> detect -> bundle -> features -> IF / rules / IOC -> risk score -> alerts (fingerprinted) -> SQLite -> API / dashboard
URLhaus / OTX -> hardened collectors -> IOC store (with last_seen / expiry) -> freshness filter -> matcher
```

## Risk scoring

Default: weights **learned on a held-out validation split** (logistic regression over anomaly strength, IOC confidence,
rules fired), `risk = 100 x P(malicious)`; alert threshold = lowest score keeping validation FPR <= 1%. Nothing is fitted on test.
The original hand-set weights `{0.50, 0.55, 0.20}` (sum 1.25, intentionally: any one strong channel can alert, agreement
saturates at 100) remain as an **uncalibrated prior**, used as a fallback and as an ablation baseline. If validation has
< 5 IOC hits, the IOC weight cannot be learned and the method becomes `calibrated_partial` (flagged in the bundle). Learned
coefficients are dataset-specific; scores reflect validation prevalence and are for ranking and thresholds, not literal probabilities.

## Threat-intelligence integration (live verification: NOT done)

Hardened, but **never run against the live services by the author**. What is implemented and covered by mocked-response tests:

- Explicit timeouts, bounded retries with backoff, `Retry-After` honoured on 429/503, 401/403 raise `FeedAuthError` without retry,
  redirects refused, response size capped, secrets never placed in error messages.
- OTX pagination can only follow links to `otx.alienvault.com` over HTTPS, so a malformed or hostile response cannot send your API key elsewhere.
- Parsers never raise on malformed input: bad rows are skipped and counted by reason (oversized values, control characters, bad ports,
  invalid IPs, inactive OTX indicators, wrong types).
- **Freshness:** indicators carry `last_seen`/`expires_at`. At match time, expired ones and ones older than a per-source maximum age
  (default URLhaus 30 d, OTX 365 d: **assumptions**, configurable in `config.py`) are ignored and counted. Undated indicators cannot be aged and are counted separately.
  Re-ingesting refreshes `last_seen` rather than duplicating. Old databases migrate in place.
- IPs are canonicalised (IPv6 case/compression) on both sides of the match.

To verify live (needs your own keys; exit code is non-zero on failure):
`export URLHAUS_AUTH_KEY=... OTX_API_KEY=... && python scripts/verify_live_feeds.py`. It reports auth outcome, latency, accepted/rejected counts,
indicator-type mix and age distribution to `docs/live_feed_verification.json`. Real rate-limit behaviour and exact current field names still need
that live run; OTX field names (`expiration`, `is_active`, `modified`) follow the public docs but are unconfirmed.

## Time-window strategy (batch consistency)

- Per-source behavioural aggregates use **epoch-aligned 5-minute tumbling windows**, so a flow's aggregates do not depend on batch size when its window is complete.
- Without both `src_ip` and `timestamp` a window cannot be defined, so aggregates are **disabled** rather than computed over the whole batch
  (which would change with batch size). A model trained one way refuses input of the other kind.
- The first/last window of a batch may be cut mid-window, understating aggregates. `detect` flags those flows (`edge_window`, printed warning) and accepts
  `--context <earlier flows>`, which completes the first window without scoring the context rows. Test: scoring a stream as one batch vs two batches + context gives identical scores.
- Train/val/test cuts are aligned to window boundaries, with a 10-minute embargo, so no window straddles splits.
- Not yet implemented: persistent cross-run window state. Continuous deployment would need it; today you pass `--context` yourself.

## Model bundle

`models/bundle-<utc>/` (pointer `models/LATEST`): `manifest.json` (format/feature-set versions, Python/scikit-learn/numpy/pandas versions, feature columns and
order, aggregate mode and window, rule and anomaly thresholds, risk weights, alert threshold, calibration, training summary, evaluation snapshot, SHA-256 of files),
`isolation_forest.joblib`, `reference_scores.npy`. Loading verifies checksums and versions and **any** corruption raises `BundleError`. joblib is pickle: checksums detect corruption,
not a malicious bundle; load only bundles you trust.

## Real-data evaluation protocol

Implemented and tested on synthetic and CIC-layout fixtures: temporal split with embargo; leakage report and exclusion of cross-split duplicates from metrics; per-attack
recall with support; unseen-attack-type test; cross-day option; memory-safe loading (only needed columns); window-preserving benign subsampling with prevalence-corrected
precision; Random Forest row cap; multi-seed support; provenance (command line, input SHA-256, library versions) in every `results.json`; CIC 12-hour-timestamp repair
detected per day. Step by step: **`docs/CICIDS2017_EXPERIMENT.md`** (includes the checksum for your `GeneratedLabelledFlows.zip` and a blank results template).

## Results: synthetic data, seed 42 (pipeline validation only, NOT detection performance)

21,200 flows; 4,297 test rows (309 attacks); 0 duplicates to exclude (synthetic floats rarely collide).

| Model | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| Rules (calibrated thresholds) | 0.730 | 0.637 | 0.680 | 0.0183 | 0.811 |
| IOC match only | 1.000 | 0.249 | 0.399 | 0.0000 | 0.625 |
| Isolation Forest (benign-only training) | 0.832 | 0.511 | 0.633 | 0.0080 | 0.843 |
| Hybrid: prior weights, default threshold | 0.850 | 0.770 | 0.808 | 0.0105 | 0.929 |
| Hybrid: prior weights, threshold tuned on validation | 0.841 | 0.786 | 0.813 | 0.0115 | 0.929 |
| Hybrid: weights + threshold calibrated on validation | 0.846 | 0.803 | 0.824 | 0.0113 | 0.931 |
| Isolation Forest (unsupervised) | 1.000 | 0.091 | 0.166 | 0.0000 | 0.839 |
| Random Forest (supervised baseline) | 0.997 | 0.952 | 0.974 | 0.0003 | 1.000 |

Honest reading:
- **The three hybrid variants are within about 2 F1 points, and that is inside the noise.** Aligning split cuts to window boundaries (a change that should not matter) moved these
  F1 values by ~0.01. Do not claim calibration "improves" accuracy from this; its value is a data-driven threshold and a probability-scaled score. Real conclusions need multiple seeds.
- Calibrated FPR cap: 0.98% on validation, 1.13% on test (cap does not transfer exactly).
- **Unseen attack types:** the supervised Random Forest scored recall 0.0 on every attack type when it was removed from training. The benign-trained Isolation Forest still found
  port scans (1.00), exfiltration (0.98) and DoS (0.75); brute force 0.43; C2 beaconing 0.00 (only intel catches it, and only for indicators the feed knows).
- Unsupervised IF ranks about as well as benign-trained IF (AUC 0.839 vs 0.843) but its threshold lands above most attacks because attacks contaminate training.
- Single seed, simple synthetic attacks, no confidence intervals.

## Testing and verification status

- **Tests (`tests/`):** malformed CSVs (empty, header-only, binary, missing columns, ragged rows, non-numeric/negative/out-of-range values), invalid IPs (flows, IOCs, IPv6 normalisation),
  expired/stale/undated indicators and DB migration, malformed API responses (garbage parser input, 401/429/5xx/timeouts/redirects/oversize, hostile pagination), corrupted bundles (missing/garbled
  manifest, structurally invalid fields, valid-checksum-but-unpicklable model, bad reference scores, tampering), duplicate alerts (re-runs, duplicate flows), unexpected values (extreme/NaN/inf/negative, single-row and empty
  batches), batch/window consistency, CIC-format loading, and checksum verification. One of these tests found a real bug (ragged CSV rows were silently accepted when selecting columns); it is fixed.
- **How they were run:** 81 test cases passed in an offline sandbox where pytest could not be installed, via a small stand-in runner that approximates pytest. **Run `python -m pytest -q` yourself**;
  `.github/workflows/ci.yml` runs it and the end-to-end demo on Python 3.10 and 3.12.
- **Not verified:** live URLhaus/OTX responses (see above), the Streamlit dashboard in a browser (it compiles; not run), and everything on real CIC-IDS2017 data.

## Limitations

Synthetic attacks are simple; CIC-IDS has labelling/flow-construction issues and lab-only addresses (IOC matching is not meaningful on it); batch analysis only; risk scores are not real-world probabilities;
the default IOC max-age values and the 1% FPR target are assumptions; the CIC AM/PM repair is a detected heuristic, not a guarantee.

## Layout

`intelligence/` collectors, HTTP client, matcher · `detection/` preprocessing, features, IF, rules, scoring, pipeline, bundle, leakage, evaluation · `database/` · `alerts/` · `api/` · `dashboard/` ·
`scripts/` (checksum + live-feed verification) · `docs/` · `tests/` · `main.py`.

Uses public data and feeds only. Keys live in environment variables; no credentials or captures are committed.
