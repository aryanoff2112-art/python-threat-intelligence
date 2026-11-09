# CIC-IDS2017 experiment protocol (Version 3 milestone)

**Status: NOT YET RUN.** This repository contains the protocol and tooling, not results. Every table below is
blank on purpose. Do not publish numbers that did not come from `results.json` produced by your own run.

## 1. Obtain and verify the data

1. Download *GeneratedLabelledFlows.zip* from the official UNB Canadian Institute for Cybersecurity dataset
   page for CIC-IDS2017 (https://www.unb.ca/cic/datasets/ids-2017.html; confirm you are on the official site).
   Use this flow-CSV set, not *MachineLearningCVE*: only this set contains source/destination IPs.
2. Verify the download. The checksum you were given is for the zip:
   `5ca3f8f69e3514950681615824149973  GeneratedLabelledFlows.zip`
   ```bash
   cp GeneratedLabelledFlows.md5 data/raw/            # the checksum file
   mv GeneratedLabelledFlows.zip data/raw/
   python scripts/verify_checksums.py data/raw/GeneratedLabelledFlows.md5 --dir data/raw   # must print OK
   unzip data/raw/GeneratedLabelledFlows.zip -d data/raw
   ```
   MD5 catches corruption only. A mismatch means: re-download, and do not use the data.

## 2. Use a clean evaluation database (important)

CIC-IDS2017 is a 2017 lab capture with private addresses. Live 2026 threat feeds cannot be meaningfully
applied to it (wrong era, wrong network), so **evaluate with an empty indicator DB** and report IOC matching as
"not applicable on this dataset". Pass a fresh `--db`:

```bash
export DB=data/cic_eval.db        # new, empty file
```

With zero IOC hits the risk scorer records `calibrated_partial` (anomaly + rules calibrated, IOC prior unused).
The "IOC match only" row will be all zeros; that is expected, not a bug.

## 3. Experiments

File names below are as I recall them; use whatever is in your zip. The first run is the one to report;
the others quantify how much the headline depends on protocol choices.

**E1: cross-day generalisation (primary).** Train on Monday and Tuesday, test on Wednesday to Friday, so most
test attack types never appear in training.
```bash
python main.py evaluate --db $DB \
  --train data/raw/Monday*.csv data/raw/Tuesday*.csv \
  --test  data/raw/Wednesday*.csv data/raw/Thursday*.csv data/raw/Friday*.csv \
  --benign-window-frac 0.25 --rf-max-rows 300000 --seed 42
```
Caveats to state in your write-up: Monday is benign-only; validation is carved from the end of the training days, so
the risk calibration only ever sees Tuesday's attack types (FTP/SSH-Patator).

**E2: single-stream temporal split.** All days concatenated in time order; test is roughly the last 20% (mostly Friday).
```bash
python main.py evaluate --db $DB --flows data/raw/*.csv --benign-window-frac 0.25 --seed 42
```

**E3: leakage ablation.** Same as E2 plus `--keep-duplicates` (cross-split duplicates are normally excluded from metrics).
The difference between E2 and E3 is the inflation that naive splitting would have caused; report it.

**Variance.** Repeat E1 and E2 with `--seed 1`, `--seed 2`, `--seed 3` (seed also controls benign-window subsampling).
Report mean and standard deviation, not the best run.

**Memory.** Only the ~17 needed columns are read. If RAM is still limited, lower `--benign-window-frac` (all attack
windows are kept; benign windows are sampled) and `--rf-max-rows`. Disclose both values. Subsampling inflates raw
precision, so report `precision_at_original_prevalence`, which the tool computes.

## 4. Check before trusting any number

- `results.json -> leakage`: `time_order_ok` is `true`; duplicates counts are plausible; `conflicting_label_signatures_in_train`
  (identical features, different labels) is reported honestly, since it bounds achievable accuracy.
- Cleaning report printed at load: `twelve_hour_clock_rows_shifted`. CIC-IDS2017 timestamps are, to my recollection,
  written without AM/PM; the loader detects this per day and repairs it. Confirm the shifted-row count is non-zero for
  full-day files and that attacks fall where the dataset documentation says (e.g. Friday DDoS/PortScan in the afternoon).
- `dataset.attack_support`: do not interpret per-attack recall for attack types with very few test flows.
- Published analyses of CIC-IDS2017 document flow-construction and labelling errors. If you use a corrected release, say which.

## 5. What to record (maps to the milestone tasks)

All values come from `data/processed/results.json` (`models.<name>`), `performance`, and `reproducibility`
(command line, SHA-256 of inputs, library versions).

| Metric | Where |
|---|---|
| Precision, recall, F1, FPR | `models.*.precision / recall / f1 / false_positive_rate` |
| Precision at original prevalence | `models.*.precision_at_original_prevalence` (when subsampled) |
| ROC-AUC, PR-AUC | `models.*.roc_auc / pr_auc` |
| Processing throughput | `performance.throughput_flows_per_sec` (state the CPU) |
| Per-attack recall + support | `models.*.recall_by_attack`, `dataset.attack_support` |
| Unseen-attack generalisation | `unseen_attack_generalization` |

### Results template (fill from your run; leave blank until then)

E1, seed 42, benign-window-frac = ___, rf-max-rows = ___, CPU = ___

| Approach | Precision | Prec. @ orig. prevalence | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| Behavioural rules | | | | | | |
| Isolation Forest (benign-only) | | | | | | |
| Isolation Forest (unsupervised) | | | | | | |
| IOC matching | n/a | n/a | n/a | n/a | n/a | n/a |
| Hybrid (calibrated) | | | | | | |
| Random Forest baseline | | | | | | |

Throughput: ______ flows/s. Mean ± sd over seeds 1-3: ______.

Then answer, in your own words: where does each approach fail, why, and what would you change? A negative or
mediocre result that is explained and reproducible is more convincing than a high number you cannot explain.
