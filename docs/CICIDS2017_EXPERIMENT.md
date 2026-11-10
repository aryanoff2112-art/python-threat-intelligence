
# CIC-IDS2017 evaluation protocol

**Status: NOT RUN in this repository snapshot.** This project includes the experiment tooling and a blank reporting template, not real-world benchmark results. Do not publish synthetic-demo metrics as CIC-IDS2017 results.

## 1. Download and verify the correct dataset

Use the official CIC-IDS2017 `GeneratedLabelledFlows.zip` release from the Canadian Institute for Cybersecurity: https://www.unb.ca/cic/datasets/ids-2017.html. This flow set includes source/destination IPs. The `MachineLearningCVE` files do not include the same network identity fields and are not interchangeable for IOC evaluation.

Put both the archive and its supplied checksum file in `data/raw/`, then run in PowerShell from the project root:

```powershell
python scripts/verify_checksums.py data/raw/GeneratedLabelledFlows.md5 --dir data/raw
Expand-Archive -Path data/raw/GeneratedLabelledFlows.zip -DestinationPath data/raw -Force
Get-ChildItem data/raw -Recurse -Filter *.csv | Select-Object -ExpandProperty FullName
```

The checksum provided with this project is expected to match the archive named `GeneratedLabelledFlows.zip`. MD5 detects accidental corruption; it is not a cryptographic authenticity guarantee. If verification fails, re-download and do not run the experiment on that archive.

## 2. Keep historical IOC data out of the benchmark

CIC-IDS2017 is a 2017 lab capture. Current OTX/URLhaus indicators are not ground truth for 2017 private-address traffic. Unless you have a documented historical IOC feed whose validity period covers the capture, disable IOC matching for the benchmark using `--no-ioc`. This leaves the IOC-only baseline with no hits and the hybrid model without an IOC signal; report that limitation clearly. Live IOC collection remains available for the separate current-traffic demo/detection workflow.

## 3. Primary experiment: cross-day generalisation

Use Monday and Tuesday for training/validation, and Wednesday through Friday as the held-out test set. The program splits the training days chronologically into train and validation, applies an embargo, and now refuses to continue if the three splits overlap or are out of temporal order.

```powershell
$train = Get-ChildItem data/raw -Recurse -Filter *.csv | Where-Object { $_.Name -match 'Monday|Tuesday' } | Select-Object -ExpandProperty FullName
$test = Get-ChildItem data/raw -Recurse -Filter *.csv | Where-Object { $_.Name -match 'Wednesday|Thursday|Friday' } | Select-Object -ExpandProperty FullName
if ($train.Count -eq 0 -or $test.Count -eq 0) { throw 'Could not identify expected day files; inspect the filenames first.' }
python main.py evaluate --db data/cic_eval_empty.sqlite --no-ioc --train $train --test $test --benign-window-frac 0.25 --rf-max-rows 300000 --seed 42
```

Use a new database path for this run. With `--no-ioc`, the evaluation does not load or use stored indicators, regardless of what is in another database. Check the output's `reproducibility.ioc_matching_enabled` is `false` and `dataset.iocs_loaded` is `0`.

**Caveat:** Monday is benign-only in the commonly distributed capture. Consequently, the validation split may see only the attack types present in the tail of Tuesday. The Wednesday-Friday test set contains attack types that may be unseen during training/calibration. Do not describe this as a fully representative production test.

## 4. Secondary experiments

Single-stream temporal split across all available day files:

```powershell
$all = Get-ChildItem data/raw -Recurse -Filter *.csv | Select-Object -ExpandProperty FullName
python main.py evaluate --db data/cic_eval_empty.sqlite --no-ioc --flows $all --benign-window-frac 0.25 --seed 42
```

Leakage ablation (include exact duplicate feature signatures across splits to show their effect):

```powershell
python main.py evaluate --db data/cic_eval_empty.sqlite --no-ioc --flows $all --benign-window-frac 0.25 --keep-duplicates --seed 42
```

Repeat the primary and secondary experiments with seeds 1, 2, and 3. Report mean and standard deviation, not the best seed. Keep each run's `results.json` before starting the next run because the default results path is overwritten.

## 5. Quality checks before interpreting results

- `results.json -> leakage.time_order_ok` must be `true`; the application now fails closed if timestamps overlap across train/validation/test.
- Review the cleaning report, especially invalid values, duplicates, and `twelve_hour_clock_rows_shifted`. The 12-hour clock repair is heuristic; inspect timestamps against the dataset's published capture schedule before trusting it.
- Review `dataset.attack_support` and per-attack recall. Do not overinterpret tiny support counts.
- Record `sampling.benign_row_fraction`, `sampling.rf_max_train_rows`, CPU, Python/library versions, and input SHA-256 values. Window subsampling changes class prevalence; use `precision_at_original_prevalence` where available.
- The Random Forest is a supervised baseline, not an unsupervised detector. Keep that distinction in the report.
- The benchmark's exact-duplicate filtering does not eliminate all possible leakage (for example, shared hosts or campaign behaviour). Discuss remaining limitations.

## 6. Metrics to report

| Metric | JSON location |
|---|---|
| Precision, recall, F1, FPR | `models.*.precision / recall / f1 / false_positive_rate` |
| Prevalence-corrected precision | `models.*.precision_at_original_prevalence` |
| ROC-AUC, PR-AUC | `models.*.roc_auc / pr_auc` |
| Throughput | `performance.throughput_flows_per_sec` |
| Per-attack recall | `models.*.recall_by_attack` |
| Attack support | `dataset.attack_support` |
| Experiment inputs and environment | `reproducibility` |

## 7. Results template — leave blank until measured

| Approach | Precision | Precision @ original prevalence | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|
| Behavioural rules | | | | | | | |
| Isolation Forest (benign-only) | | | | | | | |
| Isolation Forest (unsupervised) | | | | | | | |
| IOC matching | N/A (disabled) | N/A | N/A | N/A | N/A | N/A | N/A |
| Hybrid (calibrated, no IOC) | | | | | | | |
| Random Forest (supervised baseline) | | | | | | | |

Throughput: ______ flows/s. Mean ± SD over seeds: ______. CPU: ______.

A reproducible mediocre result with an honest error analysis is more useful than an inflated headline score.

