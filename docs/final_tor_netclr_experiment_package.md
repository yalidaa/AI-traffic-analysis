# NetCLR Tor Final Experiment Evidence Package

## Purpose

This document is the tracked index for the current final experiment package.

Current task framing:

```text
Tor encrypted traffic risk-evidence binary baseline.
```

This is not Tor malware detection, Tor malicious-user detection, or WFlib closed-world website-fingerprinting. WFlib CW remains a backup engineering capability only. The final competition narrative should use NetCLR as the reportable binary baseline and describe model output as traffic-side risk evidence that requires analyst review.

## Package Locations

Tracked evidence index:

```text
docs/final_tor_netclr_experiment_package.md
```

Local ignored package:

```text
outputs/final_tor_netclr_package/
```

The local package contains a small README, a metrics summary JSON, and PowerShell reproduction commands. It intentionally does not duplicate raw datasets, large PPI CSV files, model checkpoints, or the 8 MB full `metrics.json` with per-sample rows.

## Evidence Inventory

| Evidence | Path | Status |
| --- | --- | --- |
| Inferior raw archive | `datasets/raw/tor/netclr/archives/NCDrift_inf.npz.zip` | Present locally, MD5 verified |
| Superior raw archive | `datasets/raw/tor/netclr/archives/NCDrift_sup.npz.zip` | Present locally, MD5 verified |
| Inferior extracted NPZ | `datasets/raw/tor/netclr/extracted/NCDrift_inf/NCDrift_inf.npz` | Present locally |
| Superior extracted NPZ | `datasets/raw/tor/netclr/extracted/NCDrift_sup/NCDrift_sup.npz` | Present locally |
| Smoke PPI inferior CSV | `datasets/experiments/ppi/tor/netclr_smoke/NCDrift_inf.csv` | Present locally |
| Smoke PPI superior CSV | `datasets/experiments/ppi/tor/netclr_smoke/NCDrift_sup.csv` | Present locally |
| Binary negative view | `datasets/experiments/ppi/tor/netclr_drift_binary/normal/NCDrift_inf.csv` | Present locally |
| Binary positive view | `datasets/experiments/ppi/tor/netclr_drift_binary/risk/NCDrift_sup.csv` | Present locally |
| Quality JSON | `outputs/tor_data_runs/netclr_smoke/quality.json` | Present locally |
| Quality report | `outputs/tor_data_runs/netclr_smoke/quality.md` | Present locally |
| Best checkpoint | `checkpoints/tor_netclr_drift_binary_gpu_v1.pt` | Present locally |
| Full evaluation JSON | `outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/metrics.json` | Present locally |
| Evaluation report | `outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/report.md` | Present locally |
| Final local summary | `outputs/final_tor_netclr_package/` | Present locally after package generation |

## Data Integrity

| File | MD5 |
| --- | --- |
| `NCDrift_inf.npz.zip` | `1088195a92b4c94641bb468b2314b1bd` |
| `NCDrift_sup.npz.zip` | `0fef8c0bc7e88dc881798d47f61f91b5` |

## Task Semantics

| Internal label | Report label | Meaning |
| --- | --- | --- |
| `0` | `netclr_inferior_condition` | NetCLR inferior-condition trace group used as the negative side of this binary baseline. |
| `1` | `netclr_superior_condition` | NetCLR superior-condition trace group used as the positive risk-evidence side of this binary baseline. |

These labels are not `normal` and `malware`. They are a condition-pair baseline for traffic-side risk evidence under NetCLR network-condition drift.

## Quality Summary

Source quality output:

```text
outputs/tor_data_runs/netclr_smoke/quality.json
outputs/tor_data_runs/netclr_smoke/quality.md
```

| Item | Value |
| --- | ---: |
| file_count | 2 |
| sample_count | 28312 |
| invalid_rows | 0 |
| class_count | 93 |
| average_sequence_length | 127.4774 |
| min_sequence_length | 22 |
| max_sequence_length | 128 |
| short_sample_count | 0 |
| empty_direction_sample_count | 0 |

The `class_count = 93` value comes from the original NetCLR class IDs stored in the converted PPI view. The final competition task does not use those IDs as a multiclass target. The reportable binary view groups the two NetCLR condition files into negative and positive risk-evidence sides.

## Training Environment

Recorded GPU training environment:

```text
GPU: NVIDIA GeForce RTX 2060, 6 GB
Driver: 555.99
nvidia-smi CUDA runtime: 12.5
Python: D:\Learningformore\Anaconda\envs\traffic_env\python.exe
Torch: 2.5.1+cu121
torch.cuda.is_available(): True
```

The project `.venv` has CPU-only Torch and should not be used for GPU training.

## Training Command

```powershell
D:\Learningformore\Anaconda\envs\traffic_env\python.exe scripts/train/train_model.py `
  --experiment custom `
  --data-format ppi `
  --benign-dir datasets/experiments/ppi/tor/netclr_drift_binary/normal `
  --malware-dir datasets/experiments/ppi/tor/netclr_drift_binary/risk `
  --save-path checkpoints/tor_netclr_drift_binary_gpu_v1.pt `
  --negative-label-name netclr_inferior_condition `
  --positive-label-name netclr_superior_condition `
  --epochs 10 `
  --batch-size 128 `
  --embed-dim 128 `
  --num-heads 4 `
  --num-layers 2 `
  --ff-dim 256 `
  --split-mode random `
  --target-fpr 0.05
```

Training summary:

```text
Using device: cuda
total samples = 28312
best_epoch = 1
best_val_f1 = 0.7674
early stopping at epoch 4
```

Best checkpoint:

```text
checkpoints/tor_netclr_drift_binary_gpu_v1.pt
```

## Evaluation Command

```powershell
D:\Learningformore\Anaconda\envs\traffic_env\python.exe scripts/eval/run_tor_binary_eval.py `
  --checkpoint checkpoints/tor_netclr_drift_binary_gpu_v1.pt `
  --normal-dir datasets/experiments/ppi/tor/netclr_drift_binary/normal `
  --risk-dir datasets/experiments/ppi/tor/netclr_drift_binary/risk `
  --output-dir outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval `
  --negative-label-name netclr_inferior_condition `
  --positive-label-name netclr_superior_condition `
  --batch-size 256
```

Evaluation outputs:

```text
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/metrics.json
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/report.md
```

## Evaluation Results

| Metric | Value |
| --- | ---: |
| sample_count | 28312 |
| threshold | 0.5664353179 |
| accuracy | 0.2946100593 |
| precision | 0.8290482634 |
| recall | 0.0857676155 |
| f1 | 0.1554531230 |
| fpr | 0.0550712002 |
| fnr | 0.9142323845 |
| tp | 1838 |
| fp | 379 |
| tn | 6503 |
| fn | 19592 |

Grouped summary:

| Group | Count | Accuracy | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: |
| `NCDrift_inf.csv` | 6882 | 0.9449287998 | 0.0000000000 | 0.0550712002 | 0.0000000000 |
| `NCDrift_sup.csv` | 21430 | 0.0857676155 | 0.1579852157 | 0.0000000000 | 0.9142323845 |

## Report Interpretation

Recommended wording:

```text
At the low-false-positive operating point, the NetCLR binary baseline has high precision but very low recall. This means it can surface a small set of high-confidence traffic-side risk evidence, but it misses most positive-side samples. It should be reported as a risk-evidence baseline for assisted triage, not as a mature Tor threat detector.
```

Chinese report wording:

```text
在低误报约束下，NetCLR 二分类基线的 precision 较高，但 recall 很低。这说明模型可以输出一部分高置信流量侧风险证据，但漏检严重。因此当前结果适合用于风险证据优先级排序和辅助研判，不适合包装成成熟的 Tor 恶意检测系统。
```

## What To Exclude From The Final Claim

Do not claim:

- The model detects malicious Tor users.
- Tor traffic is inherently malicious.
- WFlib single-tab means binary classification.
- The current recall is sufficient for production detection.
- LLM/RAG replaces the detector.

Safe claim:

- MineShark can process real Tor-related traffic datasets into PPI format.
- The NetCLR condition-pair binary baseline produces traffic-side risk evidence.
- The current operating point favors precision over recall.
- The Agent/RAG layer helps explain and review model evidence with logs and playbooks.

## Report Generator

`scripts/docs/build_competition_report.py` reads the local summary by default:

```text
outputs/final_tor_netclr_package/metrics_summary.json
```

If the local summary is missing, the script uses an embedded NetCLR fallback summary with the same headline metrics so the anonymous DOCX can still be generated from a clean checkout.
