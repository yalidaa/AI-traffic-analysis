# Tor Dataset Strategy

## Current Task Framing

Current competition mainline:

**Tor encrypted traffic risk-evidence binary baseline, with LLM-assisted triage.**

The project should not claim that Tor traffic, Tor users, or Tor website-fingerprinting classes are malicious by themselves. The defensible claim is narrower: MineShark uses encrypted-traffic metadata to produce traffic-side risk evidence, then lets the Agent/RAG layer organize that evidence for analyst review.

Important distinction:

- Single-tab does not mean binary.
- WFlib CW is a single-tab closed-world website-fingerprinting dataset, but it is naturally a 95-class classification task.
- The current competition baseline is the NetCLR-derived binary view: `netclr_inferior_condition` vs `netclr_superior_condition`.
- That binary label is not `normal` vs `malware`; it is a risk-evidence operating point for network-condition drift.

Keep the WFlib CW pipeline in the repo as a backup engineering capability. Do not present it as the final model track unless the project explicitly returns to multiclass website fingerprinting.

## Dataset Policy

Tracked configuration lives in `configs/datasets/tor_research_registry.json`. Local data files stay under the project root in `datasets/raw/tor`, remain outside Git tracking, and can be referenced by a local manifest.

| Priority | Dataset family | Current role |
| --- | --- | --- |
| P0 | NetCLR drift-style traces / `NCDrift_inf` and `NCDrift_sup` | Current reportable binary risk-evidence baseline |
| P1 | WFlib CW / `CW.npz.zip` | Backup single-tab Tor data pipeline; 95-class closed-world website fingerprinting |
| P1 | AWF / Rimmer-style Tor WF traces | Optional future single-tab WF reference, not the current binary mainline |
| P1 | ARES / Multitab-WF-Datasets | Optional future multi-tab behavior evaluation |
| P1 | Walkie-Talkie defended traces | Optional future defense-robustness evaluation |
| P1 | WSC subpage-set traces or collection method | Optional future subpage generalization work |
| P2 | Tor circumvention-detection methodology and GTT23 genuine Tor traces | Realism and false-positive boundary references |

## NetCLR Binary Experiment Package

Final evidence index:

```text
docs/final_tor_netclr_experiment_package.md
outputs/final_tor_netclr_package/
```

Raw data:

```text
datasets/raw/tor/netclr/archives/NCDrift_inf.npz.zip
datasets/raw/tor/netclr/archives/NCDrift_sup.npz.zip
datasets/raw/tor/netclr/extracted/NCDrift_inf/NCDrift_inf.npz
datasets/raw/tor/netclr/extracted/NCDrift_sup/NCDrift_sup.npz
```

Verified MD5:

```text
NCDrift_inf: 1088195a92b4c94641bb468b2314b1bd
NCDrift_sup: 0fef8c0bc7e88dc881798d47f61f91b5
```

Converted PPI CSV:

```text
datasets/experiments/ppi/tor/netclr_smoke/NCDrift_inf.csv
datasets/experiments/ppi/tor/netclr_smoke/NCDrift_sup.csv
```

Binary training view:

```text
datasets/experiments/ppi/tor/netclr_drift_binary/normal/NCDrift_inf.csv
datasets/experiments/ppi/tor/netclr_drift_binary/risk/NCDrift_sup.csv
```

Label semantics:

| Internal label | Report label | Meaning |
| --- | --- | --- |
| `0` | `netclr_inferior_condition` | NetCLR inferior-condition trace group used as the negative side of the binary baseline. |
| `1` | `netclr_superior_condition` | NetCLR superior-condition trace group used as the positive risk-evidence side of the binary baseline. |

Quality check summary:

```text
sample_count = 28312
invalid_rows = 0
class_count = 93
average_sequence_length ~= 127.48
min_sequence_length = 22
max_sequence_length = 128
```

Quality check command:

```bash
python scripts/data/check_tor_dataset_quality.py \
  --input datasets/experiments/ppi/tor/netclr_drift_binary \
  --output-json outputs/tor_data_runs/netclr_drift_binary_quality/quality.json \
  --output-md outputs/tor_data_runs/netclr_drift_binary_quality/quality.md
```

GPU training should use the local `traffic_env` Python. The project `.venv` has CPU-only Torch and is not the intended environment for these runs.

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

Evaluate the saved checkpoint:

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

Current best checkpoint:

```text
checkpoints/tor_netclr_drift_binary_gpu_v1.pt
```

Training summary:

```text
Using device: cuda
total samples = 28312
best_epoch = 1
best_val_f1 = 0.7674
early stopping at epoch 4
```

Full evaluation:

```text
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/metrics.json
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/report.md
```

| Metric | Value |
| --- | ---: |
| sample_count | 28312 |
| threshold | 0.5664 |
| accuracy | 0.2946 |
| precision | 0.8290 |
| recall | 0.0858 |
| f1 | 0.1555 |
| fpr | 0.0551 |
| fnr | 0.9142 |
| tp | 1838 |
| fp | 379 |
| tn | 6503 |
| fn | 19592 |

Interpretation for reports and defense:

The low-FPR operating point gives high precision, so the model can surface high-confidence traffic-side risk evidence. Recall is very low, so it misses many positive-side samples and must not be packaged as a mature Tor threat detector. The honest conclusion is that the current binary baseline is useful for evidence prioritization, but it needs stronger features, better labels, or a more suitable task definition before it can support broader detection claims.

## WFlib CW Backup Capability

WFlib CW remains useful as proof that the project can ingest a real Tor single-tab dataset, run quality checks, and train/evaluate a closed-world website-fingerprinting model.

Data and converted view:

```text
datasets/raw/tor/wflib_cw/archives/CW.npz.zip
datasets/raw/tor/wflib_cw/extracted/CW.npz
datasets/experiments/ppi/tor/wflib_cw/CW.csv
```

Quality check summary:

```text
sample_count = 105730
class_count = 95
invalid_rows = 0
average_sequence_length ~= 126.43
min_sequence_length = 50
max_sequence_length = 128
```

Report WFlib CW as:

```text
Tor single-tab closed-world website-fingerprinting backup experiment.
```

Do not report it as:

```text
Tor binary detection
Tor malware detection
Tor malicious-user detection
```

If this backup line is run later, use the multiclass scripts intentionally:

```bash
python scripts/train/train_tor_multiclass.py --preset tor_cw_multiclass --cpu

python scripts/eval/run_tor_multiclass_eval.py \
  --checkpoint checkpoints/tor_cw_multiclass_baseline.pt \
  --data-dir datasets/experiments/ppi/tor/wflib_cw \
  --output-dir outputs/tor_data_runs/cw_multiclass_baseline \
  --max-samples-per-class 20 \
  --cpu
```

## Registry And Manifest Commands

Render the research registry:

```bash
python scripts/data/render_tor_dataset_inventory.py \
  --output outputs/tor_dataset_inventory.md
```

Validate a local data manifest:

```bash
python scripts/data/render_tor_dataset_inventory.py \
  --local-manifest datasets/experiments/tor_manifest.local.json \
  --require-existing-paths \
  --output outputs/tor_dataset_inventory.md
```

Example local manifest:

```json
{
  "datasets": [
    {
      "id": "local-netclr-drift",
      "dataset_id": "netclr-drift",
      "role": "main_binary_baseline",
      "label_type": "netclr_condition_pair",
      "format": "npz",
      "path": "datasets/raw/tor/netclr",
      "split": "local_random_train_val_test",
      "notes": "Local path is not committed. Labels are condition-pair risk evidence, not malware labels."
    }
  ]
}
```

## Report Boundary

Use these sentences in the report and defense:

- Tor is anonymous encrypted communication, not an attack fact.
- Tor users are not malicious by default.
- The current competition baseline is NetCLR condition-pair risk-evidence binary classification, not Tor malicious-user detection.
- MineShark outputs traffic-side risk evidence and requires analyst review.
- LLM/RAG output is an explanation layer over model and log evidence, not a replacement for the detector.
