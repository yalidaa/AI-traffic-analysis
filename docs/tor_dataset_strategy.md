# Tor Dataset Strategy

This project now treats Tor encrypted traffic as the primary research direction. The competition wording should be:

**MineShark: Tor encrypted anonymous-traffic risk analysis and LLM-assisted triage.**

The system must not state that Tor traffic is malicious by itself. The defensible claim is narrower: MineShark analyzes Tor encrypted traffic metadata, website-fingerprinting behavior, multi-tab patterns, defended traces, and drift-sensitive risk evidence without decrypting content.

## Dataset Policy

Primary datasets should be selected from recent Tor / website-fingerprinting work in the four major security venues:

| Priority | Dataset family | Conference anchor | Role |
| --- | --- | --- | --- |
| P0 | AWF / Rimmer-style Tor WF traces | USENIX Security 2023 and ACM CCS 2023 references | Single-tab main benchmark |
| P0 | ARES / Multitab-WF-Datasets | IEEE S&P 2023 | Multi-tab benchmark |
| P0 | NetCLR drift-style traces | ACM CCS 2023 | Temporal drift benchmark |
| P1 | Walkie-Talkie defended traces | USENIX Security 2023 references | Defense robustness |
| P1 | WSC subpage-set traces or collection method | USENIX Security 2024 | Subpage generalization |
| P1 | Tor circumvention-detection methodology | NDSS 2024 | False-positive boundary and realism check |
| P2 | GTT23 genuine Tor traces | External Tor measurement dataset | Realism check only |

Tracked configuration lives in `configs/datasets/tor_research_registry.json`. Local data files should stay under the project root in `datasets/raw/tor`, remain outside Git tracking, and be referenced by a local manifest.

## Commands

Create the local data roots used by the first-stage plan:

```powershell
New-Item -ItemType Directory -Force datasets/raw/tor
New-Item -ItemType Directory -Force datasets/raw/tor/awf
New-Item -ItemType Directory -Force datasets/raw/tor/ares
New-Item -ItemType Directory -Force datasets/raw/tor/netclr
New-Item -ItemType Directory -Force datasets/raw/tor/walkie_talkie
```

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

Convert Tor WF JSONL/CSV/trace/NPY/NPZ records to MineShark PPI CSV:

```bash
python scripts/data/prepare_tor_ppi.py \
  --input datasets/raw/tor/awf/normal \
  --output datasets/experiments/ppi/tor/normal/awf_normal.csv \
  --default-app normal_tor \
  --max-len 128

python scripts/data/prepare_tor_ppi.py \
  --input datasets/raw/tor/awf/risk \
  --output datasets/experiments/ppi/tor/risk/awf_risk.csv \
  --default-app tor_risk_evidence \
  --max-len 128
```

The converter expects direction and timing fields such as `directions`, `dirs`, `timestamps`, `times`, or `iats`. Direction-only Tor cell traces use `--default-size 514` as an explicit approximation for PPI compatibility.

Inspect converted PPI quality before training:

```bash
python scripts/data/check_tor_dataset_quality.py \
  --input datasets/experiments/ppi/tor \
  --output-json outputs/tor_eval/quality.json \
  --output-md outputs/tor_eval/quality.md
```

Train the first-stage Tor binary checkpoint with the preset:

```bash
python scripts/train/train_model.py \
  --experiment tor_binary
```

Use an existing MineShark checkpoint only as initialization or compatibility evidence:

```bash
python scripts/train/train_model.py \
  --experiment tor_binary \
  --init-checkpoint checkpoints/deep_mineshark_best.pt \
  --init-mode encoder
```

Evaluate a trained Tor checkpoint:

```bash
python scripts/eval/run_tor_binary_eval.py \
  --checkpoint checkpoints/tor_binary_mineshark.pt \
  --normal-dir datasets/experiments/ppi/tor/normal \
  --risk-dir datasets/experiments/ppi/tor/risk \
  --output-dir outputs/tor_eval
```

## Local Manifest Shape

```json
{
  "datasets": [
    {
      "id": "local-awf-main",
      "dataset_id": "awf-rimmer",
      "role": "main_train_eval",
      "label_type": "monitored_unmonitored",
      "format": "jsonl",
      "path": "datasets/raw/tor/awf",
      "split": "train_val_test",
      "notes": "Local path is not committed."
    }
  ]
}
```

## First-Stage Label Semantics

The current training pipeline remains binary:

| Internal label | Report label | Meaning |
| --- | --- | --- |
| `0` | `normal_tor` | Normal Tor encrypted traffic or unmonitored Tor traces. |
| `1` | `tor_risk_evidence` | Tor traffic risk evidence, such as monitored fingerprinting target, multi-tab risk fixture, drift stress case, or defended trace evaluation target. |

Do not call label `1` "Tor malware". The model output is an operating point for traffic-side risk review.

## Report Boundary

Use these sentences in the report and defense:

- Tor is anonymous encrypted communication, not an attack fact.
- MineShark detects traffic-side risk evidence such as fingerprintable behavior, multi-tab correlation, defended-trace robustness gaps, and temporal drift.
- LLM/RAG output is an explanation layer over model and log evidence, not a replacement for the detector.
