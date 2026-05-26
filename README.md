# MineShark Traffic Analysis

MineShark is a Python/PyTorch prototype for encrypted traffic analysis. It trains a Transformer-based binary classifier for `benign` vs `malware` traffic using packet-level metadata such as packet sizes, directions, and inter-arrival times. It also includes a lightweight security report generator that turns model predictions and traffic context into JSON/Markdown audit reports.

The project is organized as a conventional Python package under `src/`, with command wrappers in `scripts/` and local runtime artifacts kept out of Git.

## Project Layout

```text
.
├── configs/                 # Environment, reporting, and future experiment configs
├── docs/                    # Project notes, dependency docs, reporting docs
├── src/mineshark/           # Main Python package
│   ├── data/                # Dataset loading and data preparation utilities
│   ├── models/              # Model definitions
│   ├── training/            # Training loop and losses
│   └── reporting/           # Audit report generation
├── scripts/                 # Thin CLI wrappers for common tasks
│   ├── data/
│   ├── report/
│   └── train/
├── datasets/                # Local datasets and converted features, ignored by Git
├── checkpoints/             # Local model weights, ignored by Git
└── outputs/                 # Generated reports and experiment outputs, ignored by Git
```

## Core Data Roles

Local data is expected under `datasets/`:

```text
datasets/raw/logs_benign/
datasets/raw/logs_malware/
datasets/raw/mta/
datasets/processed/cesnet_ppi/
datasets/experiments/
```

These files are intentionally ignored by Git because they contain datasets, packet captures, converted CSVs, and large generated artifacts.

## Install

For the current Windows training machine, the Conda environment snapshot is:

```text
configs/env/traffic_env.yaml
```

To recreate it:

```powershell
conda env create -f configs/env/traffic_env.yaml
conda activate traffic_env
```

For package-style usage during development:

```powershell
pip install -e .
```

Training dependency details are documented in:

```text
docs/training_dependencies.md
```

## Training

Run from the project root:

```powershell
python .\scripts\train\train_model.py --experiment latest
```

Useful presets currently defined in `src/mineshark/training/train.py`:

```text
base
latest
cross_domain
ppi_local_latest
ppi_hybrid_latest
custom
```

Example local PPI experiment:

```powershell
python .\scripts\train\train_model.py --experiment ppi_local_latest
```

Model checkpoints are written to `checkpoints/` and are ignored by Git.

## Data Preparation

Convert MineShark/Zeek-style logs to PPI CSV:

```powershell
python .\scripts\data\prepare_ppi_from_logs.py `
  --log-dir datasets/raw/logs_benign `
  --out-dir datasets/experiments/ppi/local_benign `
  --app-label benign
```

Prepare the base/latest/hybrid experiment folders:

```powershell
python .\scripts\data\prepare_experiment_data.py
```

Safety note: this script no longer clears existing non-empty output directories automatically. If an experiment folder already contains files, move or manually clean it first.

Export CESNET benign PPI data:

```powershell
python .\scripts\data\prepare_cesnet_benign.py --data-root D:\path\to\cesnet-cache
```

## Reporting

Generate a rule-based audit report from a trained checkpoint:

```powershell
python .\scripts\report\generate_audit_report.py `
  --checkpoint checkpoints/main_in_domain.pt `
  --log-file datasets/raw/logs_malware/Zeus.pcap.log `
  --max-events 5 `
  --no-llm
```

Reports are written to:

```text
outputs/reports/
```

The local security knowledge base is:

```text
configs/reporting/security_playbook.jsonl
```

## LangGraph Agent + RAG + Wazuh

Build the FAISS RAG index with Qwen/DashScope embeddings:

```powershell
python .\scripts\rag\build_index.py --env-file .env
```

Run the LangGraph security triage Agent in VM sidecar mode:

```powershell
python .\scripts\agent\run_agent_audit.py `
  --env-file .env `
  --max-events 5
```

The Agent reads the VM's existing MineShark AI alerts from `/var/log/ai_alerts.json`, enriches them with Wazuh, Zeek, Suricata, and the local FAISS RAG index, then writes JSON/Markdown reports to:

```text
outputs/reports/
```

Detailed setup notes are in:

```text
docs/agent_rag_wazuh.md
```

## Git Policy

The repository tracks source code, scripts, configs, and docs. It ignores:

- datasets and packet captures
- generated PPI CSVs and logs
- model checkpoints
- report outputs
- Python caches and IDE files

This keeps the GitHub repository lightweight while preserving the local training workspace layout.
