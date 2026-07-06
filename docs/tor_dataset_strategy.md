# Tor Dataset Strategy

## Current Research Framing

MineShark-Tor is now framed as a thesis-oriented Tor website fingerprinting and encrypted traffic behavior recognition project.

The first milestone is **not** model innovation. It is a one-week dataset phase:

1. identify authoritative Tor WF datasets used by recent top-tier security/networking papers;
2. verify availability, scale, labels, and reproducibility;
3. decide the main dataset before implementing DTB-Fusion and full experiments.

This replaces the earlier competition-first framing where NetCLR was presented mainly as a condition-pair binary risk-evidence baseline.

## Selection Policy

The main paper dataset should satisfy these rules:

- Prefer USENIX Security, IEEE S&P, ACM CCS, NDSS, and PAM sources.
- Support Tor website fingerprinting or Tor encrypted traffic behavior recognition.
- Support closed-world evaluation and ideally one realistic extension: open-world, drift/cross-environment, multi-tab, defense robustness, or subpage/generalization.
- Have public artifacts, clear labels, and formats convertible to MineShark PPI/trace.
- Avoid choosing a dataset merely because it is already local.

## Candidate Priority

| Priority | Dataset family | Role |
| --- | --- | --- |
| P0 | NetCLR / NCDrift | Main candidate for realistic WF, cross-condition, and drift-aware evaluation. |
| P0 | WFlib CW/OW | Reproducible closed-world fallback and standardized artifact baseline. |
| P1 | ARES / Multitab-WF-Datasets | Second-stage multi-tab extension after the first paper pipeline is stable. |
| P1 | USENIX Security 2024 subpage-set WF | Methodology reference for data diversity and realistic browsing behavior. |
| P1 | PAM 2026 Tor WF dataset index | Dataset discovery and authority check. |
| P2 | AWF / DF / Wang14 / CUMUL | Classic baselines and related-work references, not latest-authority mainline. |

## Local Data Status

Tracked metadata lives in:

```text
configs/datasets/tor_research_registry.json
datasets/experiments/tor_manifest.local.json
```

Local data remains outside Git tracking.

Current local candidates:

| Dataset | Local status | Use |
| --- | --- | --- |
| NetCLR / NCDrift | Raw archives, extracted NPZ, and PPI CSV are present. | First P0 candidate. Re-check whether original data supports website-class, cross-condition, and trace-length experiments. |
| WFlib CW | Raw archive, extracted NPZ, and 95-class PPI CSV are present. | Closed-world reproduction and fallback main dataset. |
| AWF | Directory exists but contains no files. | Not ready. Do not claim it as a local dataset. |
| ARES / multi-tab | Not downloaded. | Keep as second-stage candidate. |

## Required Reports

Generate and keep local reports for the dataset phase:

```powershell
python scripts/data/render_tor_dataset_inventory.py `
  --local-manifest datasets/experiments/tor_manifest.local.json `
  --require-existing-paths `
  --output outputs/tor_dataset_inventory.md
```

Quality checks for converted PPI:

```powershell
python scripts/data/check_tor_dataset_quality.py `
  --input datasets/experiments/ppi/tor/wflib_cw `
  --output-json outputs/tor_data_runs/wflib_cw_quality/quality.json `
  --output-md outputs/tor_data_runs/wflib_cw_quality/quality.md
```

For NetCLR, check both the old binary view and the multiclass view:

```powershell
python scripts/data/check_tor_dataset_quality.py `
  --input datasets/experiments/ppi/tor/netclr_smoke `
  --output-json outputs/tor_data_runs/netclr_multiclass_quality/quality.json `
  --output-md outputs/tor_data_runs/netclr_multiclass_quality/quality.md
```

## Dataset Decision Gate

Proceed to DTB-Fusion only after these are true:

- `docs/tor_dataset_survey.md` records the candidate comparison.
- `docs/tor_dataset_decision.md` explains the selected main and auxiliary datasets.
- `outputs/tor_dataset_inventory.md` exists locally.
- PPI quality reports exist for the selected local datasets.
- The README states that the dataset choice went through a dedicated screening phase.

## Reporting Boundary

Use these sentences in thesis and defense materials:

- Tor is an anonymity communication system; Tor users are not malicious by default.
- This project studies passive encrypted-traffic behavior recognition and website fingerprinting.
- Dataset authority, reproducibility, and realistic assumptions are treated as first-class experiment requirements.
- NetCLR condition files must not be described as normal-vs-malicious labels.
- MineShark-Tor self-collected traces are optional system-demonstration data, not the first paper's required main dataset.
