# TrafficDetection_LLM

## Project Snapshot

This project trains a PyTorch-based traffic detection model for benign vs malware classification.
The current codebase supports two input formats:

- `log`: Zeek/MineShark-style `.pcap.log` files
- `ppi`: CSV/JSONL files containing packet-level `PPI` sequences

The main training entrypoint is:

- [train_ai.py](C:/Users/29065/Desktop/TrafficDetection_LLM/train_ai.py)

## Datasets Actually Used In This Project

### 1. USTC-TFC2016-derived Local Log Corpus

Role:
- Main in-domain training corpus
- Contains both benign and malware traffic

Local files:
- [logs_benign](C:/Users/29065/Desktop/TrafficDetection_LLM/logs_benign)
- [logs_malware](C:/Users/29065/Desktop/TrafficDetection_LLM/logs_malware)

Benign examples:
- `Gmail.pcap.log`
- `MySQL.pcap.log`
- `Outlook.pcap.log`
- `Weibo-2.pcap.log`

Malware examples:
- `Cridex.pcap.log`
- `Miuref.pcap.log`
- `Virut.pcap.log`
- `Zeus.pcap.log`

Format:
- Zeek/MineShark-style processed log files

Used by:
- `train_ai.py --data-format log`

Status:
- Confirmed used in multiple training runs

### 2. CESNET-TLS-Year22 (XS) PPI Benign Dataset

Role:
- Public benign corpus for PPI-based experiments

Local file:
- [data/cesnet_ppi/benign/cesnet_tls_year22_XS.csv](C:/Users/29065/Desktop/TrafficDetection_LLM/data/cesnet_ppi/benign/cesnet_tls_year22_XS.csv)

Source:
- Exported through `cesnet-datazoo`
- Produced by [prepare_cesnet_benign.py](C:/Users/29065/Desktop/TrafficDetection_LLM/prepare_cesnet_benign.py)

Format:
- CSV with `PPI` field

Status:
- Confirmed downloaded, exported, and used in smoke/ppi experiments

### 3. Local Malware PPI Dataset Converted From Existing Malware Logs

Role:
- Malware side of the PPI binary classification setup

Local files:
- [data/cesnet_ppi/malware](C:/Users/29065/Desktop/TrafficDetection_LLM/data/cesnet_ppi/malware)

Contained files:
- `Cridex.pcap_ppi.csv`
- `Miuref.pcap_ppi.csv`
- `Virut.pcap_ppi.csv`
- `Zeus.pcap_ppi.csv`

Source:
- Converted from local malware log files by [prepare_malware_ppi_from_logs.py](C:/Users/29065/Desktop/TrafficDetection_LLM/prepare_malware_ppi_from_logs.py)

Format:
- CSV with `PPI` field

Status:
- Confirmed used together with CESNET benign PPI data

### 4. MTA 2026 Incremental Malware Samples

Role:
- Incremental malware samples for expansion experiments

Local raw pcaps:
- [data/mta/raw](C:/Users/29065/Desktop/TrafficDetection_LLM/data/mta/raw)

Local parsed logs:
- [data/mta/logs_new_malware](C:/Users/29065/Desktop/TrafficDetection_LLM/data/mta/logs_new_malware)

Examples:
- `2026-01-31-traffic-analysis-exercise.pcap`
- `2026-02-28-traffic-analysis-exercise.pcap`
- matching `.pcap.log` files

Format:
- Raw PCAP plus converted log files

Status:
- Confirmed deployed locally
- Confirmed used in incremental malware experiments

## Datasets Confirmed To Exist Locally

### Raw / original-style data present locally

- [logs_benign](C:/Users/29065/Desktop/TrafficDetection_LLM/logs_benign)
- [logs_malware](C:/Users/29065/Desktop/TrafficDetection_LLM/logs_malware)
- [data/mta/raw](C:/Users/29065/Desktop/TrafficDetection_LLM/data/mta/raw)

### Converted training data present locally

- [data/cesnet_ppi/benign/cesnet_tls_year22_XS.csv](C:/Users/29065/Desktop/TrafficDetection_LLM/data/cesnet_ppi/benign/cesnet_tls_year22_XS.csv)
- [data/cesnet_ppi/malware](C:/Users/29065/Desktop/TrafficDetection_LLM/data/cesnet_ppi/malware)
- [data/mta/logs_new_malware](C:/Users/29065/Desktop/TrafficDetection_LLM/data/mta/logs_new_malware)

## Dataset Combinations Confirmed To Have Been Run

### A. Local benign logs + local malware logs

Format:
- `log`

Meaning:
- Main in-domain training setup

Associated checkpoints:
- [checkpoints/smoke_grouped.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/smoke_grouped.pt)
- [checkpoints/main_in_domain.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/main_in_domain.pt)
- [checkpoints/main_in_domain_v2.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/main_in_domain_v2.pt)

### B. Local benign logs + MTA incremental malware logs

Format:
- `log`

Meaning:
- Incremental malware extension experiment

Associated checkpoints:
- [checkpoints/mta_incremental_smoke.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/mta_incremental_smoke.pt)
- [checkpoints/main_with_mta.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/main_with_mta.pt)

### C. CESNET benign PPI + local malware PPI

Format:
- `ppi`

Meaning:
- Cross-source PPI binary classification experiment

Associated checkpoints:
- [checkpoints/cesnet_tls22_plus_malware_smoke.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/cesnet_tls22_plus_malware_smoke.pt)
- [checkpoints/cesnet_tls22_plus_malware.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/cesnet_tls22_plus_malware.pt)

Notes:
- `cesnet_tls22_plus_malware.pt` exists, but prior discussion suggests that run may have been affected by an earlier PPI parsing issue, so treat its result carefully.

### D. Early main log-model checkpoint

Associated checkpoint:
- [checkpoints/deep_mineshark_best.pt](C:/Users/29065/Desktop/TrafficDetection_LLM/checkpoints/deep_mineshark_best.pt)

Status:
- Highly likely tied to the earlier local log-based training path
- Exact run provenance is less certain than the checkpoints listed above

## Code-Supported But Not Yet Confirmed As Locally Materialized

### CESNET-QUIC22

Status:
- Supported by [prepare_cesnet_benign.py](C:/Users/29065/Desktop/TrafficDetection_LLM/prepare_cesnet_benign.py)
- Not currently confirmed as an exported local dataset file in this project directory

## Practical Summary

Currently confirmed as actually used:
- USTC-TFC2016-derived local log corpus
- CESNET-TLS-Year22 (XS) benign PPI export
- Local malware PPI converted from existing malware logs
- MTA 2026 incremental malware samples

Currently confirmed as locally deployed:
- `logs_benign/*.log`
- `logs_malware/*.log`
- `data/mta/raw/*.pcap`
- `data/mta/logs_new_malware/*.log`
- `data/cesnet_ppi/benign/cesnet_tls_year22_XS.csv`
- `data/cesnet_ppi/malware/*.csv`

Currently confirmed as already run:
- `logs_benign + logs_malware`
- `logs_benign + mta_logs_new_malware`
- `cesnet_ppi_benign + cesnet_ppi_malware`
