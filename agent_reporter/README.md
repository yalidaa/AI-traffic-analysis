# MineShark Agent Reporter

This folder contains the lightweight security audit report generator for MineShark.
It is intentionally separated from the main training workspace so the original
model/data pipeline remains easy to distinguish.

## What It Does

`agent_audit.py` loads a MineShark Transformer checkpoint, scores Zeek/MineShark
log connections, retrieves local security knowledge with TF-IDF, and generates:

- `outputs/audit_report.json`: structured event evidence for later Wazuh/FastAPI integration
- `outputs/audit_report.md`: Chinese security operations report

The tool does not perform automatic blocking or remediation.

## No-LLM Smoke Test

Run from the repository root:

```powershell
python .\agent_reporter\agent_audit.py --checkpoint checkpoints/main_in_domain.pt --log-file logs_malware/Zeus.pcap.log --max-events 5 --no-llm
```

## DeepSeek API Mode

Configure an OpenAI-compatible DeepSeek endpoint:

```powershell
$env:DEEPSEEK_API_KEY="your_key"
$env:DEEPSEEK_BASE_URL="https://api.deepseek.com"
$env:DEEPSEEK_MODEL="deepseek-chat"
python .\agent_reporter\agent_audit.py --checkpoint checkpoints/main_in_domain.pt --log-file logs_malware/Zeus.pcap.log --max-events 5
```

If `DEEPSEEK_API_KEY` is missing or the API call fails, the script falls back to
the local rule-based Markdown report and records the LLM error in JSON.

## Useful Options

```powershell
python .\agent_reporter\agent_audit.py `
  --checkpoint checkpoints/main_in_domain.pt `
  --log-file data/mta/logs_new_malware/2026-01-31-traffic-analysis-exercise.pcap.log `
  --threshold 0.9 `
  --max-events 5 `
  --output-json agent_reporter/outputs/mta_audit.json `
  --output-md agent_reporter/outputs/mta_audit.md
```

## Notes For Resume/Interview

Recommended wording:

```text
基于 DeepSeek API 构建安全分析报告生成器，将 Transformer 模型检测结果、Zeek/MineShark 流量上下文与本地安全知识库检索结果融合，自动生成包含风险等级、证据摘要、可疑原因与排查建议的中文安全审计报告。
```

Keep the boundary clear: this is a lightweight security analysis/reporting
agent, not a fully automated SOC response platform.
