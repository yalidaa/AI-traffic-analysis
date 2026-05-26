# MineShark 报告生成模块

报告模块负责加载 MineShark Transformer checkpoint，对 MineShark/Zeek 风格日志连接进行推理，并输出结构化 JSON 与中文 Markdown 审计报告。

## 位置

```text
src/mineshark/reporting/agent_audit.py
scripts/report/generate_audit_report.py
configs/reporting/security_playbook.jsonl
outputs/reports/
```

## 无大模型兜底测试

从项目根目录运行：

```powershell
python .\scripts\report\generate_audit_report.py `
  --checkpoint checkpoints/main_in_domain.pt `
  --log-file datasets/raw/logs_malware/Zeus.pcap.log `
  --max-events 5 `
  --no-llm
```

## DeepSeek API 模式

```powershell
$env:DEEPSEEK_API_KEY="your_key"
$env:DEEPSEEK_BASE_URL="https://api.deepseek.com"
$env:DEEPSEEK_MODEL="deepseek-chat"

python .\scripts\report\generate_audit_report.py `
  --checkpoint checkpoints/main_in_domain.pt `
  --log-file datasets/raw/logs_malware/Zeus.pcap.log `
  --max-events 5
```

如果 `DEEPSEEK_API_KEY` 缺失或 API 调用失败，脚本会回退到本地规则报告，并在 JSON 中记录错误。

## 输出

默认输出：

```text
outputs/reports/audit_report.json
outputs/reports/audit_report.md
```

可通过参数改写：

```powershell
python .\scripts\report\generate_audit_report.py `
  --checkpoint checkpoints/main_in_domain.pt `
  --log-file datasets/raw/mta/logs_new_malware/2026-01-31-traffic-analysis-exercise.pcap.log `
  --threshold 0.9 `
  --max-events 5 `
  --output-json outputs/reports/mta_audit.json `
  --output-md outputs/reports/mta_audit.md
```

## 简历边界

推荐表述：

```text
基于 DeepSeek API 构建安全分析报告生成器，将 Transformer 模型检测结果、Zeek/MineShark 流量上下文与本地安全知识库检索结果融合，自动生成包含风险等级、证据摘要、可疑原因与排查建议的中文安全审计报告。
```

边界要清楚：这是轻量级安全分析/报告生成器，不是完整自动化 SOC 处置平台。
