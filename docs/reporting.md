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

## 良性对照与误报边界

报告脚本支持把低风险/良性样本写入同一份 JSON 与 Markdown 报告，便于展示模型不是只输出“恶意概率”，而是能给出高低风险边界和误报复核依据。

从主日志中选择最低风险样本作为对照：

```powershell
python .\scripts\report\generate_audit_report.py `
  --checkpoint checkpoints/main_in_domain.pt `
  --log-file datasets/raw/logs_malware/Zeus.pcap.log `
  --max-events 5 `
  --include-benign-sample `
  --max-benign-events 3 `
  --no-llm
```

使用单独的 benign 日志作为对照：

```powershell
python .\scripts\report\generate_audit_report.py `
  --checkpoint checkpoints/main_in_domain.pt `
  --log-file datasets/raw/logs_malware/Zeus.pcap.log `
  --benign-log-file datasets/raw/logs_benign/example.pcap.log `
  --benign-threshold 0.5 `
  --max-benign-events 3 `
  --no-llm
```

新增输出字段包括：

- `benign_controls`：被选入报告的低风险/良性对照连接。
- `benign_control_note`：说明是否命中低于阈值的样本，或是否只能退回到最低概率样本。
- `summary.risk_contrast_margin`：高风险候选与对照样本之间的恶意概率差距。
- `analyst_review_template`：人工复核时可填写的误报反馈字段。

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
基于 DeepSeek API 构建安全分析报告生成器，将 Transformer 模型检测结果、Zeek/MineShark 流量上下文、良性对照样本与本地安全知识库检索结果融合，自动生成包含风险等级、证据摘要、误报边界与排查建议的中文安全审计报告。
```

边界要清楚：这是轻量级安全分析/报告生成器，不是完整自动化 SOC 处置平台。
