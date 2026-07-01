# MineShark 第七题参赛提交说明

## Tor 主线更新

当前参赛研究方向调整为 Tor 加密匿名通信流量。作品名称建议更新为：

**MineShark：面向 Tor 加密匿名通信的异常行为检测与大模型辅助研判系统。**

数据集主线不再以 USTC、UNSW 或 CIC-Darknet2020 作为核心指标来源，而是优先参考近三年四大安全顶会中的 Tor / Website Fingerprinting 论文和数据集：

- P0：AWF / Rimmer-style Tor website-fingerprinting traces，用于单标签 Tor 网站指纹主评测。
- P0：ARES / Multitab-WF-Datasets，用于多标签页 Tor 流量评测。
- P0：NetCLR drift-style traces，用于时间漂移和网络条件变化评测。
- P1：Walkie-Talkie defended traces，用于防御后 Tor 流量鲁棒性评测。
- P1：USENIX Security 2024 WSC 子页面集合方法，用于后续自采 Tor 子页面流量。

本仓库已新增 `docs/tor_dataset_strategy.md`、`configs/datasets/tor_research_registry.json`、`scripts/data/prepare_tor_ppi.py` 和 `scripts/data/render_tor_dataset_inventory.py`。正式报告中必须明确边界：Tor 是匿名加密通信协议，不天然等于恶意行为；MineShark 检测的是 Tor 加密流量中的风险模式、指纹化行为、多标签页相关性、漂移失配和可疑异常证据。

## 命题定位

参赛方向：第七题“面向加密通信协议的恶意行为检测技术”。

作品名称建议使用：MineShark：面向加密通信协议的恶意行为检测与大模型辅助研判系统。

本项目的主线是：在不解密 TLS/SSH 等加密会话明文的前提下，基于连接元数据、包长序列、方向序列、包间隔、端口和多源安全日志识别恶意行为风险线索。LLM/RAG/Agent 只作为辅助研判、报告生成和可解释审计能力，不把作品包装成 API 安全审计或源代码漏洞审计。

## 赛题成果对齐

| 赛题要求 | MineShark 对应能力 | 主要证据 |
| --- | --- | --- |
| 加密通信流量分析工具 | 读取 MineShark/Zeek/Wazuh/Suricata 日志，聚合连接元数据和告警上下文 | `src/mineshark/sensors/`、`src/mineshark/agent/toolbox.py` |
| 异常行为检测规则或模型 | Transformer 风险分、阈值校准、竞赛场景评估指标 | `src/mineshark/training/train.py`、`scripts/eval/run_competition_eval.py` |
| 正常流量与攻击流量对比 | 覆盖正常 HTTPS/SSH、C2 Beacon、加密隧道、SSH 暴力破解后行为 | `tests/fixtures/competition_scenarios/scenarios.jsonl` |
| 可解释研判 | Wazuh、Zeek、Suricata、RAG playbook 与 `tool_trace` 形成证据链 | `scripts/agent/run_agent_audit.py`、`scripts/agent/run_offline_fixture_demo.py` |

## 评测复现

运行竞赛评测：

```bash
python scripts/eval/run_competition_eval.py \
  --scenario-dir tests/fixtures/competition_scenarios \
  --output-dir outputs/competition \
  --threshold 0.70
```

输出文件：

```text
outputs/competition/metrics.json
outputs/competition/comparison.md
outputs/competition/table_data.csv
```

默认 fixture 包含 10 条脱敏样本：5 条正常样本、5 条攻击样本。默认阈值 0.70 下包含一个误报样例和一个漏报样例，用于在作品报告中解释“模型概率是风险线索，不等于攻击事实”。

## 演示路径

### 离线 fallback 演示

离线演示不依赖 DeepSeek、DashScope、Wazuh API 或 FAISS 索引，适合现场网络不可用时使用：

```bash
python scripts/agent/run_offline_fixture_demo.py \
  --fixture-dir tests/fixtures/demo_event \
  --output-dir outputs/offline_demo
```

输出文件：

```text
outputs/offline_demo/offline_agent_report.json
outputs/offline_demo/offline_agent_report.md
```

该报告保留与正式 Agent 相同的核心结构：`preflight`、`evidence_bundle`、`quality_checks`、`tool_trace` 和 `markdown_report`。RAG 在没有 FAISS 索引时会降级读取本地 `knowledge.jsonl`，并在结果中标记 `jsonl_fallback`。

### Live Wazuh/WSL 演示

Live 演示用于展示真实安全平台链路：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\agent\run_wsl_cli_agent_demo.ps1
```

验收链路：

```text
MineShark AI 告警 -> /var/log/ai_alerts.json
  -> Wazuh rule 100500
  -> Agent 查询 Wazuh/Zeek/Suricata/RAG
  -> outputs/reports/agent_audit_report.json
  -> outputs/reports/agent_audit_report.md
  -> MineShark Console 展示
```

Live 演示前必须确认 Wazuh 发行版、Indexer、Manager、Dashboard、Filebeat、Suricata、SSH、项目虚拟环境和 `.env` 均可用。

## 作品报告材料

报告应使用附件 2 模板结构：

1. 摘要
2. 第一章 作品概述
3. 第二章 作品设计与实现
4. 第三章 作品测试与分析
5. 第四章 创新性说明
6. 第五章 总结
7. 参考文献

报告必须匿名，不出现学校、院系、指导教师、队员姓名、手机号、邮箱、API Key、服务器公网地址等身份或敏感信息。建议保留如下图表：

- 系统架构图：MineShark AI、Wazuh、Zeek、Suricata、RAG、Agent、Console。
- 检测流程图：元数据提取、模型判定、阈值校准、多源证据关联。
- 实验场景表：正常 HTTPS/SSH、C2 Beacon、加密隧道、SSH 暴力破解后行为。
- 指标表：Accuracy、Precision、Recall、F1、FPR、混淆矩阵。
- 报告样例截图：Markdown 报告和 JSON `tool_trace`。

可用以下命令生成匿名版 DOCX 初稿：

```bash
python scripts/docs/build_competition_report.py \
  --metrics-json outputs/competition/metrics.json \
  --output "E:/哈工大比赛文件/哈工大比赛文件/MineShark_第七题作品报告_匿名版.docx"
```

生成后仍需要团队按报名系统要求补充真实联系人、签字、盖章等非匿名表格材料；这些信息不要写入代码仓库。

## 提交前检查清单

- `python -m unittest discover -v`
- `python scripts/eval/run_competition_eval.py --scenario-dir tests/fixtures/competition_scenarios --output-dir outputs/competition --threshold 0.70`
- `python scripts/agent/run_offline_fixture_demo.py --fixture-dir tests/fixtures/demo_event --output-dir outputs/offline_demo`
- `uv run ruff check src tests`
- `uv run ruff format --check src tests`
- `uv run pytest`
- `cd web/frontend && npm run build`
- 人工检查 DOCX：无模板说明文字、无身份信息、无乱码、无表格溢出。

## 边界表述

建议在答辩中主动说明：

- MineShark 输出风险线索和辅助研判报告，不输出最终攻击定性。
- 系统不自动封禁 IP、不隔离主机、不写回 Wazuh 状态、不修改防火墙。
- 模型误报受业务流量、运维自动化、监控探针和数据分布影响，需要人工复核。
- LLM 负责组织证据和生成报告，不替代检测模型，也不直接读取全部日志做黑盒判断。
