# MineShark LangGraph Agent / RAG / Wazuh 接入

本文说明 CLI 安全研判 Agent 如何读取已配置的 MineShark 实时 AI 告警，并把 Wazuh 告警、Zeek/Suricata 日志和安全知识库检索整合成中文研判报告。

## 当前定位

当前文档以 `productization` 分支为准，说明 MineShark 的 Agent、RAG 和 Wazuh 接入方式。真实产品化部署由 MineShark Sensor 生成版本化 `ai_alert`、`evidence_snapshot` 和 `sensor_heartbeat` 事件，再由 Wazuh Manager、Filebeat 和 Wazuh Indexer 保存；Console 和 Agent 从已配置的数据源读取这些事件。

Windows 主机主要用于代码开发、提交和同步；实际运行、RAG 索引构建、Wazuh/Zeek/Suricata 日志读取和 Agent 报告生成应在 Linux VM 中完成。

`MINESHARK_AI_ALERT_SOURCE=wazuh` 是产品化部署模式，要求配置允许的 Sensor ID 和 Wazuh Indexer 只读账号。`MINESHARK_AI_ALERT_SOURCE=local` 是兼容模式，读取 `MINESHARK_AI_ALERTS_PATH` 指定的本地文件；其中 `/var/log/ai_alerts.json` 属于旧实验链路，不应当被误认为当前 Sensor 的主要输出。

## 参考 VM 环境

```text
主机角色: Wazuh 与 MineShark-Lab 参考环境
系统: Ubuntu 22.04
控制台入口: https://localhost:8012
Wazuh Indexer: https://localhost:9200
传感器事件: /var/log/mineshark/events.jsonl
旧兼容输入: /var/log/ai_alerts.json
```

Agent 不修改传感器、Wazuh 或 Nginx 服务，只读取已配置的数据源并生成研判报告。旧的 `mineshark-ai.timer`、`/opt/mineshark_lab/ai_engine` 和 `100500` 规则属于历史演示环境，具体内容见 `docs/demo_jianli_walkthrough.md`。

## 配置

复制 `.env.example` 为 `.env`，在 Linux 虚拟机中填写真实凭据：

```bash
cp .env.example .env
```

关键变量：

```text
DEEPSEEK_API_KEY=...
DEEPSEEK_MODEL=deepseek-v4-pro
DEEPSEEK_THINKING=enabled
DEEPSEEK_REASONING_EFFORT=high
DEEPSEEK_MAX_TOKENS=8192
DASHSCOPE_API_KEY=...
WAZUH_BASE_URL=https://localhost:55000
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_VERIFY_SSL=false
ZEEK_LOG_DIR=/opt/zeek/spool/zeek
SURICATA_EVE_PATH=/var/log/suricata/eve.json
WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json
MINESHARK_AI_ALERT_SOURCE=wazuh
MINESHARK_ALLOWED_SENSOR_IDS=singlehost-wlan
MINESHARK_AI_ALERTS_PATH=/var/log/ai_alerts.json
```

`WAZUH_VERIFY_SSL=false` 只适合本地一体化/自签名证书环境。正式环境应配置 CA 并开启校验。

## 安装依赖

Agent 默认读取已配置的告警源，不在研判流程中重复运行模型，因此基础安装不会安装 PyTorch：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
```

只有需要训练模型或使用 `--rerun-model` 重新推理时，才安装机器学习依赖：

```bash
pip install -e ".[ml]"
```

## 构建 RAG 索引

```bash
python scripts/rag/build_index.py --env-file .env
```

默认知识库：

```text
configs/reporting/security_playbook.jsonl
```

默认索引输出：

```text
outputs/rag/
```

## 手动运行 Agent

示例：

```bash
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --max-events 5
```

默认模式会调用 `query_configured_ai_alerts` 读取当前配置的数据源。Wazuh 模式查询 Indexer；本地兼容模式读取 `MINESHARK_AI_ALERTS_PATH`。如果数据源为空，报告中会说明当前没有可用的实时 AI 告警。

如需调试某个 IP：

```bash
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --ip 192.0.2.10 \
  --threshold 0.5 \
  --max-events 5
```

如需精准复盘单条事件：

```bash
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --alert-id demo-alert-001 \
  --uid Cdemo1 \
  --max-events 5
```

如需只做运行前检查或只输出确定性证据聚合：

```bash
python scripts/agent/run_agent_audit.py --env-file .env --preflight-only
python scripts/agent/run_agent_audit.py --env-file .env --evidence-only --uid Cdemo1
```

只有需要重新跑离线模型推理时，才显式开启：

```bash
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --rerun-model \
  --checkpoint checkpoints/main_in_domain.pt \
  --log-file datasets/raw/logs_malware/Zeus.pcap.log
```

输出：

```text
outputs/reports/agent_audit_report.json
outputs/reports/agent_audit_report.md
```

JSON 报告会额外保留 `preflight`、`evidence_bundle`、`quality_checks`、`report_status` 和 `llm_runtime`，用于排查证据缺失、工具失败和大模型运行参数。

## 能力边界

- 只做读取、关联、研判和报告生成。
- 不写回 Wazuh，不做自动封禁、自动删除或自动处置。
- 不修改现有传感器、Wazuh 和 Nginx 服务。
- Agent 默认读取已配置的数据源，不默认重新运行模型。
- Wazuh Indexer API 查询失败时，会回退读取本地 `alerts.json`，并在 JSON 报告中记录降级原因。
- 模型概率只能作为风险线索，不能单独作为攻击事实。
