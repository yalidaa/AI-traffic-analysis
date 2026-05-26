# MineShark LangGraph Agent / RAG / Wazuh 接入

本阶段新增一个 CLI 安全研判 Agent，用于旁路读取虚拟机中已经运行的 MineShark 实时 AI 告警，并把 Wazuh 告警、Zeek/Suricata 日志和安全知识库检索整合成中文研判报告。

## 已有 VM 环境

```text
hostname: wazuh
OS: Ubuntu 24.04.3 LTS
IP: 192.168.30.152
Zeek: /opt/zeek/bin/zeek version 8.0.4
AI engine: /opt/mineshark_lab/ai_engine
Existing timer: mineshark-ai.timer, every 1 minute
Existing AI output: /var/log/ai_alerts.json
Existing Zeek conn path: /opt/zeek/spool/zeek/conn.log
```

当前 Agent 不替换、不停用、不修改 `mineshark-ai.timer`。它只读取已有输出并生成研判报告。

## 配置

复制 `.env.example` 为 `.env`，在 Linux 虚拟机中填写真实凭据：

```bash
cp .env.example .env
```

关键变量：

```text
DEEPSEEK_API_KEY=...
DASHSCOPE_API_KEY=...
WAZUH_BASE_URL=https://localhost:55000
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_VERIFY_SSL=false
ZEEK_LOG_DIR=/opt/zeek/spool/zeek
SURICATA_EVE_PATH=/var/log/suricata/eve.json
WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json
MINESHARK_AI_ALERTS_PATH=/var/log/ai_alerts.json
```

`WAZUH_VERIFY_SSL=false` 只适合本地一体化/自签名证书环境。正式环境应配置 CA 并开启校验。

## 安装依赖

旁路 Agent 默认只读取 `/var/log/ai_alerts.json`，不重新运行模型，因此默认安装不会安装 PyTorch：

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

默认模式会优先调用 `query_mineshark_ai_alerts` 读取 `/var/log/ai_alerts.json`。如果该文件为空，报告中会说明当前没有实时 AI 告警。

如需调试某个 IP：

```bash
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --ip 192.168.30.152 \
  --threshold 0.5 \
  --max-events 5
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

## 能力边界

- 只做读取、关联、研判和报告生成。
- 不写回 Wazuh，不做自动封禁、自动删除或自动处置。
- 不修改现有 `/etc/systemd/system/mineshark-ai.service` 和 `mineshark-ai.timer`。
- Agent 默认读取 `/var/log/ai_alerts.json`，不默认重新运行模型。
- Wazuh Indexer API 查询失败时，会回退读取本地 `alerts.json`，并在 JSON 报告中记录降级原因。
- 模型概率只能作为风险线索，不能单独作为攻击事实。
