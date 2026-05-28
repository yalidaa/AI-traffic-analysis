# MineShark Console / AI Traffic Analysis

`demo_jianli` 分支是 MineShark 面向 Wazuh 实验环境的最新演示分支。它把已有的加密流量 AI 告警、Wazuh 告警、Zeek/Suricata 日志和 RAG 安全知识库串起来，提供两种入口：

- **MineShark Console**：深色 SOC 风格 Web 控制台，用于展示风险态势、AI 告警、证据拓扑、报告中心和任务历史。
- **LangGraph Agent CLI**：旁路读取现有日志和告警，调用 DeepSeek 生成中文安全研判报告。

本分支不替换现有实时检测服务，不写回 Wazuh，不做自动封禁或自动处置。模型概率只作为风险线索，最终结论需要结合 Wazuh、Zeek、Suricata、RAG 和人工复核。

## Current Demo Flow

```text
MineShark live AI engine
  -> /var/log/ai_alerts.json
  -> Wazuh rule / alerts
  -> MineShark Agent evidence aggregation
  -> DeepSeek / rule fallback report
  -> MineShark Console
```

关键输出：

```text
outputs/reports/agent_audit_report.json
outputs/reports/agent_audit_report.md
outputs/console/mineshark_console.sqlite3
```

## Project Layout

```text
.
├── configs/                  # 环境、RAG 知识库和报告配置
├── docs/                     # 分支讲解、Console、Wazuh/Agent 文档
├── scripts/
│   ├── agent/                # Agent 演示与运行脚本
│   ├── data/                 # 数据准备脚本
│   ├── rag/                  # RAG 索引构建脚本
│   ├── report/               # 旧版离线报告入口
│   └── train/                # 模型训练入口
├── src/mineshark/
│   ├── agent/                # LangGraph Agent、证据聚合、质量检查
│   ├── integrations/         # Wazuh API / 本地告警回退
│   ├── rag/                  # FAISS RAG 存储和 DashScope embedding
│   ├── sensors/              # AI 告警、Zeek、Suricata 读取
│   ├── training/             # Transformer 训练
│   └── web/                  # FastAPI MineShark Console 后端
├── tests/                    # 单元测试和 demo fixture
├── web/frontend/             # React/Vite MineShark Console 前端
├── datasets/                 # 本地数据集，Git 忽略
├── checkpoints/              # 本地模型权重，Git 忽略
└── outputs/                  # 报告、RAG、Console 运行产物，Git 忽略
```

## Install

基础 Agent / RAG / Wazuh 旁路研判：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
```

MineShark Console 后端：

```bash
pip install -e ".[web]"
```

如果需要训练模型或显式使用 `--rerun-model`，再安装 ML 依赖：

```bash
pip install -e ".[ml]"
```

Windows 训练机可参考 Conda 环境快照：

```text
configs/env/traffic_env.yaml
```

## Configuration

复制 `.env.example` 为 `.env`，在 Wazuh VM 中填写真实凭据和路径：

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

## MineShark Console

Console 是本分支最新的前端入口。它由 FastAPI 提供只读 API 和任务接口，由 React/Vite 构建静态前端，并由 FastAPI 在同一端口托管。

前端构建只在开发/部署阶段需要 Node：

```bash
cd web/frontend
npm install
npm run build
cd ../..
```

启动控制台：

```bash
mineshark-console --host 0.0.0.0 --port 8008
```

访问：

```text
http://<vm-ip>:8008
```

Console 支持：

- 总览：AI 告警数、高危线索、数据源健康、最近任务和报告状态。
- AI 告警：按 IP、UID、Alert ID、阈值筛选 `/var/log/ai_alerts.json`。
- 证据拓扑：展示 MineShark AI、Wazuh、Zeek、Suricata、RAG 和报告之间的关系。
- 报告中心：查看 Agent 生成的 Markdown / JSON 报告快照。
- 任务历史：查看 `preflight`、`evidence-only`、`agent-report` 的执行状态。

网页允许触发的任务范围：

```text
preflight
evidence-only
agent-report
```

网页不触发 RAG 重建，也不启用 `rerun-model`。

更多说明见：

```text
docs/mineshark_console.md
```

## LangGraph Agent CLI

构建 RAG 索引：

```bash
python scripts/rag/build_index.py --env-file .env
```

运行一次完整 Agent 研判：

```bash
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --max-events 5
```

针对单条事件复盘：

```bash
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --alert-id demo-alert-001 \
  --uid Cdemo1 \
  --max-events 5
```

诊断模式：

```bash
python scripts/agent/run_agent_audit.py --env-file .env --preflight-only
python scripts/agent/run_agent_audit.py --env-file .env --evidence-only --uid Cdemo1
```

详细说明见：

```text
docs/agent_rag_wazuh.md
docs/demo_jianli_walkthrough.md
```

## Training And Data Preparation

训练入口仍然保留，但不是 `demo_jianli` 分支的主要演示路径。

训练模型：

```powershell
python .\scripts\train\train_model.py --experiment latest
```

常用实验预设：

```text
base
latest
cross_domain
ppi_local_latest
ppi_hybrid_latest
custom
```

转换 MineShark/Zeek 风格日志为 PPI CSV：

```powershell
python .\scripts\data\prepare_ppi_from_logs.py `
  --log-dir datasets/raw/logs_benign `
  --out-dir datasets/experiments/ppi/local_benign `
  --app-label benign
```

准备实验目录：

```powershell
python .\scripts\data\prepare_experiment_data.py
```

安全说明：数据准备脚本不会自动清空已有非空输出目录。如需清理实验目录，请人工确认后手动处理。

## Tests

运行全部单元测试：

```bash
python -m unittest discover -s tests
```

构建前端：

```bash
cd web/frontend
npm run build
```

## Git Policy

仓库跟踪源码、脚本、配置和文档；不跟踪以下本地运行产物：

- datasets 和 packet captures
- 生成的 PPI CSV、日志和实验输出
- 模型 checkpoint
- `outputs/` 下的报告、RAG 和 Console SQLite
- Python / Node 缓存和本地环境

这保证 GitHub 仓库保持轻量，同时保留本地 Wazuh VM 演示所需的目录结构。
