# MineShark 产品化平台

MineShark 是面向安全分析人员的本地可部署加密流量智能研判验证平台。当前代码基线为 `productization`，目标是把真实 WLAN 流量、模型信号、Wazuh 告警、证据快照、研判案件和中文报告组织成可复核的工作闭环。

系统提供两个主要入口：

- **MineShark Console**：展示风险总览、AI 告警、证据拓扑、研判案件、报告和任务历史。
- **Agent / RAG 命令行**：读取已配置的数据源，聚合证据并生成带有事实边界说明的中文研判报告。

系统只做旁路读取、证据关联和人工研判，不自动封禁、不自动删除、不写回 Wazuh。模型概率只是风险线索，不能单独作为攻击事实。

## 当前产品化链路

```text
Windows WLAN
  -> dumpcap 环形抓包（PCAPNG）
  -> WSL Ubuntu 22.04: MineShark Sensor
  -> /var/log/mineshark/events.jsonl
  -> Wazuh Manager -> Filebeat -> Wazuh Indexer
  -> MineShark Console（Nginx HTTPS）
  -> Agent / RAG 证据聚合与中文报告
```

Sensor 负责五元组流聚合、前 20 个包的特征提取、Transformer 评分，以及生成 `ai_alert`、`evidence_snapshot` 和 `sensor_heartbeat` 事件。模型不读取 Zeek 或 Wazuh 日志；Zeek、Suricata 可以作为后续旁证接入。当前 WSL 首阶段未安装 Zeek/Suricata，旁证为空时页面会如实显示。

当前已验证的是单机真实 WLAN 抓包到控制台的闭环，不等同于交换机 SPAN/TAP、100 Mbps 持续压测或模型效果验收。旧模型在普通 WLAN 流量上可能产生大量高风险信号，这只能证明采集和推理链路工作，不能证明流量已经确认恶意。

关键输出位置：

```text
/var/log/mineshark/events.jsonl
outputs/reports/agent_audit_report.json
outputs/reports/agent_audit_report.md
outputs/console/mineshark_console.sqlite3
```

## 项目结构

```text
.
├── configs/                  # 传感器、环境、RAG 知识库和报告配置
├── deploy/                   # WSL、Sensor、Console、Wazuh 和 Nginx 部署文件
├── docs/                     # 产品化、部署、验收和历史资料
├── scripts/
│   ├── agent/                # Agent 研判和 WSL 运行脚本
│   ├── data/                 # 数据准备脚本
│   ├── deployment/           # 离线包、模型一致性和部署验收脚本
│   ├── rag/                  # RAG 索引构建脚本
│   └── train/                # 模型训练入口
├── src/mineshark/
│   ├── agent/                # Agent、证据聚合、预检查和质量检查
│   ├── integrations/         # Wazuh Server / Indexer 接入
│   ├── rag/                  # FAISS 存储和 DashScope 向量检索
│   ├── sensor/               # 抓包、流聚合、模型推理和事件输出
│   ├── sensors/              # AI 告警、Zeek、Suricata 数据读取
│   ├── training/             # Transformer 训练
│   └── web/                  # FastAPI Console 后端和案件存储
├── tests/                    # 单元测试、接口测试和脱敏夹具
├── web/frontend/             # React/Vite Console 前端
├── datasets/                 # 本地数据集，Git 忽略
├── checkpoints/              # 本地模型权重，Git 忽略
└── outputs/                  # 报告、RAG、Console 运行产物，Git 忽略
```

## 安装

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

## 配置

复制 `.env.example` 为 `.env`，在 Wazuh VM 中填写真实凭据和路径：

```bash
cp .env.example .env
```

关键变量示例：

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

真实部署模式还需要设置 `MINESHARK_AI_ALERT_SOURCE=wazuh`、允许的 `MINESHARK_ALLOWED_SENSOR_IDS`、Wazuh Indexer 只读账号和 `MINESHARK_FRONTEND_DIST`。真实密码、令牌、证书和生产日志只保留在目标环境，不提交到仓库。

## MineShark Console

Console 是当前产品化前端入口。它由 FastAPI 提供只读 API、案件接口和 Agent 任务接口，由 React/Vite 构建静态前端。

前端构建只在开发/部署阶段需要 Node：

```bash
cd web/frontend
npm install
npm run build
cd ../..
```

开发调试时可直接启动控制台：

```bash
mineshark-console --host 127.0.0.1 --port 8008
```

开发访问地址：

```text
http://127.0.0.1:8008
```

WSL 产品化部署由 systemd 在 `127.0.0.1:8000` 运行后端，再由 Nginx 提供本机 HTTPS 入口：

```text
https://localhost:8012
```

安装器会生成本机证书和受限访问凭据；不要直接把 Uvicorn 端口暴露到局域网。

Console 支持：

- 总览：AI 告警数、高危线索、数据源健康、最近任务和报告状态。
- AI 告警：按 IP、UID、Alert ID、阈值筛选已配置的数据源；部署模式默认查询 Wazuh Indexer。
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

## Agent 与 RAG 命令行

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
docs/project_record.md
```

## 训练与数据准备

训练入口仍然保留，但训练不是当前真实部署闭环的验收替代品。

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

## 测试与格式检查

同步开发、Web 和机器学习依赖：

```bash
uv sync --extra web --extra ml --dev
```

运行静态检查、格式检查和全部测试：

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest
```

GitHub Actions 会在每次 push 和 pull request 时自动运行相同检查。

构建前端：

```bash
cd web/frontend
npm run build
```

## 分支职责

仓库保留两个长期分支，各自承担不同职责：

- `main`：系统开发主线。用于集成 MineShark Sensor、Wazuh 接入、Console、案件管理、Agent、部署脚本和文档等可交付改动。合入前应完成测试、静态检查和前端构建。
- `training`：AI 流量分析算法训练线。用于数据准备、特征处理、模型训练、阈值校准、准确率和误报率评估，以及模型版本验证。训练产生的权重、数据集和实验输出保留在本地；经过验证的算法改动再整理合入 `main`。

`productization` 曾用于整理产品化闭环，当前内容已经进入 `main`，不再作为长期开发分支。

## Git 提交范围

仓库跟踪源码、脚本、配置和文档；不跟踪以下本地运行产物：

- datasets 和 packet captures
- 生成的 PPI CSV、日志和实验输出
- 模型 checkpoint
- `outputs/` 下的报告、RAG 和 Console SQLite
- Python / Node 缓存和本地环境

这保证 GitHub 仓库保持轻量，同时保留本地 Wazuh VM 演示所需的目录结构。
