# MineShark：AI 加密流量分析与安全研判系统

MineShark 是一个面向网络安全场景的 AI 应用原型。项目在 Wazuh、Zeek、Suricata 等安全监测底座之上，补充加密流量 AI 检测、证据聚合、RAG 安全知识检索和中文研判报告生成能力，用于把原始安全告警转化为更适合人工复核的事件说明。

本项目适合作为参赛展示或团队协作项目：它不是单纯的模型训练脚本，也不是完全自动化的 SOC 平台，而是一个能够从日志、模型输出、规则告警和知识库证据中生成安全分析结论的轻量级 AI 安全分析系统。

## 项目目标

- 从 Zeek、Suricata、Wazuh 和 MineShark AI 告警中读取安全事件线索。
- 使用流量模型、规则证据和 RAG 知识库辅助判断风险。
- 调用 DeepSeek 或规则兜底逻辑生成中文安全研判报告。
- 提供 MineShark Console Web 控制台，展示告警、证据拓扑、报告和任务历史。
- 保留训练与数据准备能力，支持后续优化模型和对照实验。
- 明确人工复核边界，避免把模型输出包装成自动处置结论。

## 当前比赛口径

当前 Tor 方向主线是 **NetCLR 条件漂移风险证据二分类基线**，不是“检测 Tor 恶意用户”。二分类训练视图使用 `NCDrift_inf.csv` 与 `NCDrift_sup.csv`，报告标签为 `netclr_inferior_condition` 和 `netclr_superior_condition`；它们只表示 NetCLR 网络条件差异下的流量侧风险证据，不表示恶意/正常事实。

WFlib CW 单标签页链路已经接入并保留，但它天然是 95 类 closed-world website fingerprinting 任务。当前阶段只把它作为真实 Tor 单标签页数据处理、质量检查、训练评估的备用工程能力，不作为最终二分类主线。

参赛汇报中必须明确：Tor 是匿名加密通信协议，Tor 用户不等于恶意用户；MineShark 输出的是风险线索和辅助研判证据，最终结论需要结合 Wazuh、Zeek、Suricata、RAG 证据和人工复核。

## 核心能力

| 模块 | 作用 | 主要入口 |
| --- | --- | --- |
| AI 流量分析 | 读取流量特征，训练或复用 Transformer 模型，输出风险线索 | `scripts/train/`、`src/mineshark/training/` |
| Agent 研判 | 聚合 AI 告警、Wazuh、Zeek、Suricata 和 RAG 证据，生成中文报告 | `scripts/agent/run_agent_audit.py`、`mineshark-agent-audit` |
| RAG 知识库 | 基于本地安全知识条目构建 FAISS 索引，辅助解释告警 | `scripts/rag/build_index.py`、`mineshark-build-rag` |
| Web 控制台 | 提供只读 API、任务触发、报告中心和 SOC 风格前端 | `mineshark-console`、`web/frontend/` |
| 数据准备 | 将日志转换为训练和评估所需的 PPI CSV 等实验数据 | `scripts/data/`、`src/mineshark/data/` |
| 报告复核 | 输出风险解释、证据强度、对照差距和人工复核模板 | `src/mineshark/reporting/` |

## 系统流程

```text
Zeek / Suricata / Wazuh / MineShark AI
  -> 本地日志和告警文件
  -> 证据聚合与质量检查
  -> RAG 安全知识检索
  -> DeepSeek 或规则兜底生成中文研判
  -> Markdown / JSON 报告
  -> MineShark Console 展示
```

常见输出文件：

```text
outputs/reports/agent_audit_report.json
outputs/reports/agent_audit_report.md
outputs/console/mineshark_console.sqlite3
```

## 目录结构

```text
.
├── configs/                  # 环境配置、RAG 知识库和报告配置
├── docs/                     # 项目说明、分支说明、部署和演示文档
├── scripts/
│   ├── agent/                # Agent 演示与运行脚本
│   ├── data/                 # 数据准备脚本
│   ├── rag/                  # RAG 索引构建脚本
│   ├── report/               # 离线报告入口
│   └── train/                # 模型训练入口
├── src/mineshark/
│   ├── agent/                # LangGraph Agent、证据聚合和质量检查
│   ├── integrations/         # Wazuh API 和本地告警回退
│   ├── rag/                  # FAISS RAG 存储和 embedding
│   ├── sensors/              # AI 告警、Zeek、Suricata 读取
│   ├── training/             # Transformer 训练逻辑
│   └── web/                  # FastAPI MineShark Console 后端
├── tests/                    # 单元测试和 demo fixture
├── web/frontend/             # React/Vite 控制台前端
├── datasets/                 # 本地数据集目录，Git 默认忽略
├── checkpoints/              # 本地模型权重目录，Git 默认忽略
└── outputs/                  # 报告、RAG、Console 运行产物，Git 默认忽略
```

## 快速开始

建议使用 Python 3.10 或更高版本。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
```

如果需要运行 Web 控制台：

```bash
pip install -e ".[web]"
```

如果需要训练模型或重新运行模型推理：

```bash
pip install -e ".[ml]"
```

如果团队使用 `uv` 统一开发环境：

```bash
uv sync --extra web --extra ml --dev
```

## 环境配置

复制 `.env.example` 为 `.env`，再按实际环境填写密钥、Wazuh 地址和日志路径：

```bash
cp .env.example .env
```

常用配置项：

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

`.env` 只在本地使用，不要提交真实密钥或服务器凭据。

## 运行 MineShark Console

前端只在构建阶段需要 Node.js：

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

浏览器访问：

```text
http://<服务器或虚拟机IP>:8008
```

Console 支持查看总览、AI 告警、证据拓扑、报告中心和任务历史。网页端允许触发的任务范围为：

```text
preflight
evidence-only
agent-report
```

网页端不负责重建 RAG，不开启 `rerun-model`，也不执行自动封禁或自动处置。

## 运行 Agent 研判

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

更多说明：

```text
docs/agent_rag_wazuh.md
docs/demo_jianli_walkthrough.md
docs/mineshark_console.md
```

## 模型训练与数据准备

训练入口仍然保留，主要用于模型迭代和参赛前的实验补充。

训练模型：

```bash
python scripts/train/train_model.py --experiment latest
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

将 MineShark/Zeek 风格日志转换为 PPI CSV：

```bash
python scripts/data/prepare_ppi_from_logs.py \
  --log-dir datasets/raw/logs_benign \
  --out-dir datasets/experiments/ppi/local_benign \
  --app-label benign
```

Tor 加密流量数据集主线说明见：

```text
docs/tor_dataset_strategy.md
configs/datasets/tor_research_registry.json
```

当前推荐复现实验是 NetCLR 二分类基线：

```text
datasets/experiments/ppi/tor/netclr_drift_binary/normal/NCDrift_inf.csv
datasets/experiments/ppi/tor/netclr_drift_binary/risk/NCDrift_sup.csv
checkpoints/tor_netclr_drift_binary_gpu_v1.pt
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/
```

结果口径：低误报约束下 precision 较高，但 recall 很低；可以作为高置信风险证据基线，不能包装成成熟的 Tor 恶意检测系统。

将 Tor website-fingerprinting JSONL/CSV/trace 序列转换为 PPI CSV：

```bash
python scripts/data/prepare_tor_ppi.py \
  --input E:/datasets/tor/awf/train.jsonl \
  --output datasets/experiments/ppi/tor_awf_train.csv \
  --default-app tor \
  --max-len 128
```

渲染或校验本地 Tor 数据 manifest：

```bash
python scripts/data/render_tor_dataset_inventory.py \
  --local-manifest datasets/experiments/tor_manifest.local.json \
  --output outputs/tor_dataset_inventory.md
```

准备实验目录：

```bash
python scripts/data/prepare_experiment_data.py
```

数据准备脚本不会自动清空已有非空输出目录。如需清理实验目录，请人工确认后手动处理。

## 测试与格式检查

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest
```

GitHub Actions 会在 push 和 pull request 时运行 Python 检查。

## 命题赛评测与离线演示

第七题参赛材料优先参考：

```text
docs/competition_submission.md
```

运行脱敏竞赛场景评测：

```bash
python scripts/eval/run_competition_eval.py \
  --scenario-dir tests/fixtures/competition_scenarios \
  --output-dir outputs/competition \
  --threshold 0.70
```

运行不依赖外部大模型或 Wazuh API 的离线演示：

```bash
python scripts/agent/run_offline_fixture_demo.py \
  --fixture-dir tests/fixtures/demo_event \
  --output-dir outputs/offline_demo
```

评测输出 `metrics.json`、`comparison.md` 和 `table_data.csv`；离线演示输出同结构 JSON/Markdown 研判报告和 `tool_trace`。

## 分支协作建议

当前仓库主要分支含义如下：

| 分支 | 定位 |
| --- | --- |
| `main` | GitHub 默认分支，目前落后于演示分支 |
| `demo_jianli` | MineShark Console、Wazuh 旁路 Agent、RAG 和演示流程的稳定基线 |
| `training` | 在 `demo_jianli` 基础上继续补充训练、报告质量和人工复核能力 |

参赛协作建议：

- 如果团队重点展示完整 Web 控制台和 Wazuh/Agent 演示，优先基于 `demo_jianli`。
- 如果团队还要展示模型训练、良性对照、报告质量评估和人工复核模板，优先基于 `training`。
- 不建议直接以落后的 `main` 作为参赛开发基线，除非先把 `demo_jianli` 或 `training` 合回。
- 合并前先跑测试，避免把演示能力、训练能力和文档状态拆散。

## 安全边界

MineShark 输出的是风险线索和辅助研判，不是最终安全处置结论。

项目当前不做：

- 不替换现有 Wazuh、Zeek 或 Suricata 服务。
- 不写回 Wazuh 告警状态。
- 不自动封禁 IP、隔离主机或修改防火墙。
- 不把模型概率当作唯一判定依据。

建议在参赛展示中明确说明：最终结论需要结合 Wazuh、Zeek、Suricata、RAG 证据和人工复核。

## Git 跟踪策略

仓库跟踪源码、脚本、配置模板、测试和文档；不跟踪以下本地运行产物：

- 数据集和 packet captures。
- 生成的 PPI CSV、日志和实验输出。
- 模型 checkpoint。
- `outputs/` 下的报告、RAG 索引和 Console SQLite。
- Python / Node 缓存和本地虚拟环境。

这样可以保证 GitHub 仓库保持轻量，同时保留本地或服务器演示所需的目录结构。
