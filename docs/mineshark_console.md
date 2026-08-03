# MineShark Console

MineShark Console 是 `main` 系统开发主线的安全研判控制台。它用 FastAPI 暴露只读 API、案件接口和 Agent 任务入口，用 React/Vite 构建前端静态文件。开发模式由 FastAPI 直接托管；WSL 产品化部署由 Nginx 提供 HTTPS 入口。

## 安装

```bash
pip install -e ".[web]"
```

前端只在构建时需要 Node：

```bash
cd web/frontend
npm install
npm run build
```

## 启动

开发调试时，在项目目录内运行：

```bash
mineshark-console --host 127.0.0.1 --port 8008
```

浏览器访问：

```text
http://127.0.0.1:8008
```

WSL 产品化安装使用 systemd 在 `127.0.0.1:8000` 运行后端，并由 Nginx 反向代理到：

```text
https://localhost:8012
```

部署模式默认从 Wazuh Indexer 查询 `ai_alert`、`evidence_snapshot` 和 `sensor_heartbeat`，并按允许的 Sensor ID 过滤。`/var/log/ai_alerts.json` 仅是本地兼容模式的旧输入，不是当前真实 Sensor 的主要输出。

当前 `main` 的 Console 默认使用白色工作台界面；历史深色方案和截图只作为旧设计资料保留，不代表部署后的默认主题。

## 能力边界

- 支持读取 MineShark AI 告警、Wazuh、Zeek、Suricata 和 RAG 证据；未接入的数据源会明确显示为空或未连接。
- 总览页的 RAG 数据源状态来自 `/api/health` 或 `/api/overview` 的 `sources.rag_index`，展示索引路径、embedding `provider`、知识条数 `count`、`knowledge_faiss`、`metadata_json` 和 `ok`。
- 支持网页触发 `preflight`、`evidence-only` 和 `agent-report` 三类任务。
- 不从网页重建 RAG，不从网页开启 `rerun-model`。
- Agent 报告会继续更新 `outputs/reports/agent_audit_report.json` 和 `.md`，并在 SQLite 中保存历史快照。
- SQLite 默认路径为 `outputs/console/mineshark_console.sqlite3`。

部署安装器会把知识库放在 `/var/lib/mineshark/security_playbook.jsonl`，把 FAISS 索引和元数据放在 `/var/lib/mineshark/outputs/rag/`。有 `DASHSCOPE_API_KEY` 时 provider 为 DashScope；无密钥时 provider 为 `local-hash`，这仍是可用的离线 RAG 部署。页面显示“未覆盖”时，应同时检查两个索引文件和健康接口，不能只根据是否配置 DashScope 判断。

Wazuh Indexer 的 `activating`、连接拒绝或查询错误必须独立显示为 Wazuh 数据源异常；RAG 状态正常不能推导出 Wazuh 告警链路正常。
