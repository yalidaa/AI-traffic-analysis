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

## 能力边界

- 支持读取 MineShark AI 告警、Wazuh、Zeek、Suricata 和 RAG 证据；未接入的数据源会明确显示为空或未连接。
- 支持网页触发 `preflight`、`evidence-only` 和 `agent-report` 三类任务。
- 不从网页重建 RAG，不从网页开启 `rerun-model`。
- Agent 报告会继续更新 `outputs/reports/agent_audit_report.json` 和 `.md`，并在 SQLite 中保存历史快照。
- SQLite 默认路径为 `outputs/console/mineshark_console.sqlite3`。
