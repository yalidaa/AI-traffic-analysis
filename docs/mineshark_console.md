# MineShark Console

MineShark Console 是 `demo_jianli` 分支的深色 SOC 演示控制台。它用 FastAPI 暴露只读 API 和 Agent 任务入口，用 React/Vite 构建前端静态文件，并由 FastAPI 在同一端口托管。

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

在 Wazuh VM 的项目目录内运行：

```bash
mineshark-console --host 0.0.0.0 --port 8008
```

浏览器访问：

```text
http://<vm-ip>:8008
```

## 能力边界

- 支持读取 MineShark AI 告警、Wazuh、Zeek、Suricata 和 RAG 证据。
- 支持网页触发 `preflight`、`evidence-only` 和 `agent-report` 三类任务。
- 不从网页重建 RAG，不从网页开启 `rerun-model`。
- Agent 报告会继续更新 `outputs/reports/agent_audit_report.json` 和 `.md`，并在 SQLite 中保存历史快照。
- SQLite 默认路径为 `outputs/console/mineshark_console.sqlite3`。
