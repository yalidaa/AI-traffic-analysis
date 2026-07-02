# MineShark Console 真实部署指南

本文面向第一版真实部署：Linux/Wazuh VM、仅内网访问、端到端可用。Console 保持旁路研判模式：不替换 `mineshark-ai.timer`，不自动封禁，不写回 Wazuh，只读取 MineShark AI 告警、Wazuh、Zeek、Suricata 和 RAG 证据后生成中文研判报告。

## 1. 部署边界

- 部署目标：运行 Wazuh、Zeek、Suricata 或能读取这些日志的 Linux VM。
- 访问范围：实验室或内网访问 `http://<vm-ip>:8008`。
- 必须存在：`/var/log/ai_alerts.json`，由现有 `mineshark-ai.timer` 或等价实时检测链路持续写入。
- 不在第一版处理：公网 HTTPS、登录认证、自动封禁、Wazuh 写回、替换实时检测服务。

## 2. 准备项目和依赖

把项目放到 Linux VM，例如：

```bash
sudo mkdir -p /opt/mineshark-console
sudo chown -R "$USER":"$USER" /opt/mineshark-console
cd /opt/mineshark-console
```

复制或拉取本仓库后，安装 Python web 依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[web]"
```

构建前端静态文件：

```bash
cd web/frontend
npm install
npm run build
cd ../..
```

构建完成后，FastAPI 会在同一个 `8008` 端口托管 `web/frontend/dist`，生产访问不需要再单独运行 Vite。

## 3. 配置生产 .env

复制模板：

```bash
cp .env.production.example .env
chmod 600 .env
```

至少填写：

```text
DEEPSEEK_API_KEY=...
DASHSCOPE_API_KEY=...
WAZUH_PASSWORD=...
WAZUH_INDEXER_PASSWORD=...
```

确认这些路径对 Console 进程可读：

```text
MINESHARK_AI_ALERTS_PATH=/var/log/ai_alerts.json
WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json
ZEEK_LOG_DIR=/opt/zeek/spool/zeek
SURICATA_EVE_PATH=/var/log/suricata/eve.json
MINESHARK_RAG_INDEX_DIR=outputs/rag
```

如果 Wazuh 使用自签名证书，实验环境可以临时保留 `WAZUH_VERIFY_SSL=false`。正式环境应配置可信 CA 后改为 `true`。

## 4. 构建 RAG 索引

RAG 构建会调用 DashScope embedding：

```bash
source .venv/bin/activate
python scripts/rag/build_index.py --env-file .env
```

成功后应看到：

```text
outputs/rag/knowledge.faiss
outputs/rag/metadata.json
```

## 5. 部署前检查

运行只读检查脚本：

```bash
source .venv/bin/activate
python scripts/deploy/check_production_readiness.py --env-file .env --host 0.0.0.0 --port 8008
```

检查内容包括：

- DeepSeek 和 DashScope key 是否设置。
- AI 告警、Wazuh alerts、Zeek、Suricata 路径是否存在且类型正确。
- RAG 索引文件是否存在。
- `web/frontend/dist/index.html` 是否已构建。
- `8008` 端口是否可绑定。
- Wazuh API 可选连通性检查。

如需连 Wazuh API 也一起检查：

```bash
python scripts/deploy/check_production_readiness.py --env-file .env --check-wazuh-api
```

## 6. 前台启动验证

先以前台方式启动，便于看日志：

```bash
source .venv/bin/activate
MINESHARK_ENV_FILE=.env mineshark-console --host 0.0.0.0 --port 8008
```

浏览器访问：

```text
http://<vm-ip>:8008
```

验证顺序：

1. 打开首页，确认能看到真实 MineShark AI 告警。
2. 点击 `Preflight`，确认任务成功或只剩非阻断 warning。
3. 点击 `生成报告`，确认任务成功。
4. 进入报告中心，确认 Markdown 报告已渲染。
5. 检查接口：`curl http://127.0.0.1:8008/api/health`。

## 7. systemd 服务化

复制模板：

```bash
sudo cp deploy/systemd/mineshark-console.service /etc/systemd/system/mineshark-console.service
sudo systemctl daemon-reload
```

按实际路径编辑：

```bash
sudo systemctl edit --full mineshark-console.service
```

重点确认：

- `WorkingDirectory=/opt/mineshark-console`
- `Environment=MINESHARK_ENV_FILE=/opt/mineshark-console/.env`
- `ExecStart=/opt/mineshark-console/.venv/bin/mineshark-console --host 0.0.0.0 --port 8008`
- `User=` 使用能读取日志和 RAG 文件的账号。

启动并查看状态：

```bash
sudo systemctl enable --now mineshark-console
systemctl status mineshark-console
journalctl -u mineshark-console -n 100 --no-pager
```

## 8. 辅助脚本

`scripts/deploy/production_console.sh` 提供几个显式子命令：

```bash
bash scripts/deploy/production_console.sh install
bash scripts/deploy/production_console.sh build-frontend
bash scripts/deploy/production_console.sh build-rag
bash scripts/deploy/production_console.sh check
bash scripts/deploy/production_console.sh serve
bash scripts/deploy/production_console.sh systemd-hint
```

脚本不会删除文件，也不会自动替换 `mineshark-ai.timer` 或 Wazuh 服务。第一次真实部署建议逐条执行，看到每一步输出后再进入下一步。

## 9. 常见问题

- 首页告警为 0：检查 `/var/log/ai_alerts.json` 是否存在、是否有 JSON/JSONL 记录、Console 用户是否有读权限。
- 生成报告降级为证据报告：检查 `DEEPSEEK_API_KEY` 是否在 `.env` 中设置，并确认服务启动时使用了正确的 `MINESHARK_ENV_FILE`。
- RAG 未命中：先确认 `outputs/rag/knowledge.faiss` 和 `outputs/rag/metadata.json` 存在，再检查 `DASHSCOPE_API_KEY`。
- Wazuh API warning：确认 `WAZUH_BASE_URL`、`WAZUH_INDEXER_URL`、账号密码和 TLS 设置。
- 前端 404 或旧页面：重新执行 `npm run build`，确认 `web/frontend/dist/index.html` 存在。
