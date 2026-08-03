# MineShark-Lab 单机 WSL 部署

## 实际拓扑

```text
Windows WLAN + Npcap
  -> E:\Wireshark\dumpcap.exe
  -> E:\MineShark-runtime\spool\*.pcapng
  -> Ubuntu 22.04 WSL: MineShark-Lab
       -> MineShark Sensor
       -> Zeek 8.0.9 /var/lib/mineshark/zeek-logs/current
       -> Suricata 6.0.4 /var/log/suricata/eve.json
       -> Wazuh Manager / Indexer / Dashboard
       -> MineShark Console
```

这套环境验证的是“单机真实 WLAN 抓包到控制台”的闭环，不等同于交换机 SPAN/TAP 或企业 100 Mbps 压测。Windows 负责访问物理 WLAN 网卡，Sensor 不直接访问 Windows 网卡。

## 固定版本

MineShark-Lab 安装器当前固定以下组件版本：

| 组件 | 版本 |
| --- | --- |
| Wazuh Manager / Indexer / Dashboard | `4.14.7` |
| Zeek | `8.0.9` |
| Suricata | `6.0.4` |

版本以 `deploy/wsl-lab/install-guest.sh` 的校验和安装变量为准；目标机升级任一组件后，应重新执行部署验收并记录实际版本。

## 安装与修复

宿主机安装器：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\wsl-lab\install-host.ps1 -CaptureInterface 6 -SkipWiresharkInstall
```

目标发行版固定为 `MineShark-Lab`，目录为 `E:\WSL\MineShark-Lab`；如果发行版、目录或运行时目录已经存在，安装器会停止，不覆盖未知内容。

客体修复或升级：

```powershell
wsl -d MineShark-Lab -- bash /mnt/e/MineShark-product/deploy/wsl-lab/repair-guest.sh
```

脚本会校验 Ubuntu 22.04、Wazuh 4.14.7、Zeek 8.0.9、Suricata 6.0.4、模型 SHA-256、Python 3.10 的 `tomli` 兼容性、Wazuh XML、Nginx 和 Sensor 配置。

## 日常操作

- 控制台：`https://localhost:8012`；凭据在 WSL 的 `/var/lib/mineshark/console-credentials.txt`。
- 查看 Sensor：`wsl -d MineShark-Lab -- systemctl status mineshark-sensor`。
- 查看健康：`wsl -d MineShark-Lab -- cat /var/lib/mineshark/status.json`。
- 启停真实 WLAN 抓包：任务 `MineShark-WLANCapture`。停止抓包不会停止 Sensor、Wazuh 或控制台。
- 抓包目录：`E:\MineShark-runtime\spool`；snaplen 为 128 字节、5 秒轮转、最多 60 个文件。
- 旁证日志：Zeek `8.0.9` 写入 `/var/lib/mineshark/zeek-logs/current/`；Suricata `6.0.4` 写入 `/var/log/suricata/eve.json`。

## RAG 索引

客体安装器和修复脚本会在写入 `/etc/mineshark/console.env` 后自动执行：

```bash
runuser -u mineshark -- /opt/mineshark/venv/bin/mineshark-build-rag \
  --env-file /etc/mineshark/console.env
```

默认知识库和索引路径为：

```text
/var/lib/mineshark/security_playbook.jsonl
/var/lib/mineshark/outputs/rag/knowledge.faiss
/var/lib/mineshark/outputs/rag/metadata.json
```

配置 `DASHSCOPE_API_KEY` 时索引使用 DashScope `text-embedding-v4`；无密钥时使用
`local-hash` 离线 embedding，不应因为未配置 DashScope 就把 RAG 判定为未部署。部署后检查：

```bash
curl --fail --silent http://127.0.0.1:8000/api/health
curl --fail --silent 'http://127.0.0.1:8000/api/evidence?top_k=4'
```

健康响应中的 `sources.rag_index` 必须同时核对 `provider`、`count`、
`knowledge_faiss`、`metadata_json` 和 `ok`；第二个接口应返回 HTTP 200，且在有查询上下文时
检查 `evidence_bundle.rag_matches`。网页不会触发 RAG 重建。

## 服务状态边界

“安装成功”不等于“所有服务当前在线”。每次启动、修复或重启后都要现场检查：

```bash
systemctl is-active wazuh-indexer wazuh-manager filebeat wazuh-dashboard nginx mineshark-sensor mineshark-console mineshark-zeek
```

如果 Wazuh Indexer 反复处于 `activating` 或 `127.0.0.1:9200` 连接被拒绝，Console 的 Wazuh 数据源应保持未就绪并记录错误；不能用 RAG 已正常或软件包已安装替代 Indexer 验收。

## 证据边界

- 事件包含模型版本、哈希、阈值、概率和完整特征快照；不保存明文载荷。
- 当前 WSL 安装器会安装 Zeek/Suricata，但旁证日志只有在对应的实时采集或 PCAP 回放流程运行后才会出现；空日志仍必须显示为空，不得把空旁证写成已确认攻击。
- 普通 WLAN 流量被旧模型判为高风险，只能证明实时采集和推理链路工作，不能作为模型误报率合格或真实恶意流量确认。
- 要完成 SPAN/TAP、100 Mbps、丢包率 0.1% 和 p95 60 秒验收，仍需独立 Ubuntu 传感器和隔离网络流量发生器。
