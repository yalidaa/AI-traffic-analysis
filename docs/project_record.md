# MineShark 产品化项目记录与新会话交接

更新时间：2026-08-03

> 本文前半部分是当前唯一有效的交接说明。下方“历史归档”保留旧的产品化过程，不能作为当前部署状态、主题、数据源或验证结果的依据。

## 当前交接摘要（新会话从这里开始）

### 1. 正在做什么

当前目标不是再做演示页，而是完成 MineShark 的**单机真实 WLAN 流量检测闭环**：Windows 从真实 WLAN 抓 TCP 包，Ubuntu 22.04 WSL 中的 Sensor 将包转成模型特征并推理，Wazuh 存储告警，MineShark Console 从 Wazuh Indexer 查询并展示告警、证据和案件。

真实数据流：

```text
Windows WLAN
  -> <Wireshark安装目录>\dumpcap.exe
  -> <运行时目录>\spool\*.pcapng
  -> WSL Ubuntu 22.04: MineShark-Lab
       -> MineShark Sensor
       -> /var/log/mineshark/events.jsonl
       -> Wazuh Manager -> Filebeat -> Wazuh Indexer
       -> MineShark Console / Nginx -> https://localhost:8012
```

`dumpcap` 只负责抓包；Sensor 才负责五元组流聚合、前 20 包特征、Transformer 评分、`ai_alert`、`evidence_snapshot` 和心跳事件。模型不读取 Zeek/Wazuh 日志；Zeek 8.0.9 与 Suricata 6.0.4 作为旁证源安装并由 Sensor 只读查询。

MineShark-Lab 参考版本为 Wazuh `4.14.7`、Zeek `8.0.9` 和 Suricata `6.0.4`。RAG 索引部署在 `/var/lib/mineshark/outputs/rag/`，当前已生成 `knowledge.faiss` 和 `metadata.json`，provider 为 `local-hash`，知识条数为 10、维度为 384。无 `DASHSCOPE_API_KEY` 时使用该离线 provider；配置 key 才切换到 DashScope `text-embedding-v4`。

### 2. 环境和边界

- 工作区：`<项目根目录>`，分支 `main`。
- 本目录是 Git worktree；元数据位于主仓库的 worktree 管理目录。禁止修改、清理或切换主仓库工作区。
- 新 WSL：`MineShark-Lab`，Ubuntu 22.04，安装目录 `<WSL发行版目录>\MineShark-Lab`。
- 旧 WSL `Wazuh` 保持停止，不升级、不改配置、不参与本次运行。
- Windows 抓包程序：`<Wireshark安装目录>\dumpcap.exe`，WLAN 接口编号按目标主机配置。
- 抓包策略：`tcp`、snaplen `128`、5 秒轮转、60 文件环形覆盖，目录 `<运行时目录>\spool`。
- 控制台：`https://localhost:8012`。Nginx 只对 `127.0.0.1` / `::1` 免 Basic Auth；外部来源仍受限制。
- 请保留当前脏工作树，不要执行 `git reset --hard`、`git clean`、`git checkout -- <path>`、`Remove-Item -Recurse` 或任何批量删除。

### 3. 已完成且已验证

- 已创建独立 Ubuntu 22.04 WSL，安装 Wazuh 4.14.7 Manager、Indexer、Dashboard、Filebeat、Zeek 8.0.9、Suricata 6.0.4、MineShark Sensor、Console 和 Nginx。
- 已恢复并校验模型 `deep-mineshark-legacy-20260304`，SHA-256：`9c40a0145309fcc124583ed1d6c7c82b469e7e39948d9f6da57a2ed5e03cd9c1`。
- Python 3.10 / Ubuntu 22.04 兼容已修复：Sensor 在没有内置 `tomllib` 时回退使用 `tomli`。
- Windows dumpcap 已验证持续产生真实 WLAN PCAPNG；Sensor 已真实处理过大量流和产生大量 `ai_alert` / `evidence_snapshot`。
- Sensor 对 dumpcap 环形轮转的文件消失竞态已修复：发现或读取到被覆盖的 PCAP 时跳过，不再导致 systemd 重启风暴。
- Console、Nginx、Wazuh、Indexer、Filebeat、Dashboard、Sensor 的服务安装和启动链路已经完成过部署验收；当前运行状态以本节的现场复核为准。WSL 常驻任务使用 `/bin/sleep infinity`，不能再使用 `/bin/true` 或 `bash -lc` 版本。
- Nginx 配置目录权限和本机回环访问已修复；本机访问控制台已验证 HTTP `200`。
- 本轮自动化验收：`.venv\Scripts\python.exe -m pytest` 为 `106 passed, 1 warning`；`.venv\Scripts\ruff.exe check src tests` 和 `ruff format --check src tests` 通过；前端在 `web\frontend` 执行 `npm run build` 成功，主 bundle 为 637.15 kB（gzip 196.55 kB）。Vite 的单包超过 500 kB 提示是独立的性能优化事项，不阻塞当前闭环。
- Wazuh 规则修复已落地：`ai_alert` 使用实际 JSON 解码路径，并同时兼容默认 Suricata JSON 父规则 `86600`；`wazuh-analysisd -t` 通过，真实高风险模型信号经 `wazuh-logtest` 命中规则 `110103`、level `12`。

关键部署文件：

- `deploy/wsl-lab/install-host.ps1`
- `deploy/wsl-lab/install-guest.sh`
- `deploy/wsl-lab/repair-guest.sh`
- `deploy/wsl-lab/mineshark-sensor-wsl.service`
- `deploy/wsl-lab/sensor.toml`
- `deploy/wazuh/mineshark_rules.xml`
- `docs/wsl_lab_deployment.md`

### 4. 2026-08-03 现场状态

本次复核不能继续写成“Wazuh 全部在线”。`systemctl is-active` 返回：Wazuh Indexer 和 Manager 仍处于 `activating`，Filebeat、Dashboard、Nginx、Sensor、Console 和 MineShark Zeek 服务为 `active`；Indexer 的 `9200` 连接仍可能被拒绝。Indexer 反复启动期间，Wazuh 告警链路视为未就绪，必须修复或重新启动后再做 Console 告警验收。

RAG 已经不是“可能无索引”的状态：`/var/lib/mineshark/outputs/rag/` 下存在 `knowledge.faiss` 和 `metadata.json`，元数据为 provider `local-hash`、10 条知识、384 维。上一轮 API 验收中 `/api/health` 的 `sources.rag_index.ok=true`，`/api/evidence?top_k=4` 返回 HTTP 200 且有 4 条 RAG 命中；后续现场仍应重新执行这两项检查。

Suricata 当前有日志；Zeek 当前没有有效旁证事件。旁证空或服务异常时，Console 只能显示空状态/错误原因，不能把“已安装”写成“已有证据”，也不能把模型概率写成攻击事实。

Wazuh 规则字段路径的修复仍已落地：使用 `data.schema_version`、`data.event_type`、`data.risk_level`，并兼容默认 Suricata JSON 父规则 `86600`；`wazuh-analysisd -t` 和历史 `wazuh-logtest` 验收记录保留在下方历史资料中，不能替代本次 Indexer 在线检查。

**计划任务的可靠性仍是未完成项。** `MineShark-Lab-Start` 之前的记录为 `Last Result: 1`；本轮手动 `Start-ScheduledTask` 后任务进入 `Running`，约 13 秒后仍保持运行，说明当前任务命令可以启动 WSL 常驻实例，但尚未完成重新登录或重启后的持久化验收。

### 5. 下一步的精确执行顺序

1. 在 Windows 重新登录或重启后验证 `MineShark-Lab-Start` 是否自动保持 `Running`，并确认 Wazuh、Indexer、Sensor、Nginx 都重新为 `active`；当前 Indexer/Manager 仍处于 `activating`，应先定位启动日志和 9200 拒绝原因。
2. 将 Wazuh 本地告警文件读取改为受控、只读的权限方案，或继续以 Indexer 作为部署模式唯一告警源；不要为了让状态变绿而放宽证书、密码或目录权限。
3. 为 Zeek/Suricata 增加稳定的实时采集或 PCAP 回放调度，并给案件固化版本化 evidence bundle；当前证据覆盖仍以现场日志为准。
4. 对旧模型的大量普通流量高风险输出做单独的校准/误报研究，不能把本轮链路验收当成模型效果验收。
5. 任何进一步改动完成前，重新执行后端测试、Ruff、前端构建和浏览器 Console 验收。

### 6. 绝对不要再踩的坑

1. 不要用“dumpcap 看到包”替代“前端能看到 AI 告警”。必须逐段验证：PCAP -> Sensor `ai_alert` -> Wazuh 规则 -> Indexer -> `/api/alerts` -> 前端。
2. Wazuh JSON 规则字段必须使用 `data.event_type`、`data.risk_level` 等实际解码路径；不要用裸 `event_type`，也不要依赖复杂、多重 `<match>` 假设。
3. Wazuh `<localfile>` 必须插入 `/var/ossec/etc/ossec.conf` 的 `</ossec_config>` 之前，不能追加到根标签之后。
4. Windows dumpcap 环形覆盖会让 Sensor 看到消失的文件；发现和读取都必须忽略 `FileNotFoundError`，不能让服务重启。
5. Ubuntu 22.04 的 Python 3.10 没有 `tomllib`；保留 `tomli` 回退依赖。
6. WSL 启动任务必须常驻 `/bin/sleep infinity`；`/bin/true` 会立刻让发行版停止。不要恢复 `bash -lc` 版本，任务调度器的参数解析曾返回 `0xFFFFFFFF`。
7. Nginx 必须能遍历 `/etc/mineshark`，目录使用 `0755`；否则即使凭据正确也会得到 `500`。本机回环免认证是为桌面查看，不代表可以暴露给局域网。
8. 不要打印、提交或写入 Console/Wazuh 密码、证书私钥。凭据仅存放在 WSL 受限文件中。
9. 当前旧模型会把大量普通 WLAN 流量打成高风险。它只能证明采集和推理链路，不是攻击确认，也绝不能写成模型效果/误报率已达标。
10. Zeek/Suricata 已安装不等于已有证据；证据快照为空仍是诚实状态，不得伪造旁证。

## 历史归档（仅供追溯，不作为当前状态）

### 0. 2026-07-30 真实部署增量

已新增独立 Ubuntu Sensor 实现与中央 Wazuh 闭环，不再把 WSL 定时读取共享日志当作最终部署形态：

- `dumpcap` 5 秒/60 文件/128 snaplen 环形抓包，独立 capture 服务；Transformer Sensor 以非 root `mineshark` 用户运行。
- `mineshark-sensor validate-config|run|replay|status`、TOML 配置、PCAP/PCAPNG、VLAN、IPv4/IPv6 TCP、跨文件/重启流状态、确定性事件与 SQLite outbox。
- 恢复模型固定为 `legacy-zeek-v1`：前 20 包、TCP payload+54、相对流起点累计时间。黄金 PCAP 已验证新 Sensor 与 Zeek 生产者一致，旧/新 CPU 概率误差为 0。
- `ai_alert`、脱敏 `evidence_snapshot`、`sensor_heartbeat` 通过 Wazuh Agent JSONL 通道上送；中央提供者按 schema 和 Sensor 白名单查询，重复 `event_id` 去重，未知版本隔离。
- `/api/alerts`、案件同步和证据聚合在部署模式读取 Wazuh Indexer；Sensor 证据快照会合并回现有 evidence bundle。CORS 已改为显式白名单。
- 已提供 systemd、Wazuh 规则、Nginx HTTPS、日志轮转、Sensor/Console 安装器、Linux 离线包构建器和中文部署/验收手册。

物理 SPAN/TAP、100 Mbps 持续 30 分钟、丢包率不超过 0.1%、端到端 p95 不超过 60 秒仍需在目标 Ubuntu/交换机/Wazuh 环境签署，开发机回放不代表这些验收已完成。详见 `docs/real_sensor_deployment.md` 与 `docs/real_sensor_acceptance.md`。

## 1. 这是什么任务

当前任务是将来源于 `AI-traffic-analysis` 的 `demo_jianli` 分支的 MineShark，产品化为面向国企安全运营场景的本地可部署加密流量智能研判验证平台。

展示对象是信息安全相关甲方领导和导师。目标是证明实验室具备可交付的研究、工程和实施能力，而不是做求职 Demo、营销落地页、自动判定攻击的 AI 产品或完整商用 SOC。

产品表述必须坚持以下边界：

- 本地可部署、旁路只读、分析员确认、全程留痕。
- 可接入现有 Wazuh、Zeek、Suricata 体系；“支持接入”不等于“当前在线”。
- 模型输出是待复核的信号，不是攻击结论。
- 结果必须能回到原始告警、证据、案件快照和报告，不能用纯假数据堆出系统体量。

## 2. 工作区与硬边界

- 活动仓库：`<项目根目录>`
- 当前分支：`main`
- 严禁修改、切换或清理主仓库工作区。
  - 该 training 工作区可能包含其他未提交改动。
- 当前 MineShark 工作树也是脏的，所有已有改动都应视为用户资产；不要使用 `git reset --hard`、`git clean`、`git checkout -- <path>` 或批量删除。
- 当前前端构建产物由 FastAPI 从 `web/frontend/dist` 提供；改前端后必须重新执行 `npm run build`。

## 3. 已完成内容

### 3.1 后端与闭环能力

已完成 Windows SQLite 连接正确关闭，解决测试临时文件被锁的问题。

已完成“研判案件”闭环：

1. 从 AI 告警创建案件。
2. 保存 `alert_key`、完整 `alert_snapshot`、状态、结论、负责人、研判依据及时间戳。
3. 通过 API 查询、创建和更新案件。
4. 通过受控同步为新告警建案，重复 `alert_key` 会跳过，不会重复建案。

现有 API：

- `GET /api/health`
- `GET /api/overview`
- `GET /api/alerts`
- `GET /api/evidence`
- `GET /api/cases`
- `POST /api/cases`
- `PATCH /api/cases/{case_id}`
- `POST /api/cases/sync`
- `GET/POST /api/tasks`
- `GET /api/reports`

不要随意修改模型、阈值、SQLite schema、报告生成逻辑或案件同步幂等逻辑。本轮产品化只增加前端的数据展示适配，不增加后端 API。

### 3.2 指挥台前端

已完成“混合指挥台”方向，借鉴的是公开竞品的工作流和信息架构，而不是品牌或登录后 UI 的像素级复刻：

- Wazuh：本地部署边界、数据源健康、模块化导航。
- Microsoft Sentinel：事件调查、时间线、事实上下文和原始日志。
- Elastic Security：分析员工作台、告警队列与详情并置。
- Splunk Enterprise Security：队列优先、明确研判与处置动作。

MineShark 自己的核心识别元素是“研判链路总线”：模型信号 -> 证据接入 -> 人工案件 -> 最终结论。它连接的都是实际告警、证据包和 SQLite 案件快照。

已完成的页面改造：

- 全局壳层：六个原有入口保持不变，视觉分为“指挥台 / 研判 / 交付留痕”；顶部展示本地边界、节点身份、成功刷新时间和全局动作。
- 总览：当前风险、证据覆盖、处置闭环、本地部署边界、研判链路总线、真实告警与案件工作区。
- AI 告警：过滤器 + 队列 + 调查详情；详情包括模型信号、证据摘要、关联案件、原始告警快照、证据拓扑和建案/查看案件动作。
- 研判案件：案件队列、事实快照、状态时间线、负责人、研判结论、依据和重新打开提示。
- 证据拓扑：React Flow 拓扑、查询窗口、基于 `evidence_bundle` 的证据台账、事件数、缺失原因和错误状态。
- 报告中心：报告队列 + 可追溯阅读器；当前没有报告时诚实展示空状态。
- 任务历史：任务时间线 + 系统状态；当前没有任务时诚实展示空状态。
- 当前 `main` 默认使用白色、克制、工业化的令牌、焦点环、4px 状态标签和表格行高；历史深色方案和截图只保留作设计追溯，不是当前默认主题。不使用紫色渐变、装饰性光球或攻击地图。

关键实现文件：

- `web/frontend/src/App.jsx`
- `web/frontend/src/styles.css`
- `tests/test_web_console.py`

### 3.3 设计与验证交付物

Codex 会话工作目录下已有设计和验证材料：

- `<Codex会话输出目录>\e-mineshark-product-productization-e-trafficdetection\outputs\mineshark_competitor_design_comparison.md`
- `<Codex会话输出目录>\e-mineshark-product-productization-e-trafficdetection\outputs\mineshark_design_brief_v2.md`
- `<Codex会话输出目录>\e-mineshark-product-productization-e-trafficdetection\outputs\mineshark_ui_verification_v2.json`
- `<Codex会话输出目录>\e-mineshark-product-productization-e-trafficdetection\outputs\screenshots-v2\`

最近一次桌面主演示截图：

`...\outputs\screenshots-v2\mineshark-command-center-1920x1080.png`

## 4. 当前演示数据与事实状态

最近用于验收的服务地址为 `http://127.0.0.1:8011`，使用 `tests/fixtures/demo_event/ai_alerts.json`。

当前演示数据不是“完整 SOC 数据集”，具体为：

- AI 告警：1 条，`demo-alert-001`，模型分数 `0.930`，模型预测为 `malware`。
- 案件：1 个，已关闭；分析员结论为 `benign`，界面统一显示“良性流量”。
- 数据源实际就绪：MineShark AI 为 1/5；Wazuh、Zeek、Suricata、RAG 未就绪。
- 报告：0 条。
- 任务历史：0 条。

因此页面必须继续诚实表达：

- 只有一个时间样本时显示“样本不足以形成趋势”，不要画趋势图。
- 未接入或路径不存在的来源显示“未连接 / 路径不存在 / 索引缺失 / 查询异常”，不要显示为在线。
- 报告和任务为空时展示空状态，不创建假的报告、任务、攻击数或成功率。

## 5. 最近验证结果

最近一次完成时间：2026-07-29。

- 后端全量测试：`38 passed`。
- Ruff：`All checks passed!`。
- 前端生产构建：通过。
- 浏览器验证：通过，覆盖 1920x1080、1600x900、1280x800、1180x820、768x1024、375x812。
- 浏览器验证确认：无页面级横向溢出、无 console/page error、图标按钮均有 `aria-label`、键盘焦点有可见 outline。
- 交互验证确认：告警筛选、告警详情、证据请求、证据台账、总线进入证据和案件、案件保存、报告空状态、任务历史刷新、连续两次告警同步去重。
  - 两次同步均为 `created=0`、`skipped_existing=1`，符合幂等预期。

已知但暂不处理的构建警告：前端主包约 636.66 kB，Vite 提示可拆包。性能拆包是独立任务，当前不要为了消除警告顺手大规模重构。

注意：浏览器验证为了验证案件更新，向现有 demo 案件发送过一次保持原有结论的 PATCH；`benign` 结论未变化，但 `updated_at` 已更新。这不是数据损坏。

## 6. 当前卡点

没有代码实现层面的硬阻塞。当前限制来自演示环境和产品成熟度，而不是前端样式：

1. 演示数据量只有一个时间样本，不能支持趋势、误报率、升级率或阈值分桶等真实统计。
2. Wazuh、Zeek、Suricata 和 RAG 在当前 Windows 演示环境未接入或不存在，证据页只能显示真实的缺失/错误信息。
3. 报告和任务当前为空；不要为了填满页面触发外部模型或伪造结果。
4. 单次证据查询仍是临时聚合，尚未把 Wazuh/Zeek/Suricata/RAG 结果版本化固化到案件。

## 7. 下一步计划

按 `docs/productization_roadmap.md` 的优先级推进，不要同时混入性能大重构或新的营销功能。

### P0：持续接入与去重

- 为新告警建立可控的轮询或增量同步入口。
- 用 `alert_key`、时间窗口和网络五元组继续保证重复告警不重复建案。
- 明确显示新告警、已有案件和已关闭案件。

### P1：证据快照与可复现研判

- 在案件处置时固化当前 evidence bundle 的版本化快照，而不是只在报告生成时临时查询。
- 报告需要引用已保存快照，便于复盘、审计和重现。

### P2：处置质量度量

- 在积累足够真实样本后，再做待研判时长、升级率、误报率、模型阈值分桶结论和数据源缺失率。
- 任何统计图表都必须可从 API/案件快照复算；样本不足时继续使用诚实空状态。

### P3：运行可靠性与交付

- 健康检查、任务超时/重试语义、审计日志、部署配置说明。
- 将演示夹具与真实环境做明显隔离。
- 准备面向甲方的本地部署说明和接入边界说明。

## 8. 新会话的推荐工作方式

1. 先确认目录为 `<项目根目录>`，分支为 `main`，并确认没有进入主仓库工作区。
2. 先读本文件和 `docs/productization_roadmap.md`，再读取 `git status`；保留已有未提交改动。
3. 新功能必须严格 TDD：先在 `tests/test_web_console.py` 或对应测试中写失败测试，运行并确认失败，再做最小实现。
4. 前端改动完成后，先构建，再让 FastAPI 托管最新 `dist`，最后运行浏览器截图/交互检查。
5. 所有完成结论都要有本轮新鲜命令输出；不要引用旧的“应该能过”。

本机命令建议（PowerShell / RTK 环境）：

```powershell
rtk proxy pwsh -NoLogo -NoProfile -Command "& '<项目根目录>\.venv\Scripts\python.exe' -m pytest -q"
rtk proxy pwsh -NoLogo -NoProfile -Command "& '<项目根目录>\.venv\Scripts\ruff.exe' check src tests"
rtk npm run build
rtk node <Codex会话输出目录>\e-mineshark-product-productization-e-trafficdetection\outputs\mineshark_ui_verify_v2.cjs
```

前端构建命令必须在 `<项目根目录>\web\frontend` 执行。前面三个 Python/Node 命令均应使用仓库或脚本要求的工作目录；不要依赖 Windows Store 的 `python` shim。

如需重启控制台：先在 `<项目根目录>` 完成前端构建，再使用仓库入口 `<项目根目录>\.venv\Scripts\mineshark-console.exe --host 127.0.0.1 --port 8011`。启动前先检查端口是否已有服务，避免误杀用户进程。

## 9. 绝对不要再踩的坑

1. 不要碰主仓库工作区，包括切分支、回退、清理、格式化或测试产生的写入。
2. 不要在脏工作树中使用任何清理或回退命令；只在理解现有修改后做增量编辑。
3. 不要把模型 `malware` 预测写成“已确认攻击”；演示数据的人工结论是“良性流量”。
4. 不要把“支持接入 Wazuh/Zeek/Suricata”展示成“当前在线”；当前只有 MineShark AI 数据源真实就绪。
5. 不要为 1 条告警伪造时间趋势、攻击地图、处置成功率、误报率或复杂统计。
6. 不要把 `/api/overview` 的 `generated_at` 当更新时间。当前它实际返回告警文件路径；前端已经改为记录成功刷新时刻。
7. 证据页面截图或自动化时，点击“生成证据拓扑”后必须等待 `/api/evidence` 响应完成；否则会截到“尚未请求”的中间状态。
8. 重复同步是正常路径：相同 alert key 第二次应该显示跳过，而不是创建新案件。
9. 不要为了填充报告/任务空状态直接触发 Agent 报告；它可能依赖外部 LLM、增加运行时间或产生不可控成本。
10. 不要做紫色渐变、装饰光球、营销式英雄页、巨大圆角卡片或蓝黑风格残留；当前默认界面保持白色、克制、工业化、证据优先，历史深色方案不作为默认入口。
11. 不要把前端拆包警告和本轮视觉/闭环工作混在一起；主包性能优化必须单开任务并重新验收。
12. PowerShell 中 `python` 可能指向 Windows Store shim。测试与 Ruff 优先使用 `.venv\Scripts\python.exe` 和 `.venv\Scripts\ruff.exe`。

## 10. 当前未提交状态

历史记录显示，截至当时写入时，旧 `productization` 分支有未提交内容。该记录只用于追溯，产品化代码现已进入 `main`；已修改或新增的关键文件包括：

- `src/mineshark/config.py`
- `src/mineshark/web/api.py`
- `src/mineshark/web/database.py`
- `tests/test_config.py`
- `tests/test_web_console.py`
- `web/frontend/index.html`
- `web/frontend/src/App.jsx`
- `web/frontend/src/styles.css`
- `docs/productization_roadmap.md`
- `docs/project_record.md`

不要因为当前记录只关注前端就覆盖或回退前述后端改动；它们共同构成当前已验证的产品化基线。
