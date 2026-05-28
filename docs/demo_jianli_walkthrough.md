# demo_jianli 分支项目讲解与复现手册

这份文档的目标是把 `demo_jianli` 分支讲清楚：它怎么一键运行、每一步在检查什么、数据从哪里来、Agent 调用了哪些工具、报告应该怎么看，以及面试时应该怎么讲。

当前分支定位：`demo_jianli` 是专门面向 Linux/Wazuh 实验环境的安全研判分支。它不替换已有的 `mineshark-ai.timer`，而是以旁路方式读取现有 AI 告警、Wazuh、Zeek、Suricata 和 RAG 知识库，最后生成中文研判报告。

## 1. 一句话讲清楚这个项目

MineShark 是一个面向加密流量的安全研判项目：已有实时 AI 引擎负责把可疑流量写入 `/var/log/ai_alerts.json`，Wazuh 负责摄取告警；`demo_jianli` 分支新增 LangGraph Agent 和 RAG 能力，把 MineShark AI 告警、Wazuh 告警、Zeek 连接日志、Suricata IDS 日志和安全知识库关联起来，生成可复核的中文 JSON/Markdown 研判报告。

需要特别注意：模型概率只能作为“风险线索”，不能直接说成“攻击事实”。最终判断需要结合 Wazuh、Zeek、Suricata、RAG 知识和人工复核。

## 2. 运行前确认

在 WSL/Wazuh 环境中，项目路径应为：

```bash
cd /opt/mineshark_agent
```

确认当前分支：

```bash
git branch --show-current
```

期望输出：

```text
demo_jianli
```

拉取最新代码：

```bash
git pull origin demo_jianli
```

确认 Wazuh 核心服务：

```bash
systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard filebeat suricata ssh
```

期望都为：

```text
active
```

为什么建议用 `root` 或 `sudo` 跑演示脚本：Agent 需要读取 `/var/log/ai_alerts.json` 和 `/var/ossec/logs/alerts/alerts.json`，普通 `ubuntu` 用户可能没有权限。

## 3. 一键运行命令

在 Wazuh 服务器内部运行：

```bash
cd /opt/mineshark_agent
sudo bash scripts/agent/run_cli_agent_demo.sh
```

如果从 Windows PowerShell 调用 WSL：

```powershell
wsl -d Wazuh -u root -- bash -lc "cd /opt/mineshark_agent && bash scripts/agent/run_cli_agent_demo.sh"
```

脚本默认会做三件事：

- 检查 Wazuh、Git、Python、`.env`、AI 告警文件。
- 重新构建 RAG 索引。
- 运行 CLI Agent 并预览报告。

如果已经构建过 RAG，只想快速复跑 Agent：

```bash
cd /opt/mineshark_agent
sudo bash scripts/agent/run_cli_agent_demo.sh --skip-rag-build
```

如果只想多看一些报告行数：

```bash
cd /opt/mineshark_agent
sudo bash scripts/agent/run_cli_agent_demo.sh --skip-rag-build --show-lines 220
```

## 4. 一键脚本每一步在检查什么

一键脚本路径：

```text
scripts/agent/run_cli_agent_demo.sh
```

它的步骤含义如下：

| 步骤 | 检查内容 | 为什么重要 |
| --- | --- | --- |
| 第 1 步 | `hostname`、磁盘空间、当前路径 | 确认确实在 Wazuh 环境和 `/opt/mineshark_agent` 项目中运行。 |
| 第 2 步 | Wazuh Indexer、Manager、Dashboard、Filebeat、Suricata、SSH | Agent 要读取 Wazuh API 和安全日志，底层服务需要先正常。 |
| 第 3 步 | Git 分支和工作区状态 | 确认当前代码是 `demo_jianli` 分支，避免跑错分支。 |
| 第 4 步 | Python 虚拟环境和 Agent CLI help | 确认 `.venv` 可用，`run_agent_audit.py` 能正常导入。 |
| 第 5 步 | `.env` 中关键密钥是否填写 | 只显示 `set/missing`，不打印真实 API Key 和密码。 |
| 第 6 步 | `/var/log/ai_alerts.json` | 确认实时 AI 告警文件存在且可读。 |
| 第 7 步 | Wazuh `alerts.json` 中是否有 MineShark 告警 | 验证 AI 告警是否已进入 Wazuh 告警体系。 |
| 第 8 步 | `outputs/rag/knowledge.faiss` 和 `metadata.json` | 查看是否已有 RAG 索引产物。 |
| 第 9 步 | 构建或跳过 RAG 索引 | 默认调用 DashScope embedding 重新生成 FAISS 索引。 |
| 第 10 步 | 正式运行 CLI Agent | 调用 DeepSeek + LangGraph 工具链生成报告。 |
| 第 11 步 | 预览 Markdown 报告 | 让你快速确认报告内容是否像一次安全研判。 |
| 第 12 步 | 打印 `tool_trace` 摘要 | 查看 Agent 调用了哪些工具，避免 LLM 过程变成黑盒。 |

## 5. 数据从哪里来

整体链路分成两层。

第一层是已经存在的实时检测层：

```text
Zeek / MineShark live log
  -> /opt/mineshark_lab/ai_engine/predict_scan.py
  -> /opt/mineshark_lab/ai_engine/deep_mineshark_best.pt
  -> /var/log/ai_alerts.json
  -> Wazuh 摄取
  -> /var/ossec/logs/alerts/alerts.json
```

这一层由原来的 `mineshark-ai.timer` 驱动。`demo_jianli` 分支不替换它、不停用它、不修改它，只读取它的输出。

第二层是新增的研判层：

```text
/var/log/ai_alerts.json
+ Wazuh alerts / agents
+ /opt/zeek/spool/zeek/conn.log
+ /var/log/suricata/eve.json
+ outputs/rag/knowledge.faiss
  -> LangGraph ReAct Agent
  -> DeepSeek
  -> outputs/reports/agent_audit_report.json
  -> outputs/reports/agent_audit_report.md
```

关键文件和作用：

| 文件或目录 | 作用 |
| --- | --- |
| `/var/log/ai_alerts.json` | MineShark 实时 AI 告警，Agent 默认优先读取。 |
| `/var/ossec/logs/alerts/alerts.json` | Wazuh 本地告警日志，Indexer API 失败时可回退读取。 |
| `/opt/zeek/spool/zeek/conn.log` | Zeek 连接日志，用于补充连接上下文。 |
| `/var/log/suricata/eve.json` | Suricata IDS 事件日志，用于补充规则告警证据。 |
| `configs/reporting/security_playbook.jsonl` | RAG 的原始安全知识库。 |
| `outputs/rag/knowledge.faiss` | FAISS 向量索引。 |
| `outputs/rag/metadata.json` | RAG 文档元数据。 |
| `outputs/reports/agent_audit_report.json` | 结构化报告，适合调试和后续前端复用。 |
| `outputs/reports/agent_audit_report.md` | 中文研判报告，适合展示和人工阅读。 |

## 6. Agent 入口和核心代码

一键脚本只是把命令串起来，真正的 Agent 入口是：

```text
scripts/agent/run_agent_audit.py
```

这个文件很薄，主要负责把 `src/` 加入 Python 路径，然后调用：

```text
src/mineshark/agent/cli.py
```

`cli.py` 负责：

- 读取命令行参数和 `.env`。
- 创建 LangGraph ReAct Agent。
- 组织用户任务说明，让 Agent 优先读取实时 AI 告警。
- 写出 JSON 和 Markdown 报告。

Agent 的工具层在：

```text
src/mineshark/agent/toolbox.py
```

这个文件负责把 Wazuh、Zeek、Suricata、RAG 和可选模型推理封装成 LangChain `StructuredTool`，供 LangGraph Agent 调用。

配置读取在：

```text
src/mineshark/config.py
```

它从 `.env` 读取 DeepSeek、DashScope、Wazuh、Zeek、Suricata、AI 告警路径和 RAG 路径等配置。

## 7. Agent 调用了哪些工具

当前 Agent 工具如下：

| 工具名 | 默认用途 | 证据来源 |
| --- | --- | --- |
| `query_mineshark_ai_alerts` | 读取 MineShark 实时 AI 告警 | `/var/log/ai_alerts.json` |
| `query_wazuh_alerts` | 查询 Wazuh 告警，失败时回退本地日志 | Wazuh Indexer API / `/var/ossec/logs/alerts/alerts.json` |
| `query_wazuh_agents` | 查询 Wazuh manager 状态和 agent 列表 | Wazuh Server API |
| `query_zeek_context` | 查询 Zeek 连接上下文 | `/opt/zeek/spool/zeek/conn.log` |
| `query_suricata_alerts` | 查询 Suricata IDS 告警 | `/var/log/suricata/eve.json` |
| `retrieve_security_knowledge` | 从 RAG 知识库检索安全解释和处置建议 | `outputs/rag/` |
| `run_traffic_model` | 可选兜底，重新跑 Transformer 推理 | 只有显式传入 `--rerun-model` 才暴露给 Agent |

默认运行模式下，Agent 的第一步必须是 `query_mineshark_ai_alerts`，因为这个分支面向的是“已有实时 AI 告警的旁路研判”，不是每次重新跑离线模型。

## 8. RAG 是怎么工作的

RAG 构建命令：

```bash
cd /opt/mineshark_agent
source .venv/bin/activate
python scripts/rag/build_index.py --env-file .env
```

构建流程：

```text
configs/reporting/security_playbook.jsonl
  -> DashScope text-embedding-v4
  -> FAISS
  -> outputs/rag/knowledge.faiss
  -> outputs/rag/metadata.json
```

RAG 的作用不是替代检测，而是给 LLM 提供项目内可控的安全知识，例如：

- C2 可疑通信解释。
- 加密流量异常研判边界。
- 横向移动和端口异常排查思路。
- Suricata/Wazuh 告警解释。
- 误报治理和人工复核建议。

面试时可以这样说：LLM 如果只靠自身知识，容易泛泛而谈；RAG 把本项目的 playbook 和规则说明注入研判过程，让报告更贴近当前系统，而不是凭空写安全建议。

## 9. 报告怎么看

报告文件：

```text
outputs/reports/agent_audit_report.md
outputs/reports/agent_audit_report.json
```

查看 Markdown 报告：

```bash
cd /opt/mineshark_agent
sed -n '1,180p' outputs/reports/agent_audit_report.md
```

Markdown 主要看这些内容：

- 总体结论：这次事件是什么风险等级或风险线索。
- 时间线：AI 告警、Wazuh 告警、网络日志是否能串起来。
- MineShark AI 告警摘要：预测类别、置信度、源/目的 IP、端口、UID。
- Wazuh/Zeek/Suricata 关联：有没有平台告警和网络上下文支撑。
- RAG 知识依据：报告引用了哪些安全 playbook。
- 处置建议：建议人工排查什么，而不是自动封禁。
- 误报与局限性：说明模型概率不是攻击事实。

查看 JSON 报告：

```bash
cd /opt/mineshark_agent
python3 -m json.tool outputs/reports/agent_audit_report.json | less
```

JSON 主要看这些字段：

| 字段 | 含义 |
| --- | --- |
| `generated_at` | 报告生成时间。 |
| `input` | 这次 CLI 运行的参数。 |
| `runtime` | 实际使用的模型、日志路径、RAG 路径和 TLS 提示。 |
| `tool_trace` | Agent 工具调用轨迹，是排查黑盒问题的重点。 |
| `agent_messages` | LangGraph/LLM 消息过程。 |
| `markdown_report` | 最终 Markdown 报告正文。 |

单独查看工具调用轨迹：

```bash
cd /opt/mineshark_agent
python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("outputs/reports/agent_audit_report.json").read_text(encoding="utf-8"))
for index, item in enumerate(data.get("tool_trace", []), start=1):
    print(index, item.get("tool"), item.get("arguments"))
PY
```

`tool_trace` 的意义：如果报告结论看起来奇怪，可以回头看 Agent 到底查了哪些证据、参数是什么、是否发生了 API 失败或本地日志回退。

## 10. 常见问题和处理

### 10.1 `Permission denied`

如果看到：

```text
wc: /var/log/ai_alerts.json: Permission denied
```

说明普通用户没有读取 AI 告警文件的权限。使用：

```bash
cd /opt/mineshark_agent
sudo bash scripts/agent/run_cli_agent_demo.sh
```

### 10.2 `WAZUH_VERIFY_SSL=false` 警告

如果看到：

```text
Warning: WAZUH_VERIFY_SSL=false
```

这是开发环境使用自签名证书时的提示。当前 Wazuh 一体化实验环境可以接受；正式环境应配置 CA 并开启证书校验。

### 10.3 RAG 构建失败

优先检查：

- `.env` 中 `DASHSCOPE_API_KEY` 是否填写。
- DashScope 账号是否有 embedding 额度。
- WSL 是否能访问外网。
- `configs/reporting/security_playbook.jsonl` 是否存在。

### 10.4 DeepSeek 调用失败

优先检查：

- `.env` 中 `DEEPSEEK_API_KEY` 是否填写。
- `DEEPSEEK_MODEL` 是否为可用模型，例如 `deepseek-chat`。
- 网络是否能访问 DeepSeek API。

### 10.5 Wazuh Indexer API 不通

Agent 会尝试回退读取：

```text
/var/ossec/logs/alerts/alerts.json
```

这也是项目鲁棒性的一个点：不是某个 API 失败就整条链路不可用，而是保留本地日志证据，并在 JSON 报告中记录降级原因。

### 10.6 `src/mineshark_traffic_analysis.egg-info/` 未跟踪

如果 `git status --short` 看到：

```text
?? src/mineshark_traffic_analysis.egg-info/
```

这是 `pip install -e .` 产生的安装元数据，不影响 Agent 运行。后续如果要清理，先单独确认，不在演示脚本中自动删除。

## 11. 面试时怎么讲

### 11.1 30 秒版本

我这个项目做的是加密流量安全研判。已有实时 AI 引擎会读取流量元数据，用 Transformer 判断可疑连接，并把结果写到 `/var/log/ai_alerts.json`；Wazuh 会摄取这类 AI 告警。我在 `demo_jianli` 分支新增了一个 LangGraph Agent，它旁路读取 AI 告警、Wazuh 告警、Zeek 连接日志、Suricata IDS 日志和 FAISS RAG 知识库，然后调用 DeepSeek 生成中文研判报告。报告保留 JSON 工具调用轨迹，能说明证据从哪里来，同时强调模型概率只是风险线索，不直接当作攻击事实。

### 11.2 2 分钟版本

这个项目分两层。

第一层是实时检测层。Wazuh 环境里已有 `mineshark-ai.timer`，它定时调用 `/opt/mineshark_lab/ai_engine/predict_scan.py`，用 `deep_mineshark_best.pt` 对流量元数据做推理。如果恶意概率超过阈值，就把 JSONL 告警写入 `/var/log/ai_alerts.json`。Wazuh 通过规则摄取这类告警，例如我们验证过规则 `100500` 能捕获 MineShark AI 告警。

第二层是我新增的研判层，也就是 `demo_jianli` 分支。它不替换原来的 timer，而是旁路读取已有结果。Agent 的入口是 `scripts/agent/run_agent_audit.py`，核心代码在 `src/mineshark/agent/cli.py` 和 `src/mineshark/agent/toolbox.py`。Agent 会优先读取 `/var/log/ai_alerts.json`，再按需查询 Wazuh、Zeek、Suricata 和 RAG 知识库，最后生成 `agent_audit_report.md` 和 `agent_audit_report.json`。

我这样设计的原因是降低风险：原检测链路继续稳定运行，Agent 即使失败也不会影响 Wazuh 摄取和实时告警。报告也不会把模型概率直接写成攻击事实，而是把它作为风险线索，再结合多源证据给人工复核建议。

### 11.3 面试官可能追问的问题

**为什么用旁路架构？**

因为已有 `mineshark-ai.timer` 已经负责实时检测。Agent 只读已有告警和日志，不写回 Wazuh，不做自动封禁。这样风险小，容易验证，也符合安全系统渐进式接入的思路。

**为什么默认不重新跑模型？**

真实环境中模型推理已经由 timer 做了。Agent 默认读取 `/var/log/ai_alerts.json`，能避免重复推理和结果不一致。只有显式传入 `--rerun-model` 时才暴露 `run_traffic_model` 工具。

**RAG 在这里解决什么问题？**

RAG 让报告能参考本地安全 playbook 和规则解释，而不是让 LLM 只凭通用知识输出。它提升报告的可控性和贴合度。

**怎么避免 LLM 黑盒？**

JSON 报告里有 `tool_trace`，记录每次工具调用的工具名、参数和结果。如果结论有问题，可以回溯 Agent 查了什么证据。

**怎么处理误报？**

报告明确区分“模型风险线索”和“攻击事实”。模型只基于元数据判断，必须结合 Wazuh、Zeek、Suricata、资产上下文和人工复核。

**Wazuh API 失败怎么办？**

优先查 Indexer API；失败时回退到 `/var/ossec/logs/alerts/alerts.json`，并在结构化结果中记录错误或降级原因。

## 12. 现场演示推荐顺序

演示时不要一上来讲所有代码，按这个顺序最自然：

1. 先打开 Wazuh Dashboard，说明平台环境是活的。
2. 展示 `/var/log/ai_alerts.json` 中的 MineShark AI 告警。
3. 展示 Wazuh `alerts.json` 中对应的 rule `100500`。
4. 运行一键脚本。
5. 打开 Markdown 报告，讲总体结论和证据链。
6. 打开 JSON 报告里的 `tool_trace`，证明 Agent 不是凭空写报告。
7. 最后讲边界：只读、不写回、不自动封禁，模型概率只是风险线索。

可用命令：

```bash
cd /opt/mineshark_agent
sudo bash scripts/agent/run_cli_agent_demo.sh --skip-rag-build --show-lines 180
```

## 13. 当前项目边界

当前已经完成：

- MineShark AI 告警旁路读取。
- Wazuh 告警和 agent 查询。
- Zeek `conn.log` 上下文读取。
- Suricata `eve.json` 读取。
- FAISS RAG 构建和检索。
- LangGraph ReAct Agent。
- DeepSeek 中文研判报告。
- JSON `tool_trace` 可追踪过程。
- 一键演示脚本。

当前没有做：

- 前端工作台。
- 自动封禁或自动处置。
- 写回 Wazuh 规则。
- 替换现有 `mineshark-ai.timer`。
- 大规模生产级 RAG 知识库。
- 报告质量自动评分。

下一阶段可以继续做：

- 前端页面展示 AI 告警、证据链、RAG 命中和报告。
- 增加 `--uid` 精准复盘单条 AI 告警的演示脚本参数。
- 构造同时命中 AI、Wazuh、Zeek、Suricata 的完整演示案例。
- 扩展 RAG 知识库。
- 增加失败降级测试和报告质量测试。

