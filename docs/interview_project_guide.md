# MineShark 项目面试讲解稿

这份文档的目标不是“写得像论文”，而是帮助你在面试里把项目讲清楚。建议你先背熟 30 秒版本，再逐步扩展到 2 分钟和 5 分钟版本。

## 1. 一句话版本

MineShark 是一个面向加密流量的安全研判项目：它先用 Transformer 模型从包长、方向、时间间隔等元数据里识别可疑流量，再把 AI 告警和 Wazuh、Zeek、Suricata、RAG 知识库关联起来，最后用 LangGraph + DeepSeek 生成中文安全研判报告。

## 2. 30 秒版本

这个项目解决的是“加密流量看不见明文，但安全运营仍然需要判断风险”的问题。我做了一个旁路研判链路：已有的 MineShark AI 引擎会把可疑流量写入 `/var/log/ai_alerts.json`，Wazuh 会摄取这类 AI 告警；我在 `demo_jianli` 分支里补了一个 LangGraph Agent，它读取 AI 告警、Wazuh 告警、Zeek 连接日志、Suricata IDS 日志和 FAISS RAG 知识库，再调用 DeepSeek 生成结构化 JSON 和 Markdown 中文报告。整个系统只做读取、关联和研判，不自动封禁，也不写回 Wazuh。

## 3. 2 分钟版本

我这个项目分成两层。

第一层是实时检测层。Linux/WSL Wazuh 环境里有一个已有的 `mineshark-ai.timer`，它会定时调用 `/opt/mineshark_lab/ai_engine/predict_scan.py`。这个脚本读取 MineShark live log，把包长序列、方向序列、包间隔转换成模型输入，再用 `deep_mineshark_best.pt` 这个 Transformer 模型做二分类推理。如果恶意概率超过阈值，比如 0.5，就把 JSONL 格式的 AI 告警写入 `/var/log/ai_alerts.json`。Wazuh 已经配置了读取这个文件，所以 AI 告警会进入 Wazuh 的告警体系。我们已经验证过一条测试告警被 Wazuh 规则 `100500` 捕获，level 是 12。

第二层是新增的研判层，也就是 `demo_jianli` 分支的主要工作。它不替换原来的实时检测服务，而是旁路读取已有结果。核心入口是 `scripts/agent/run_agent_audit.py`，内部会调用 `src/mineshark/agent/cli.py` 创建 LangGraph ReAct Agent。Agent 通过 `src/mineshark/agent/toolbox.py` 暴露多个工具，包括读取 MineShark AI 告警、查询 Wazuh Indexer、查询 Wazuh agents、读取 Zeek、读取 Suricata、检索 RAG 知识库。RAG 部分用 DashScope 的 `text-embedding-v4` 生成向量，用 FAISS 保存本地索引，知识来源是 `configs/reporting/security_playbook.jsonl`。

最终输出有两份：`outputs/reports/agent_audit_report.json` 保存完整结构化数据和工具调用轨迹，`outputs/reports/agent_audit_report.md` 是给安全运营人员看的中文研判报告。报告会区分事实证据和模型风险线索，不把模型概率直接说成攻击事实。

## 4. 5 分钟版本

### 4.1 项目背景

很多企业流量已经加密，传统基于明文内容和特征串的检测手段会受限。但加密流量仍然保留元数据，比如包长、方向、连接持续时间、包间隔、端口和通信频率。这些特征可以作为模型判断的输入。

我的项目就是基于这个思路，先用 Transformer 对流量元数据做恶意/正常二分类，再把模型输出和安全运营里的多源证据做关联，最后生成一份可读的研判报告。

### 4.2 实时 AI 检测链路

实时检测链路在 WSL Wazuh 环境里运行：

```text
/root/mineshark_lab/mineshark_live.log
  -> /opt/mineshark_lab/ai_engine/predict_scan.py
  -> /opt/mineshark_lab/ai_engine/deep_mineshark_best.pt
  -> /var/log/ai_alerts.json
  -> Wazuh rule 100500
```

`predict_scan.py` 的关键逻辑是：

- 读取新增的 MineShark live log 行。
- 解析连接的 `src_ip`、`dst_ip`、端口、UID、包长序列和 IAT 序列。
- 构造 Transformer 输入张量。
- 用模型输出恶意概率。
- 如果超过阈值，就写入 `/var/log/ai_alerts.json`。
- 用 state 文件和 dedup 文件避免重复处理和刷屏。

我们已经做过一次受控重放实验，模型输出了：

```text
prediction = Malware
ai_confidence = 0.999951
uid = lab_replay_mineshark_20260527063525
```

随后 Wazuh 摄取这条日志并触发：

```text
rule.id = 100500
rule.level = 12
description = MineShark AI detected malicious encrypted traffic
```

### 4.3 Agent 研判链路

新增 Agent 研判链路在 `/opt/mineshark_agent` 中运行，对应 Git 分支是 `demo_jianli`。

主入口：

```text
scripts/agent/run_agent_audit.py
```

它会调用：

```text
src/mineshark/agent/cli.py
```

`cli.py` 做三件事：

- 读取 `.env` 配置。
- 创建 LangGraph ReAct Agent。
- 把最终 JSON 和 Markdown 报告写入 `outputs/reports/`。

Agent 的工具都在：

```text
src/mineshark/agent/toolbox.py
```

主要工具包括：

```text
query_mineshark_ai_alerts
query_wazuh_alerts
query_wazuh_agents
query_zeek_context
query_suricata_alerts
retrieve_security_knowledge
```

所以 Agent 不是凭空编报告，而是按工具链去查证据。

### 4.4 RAG 知识库链路

RAG 的知识来源是：

```text
configs/reporting/security_playbook.jsonl
```

构建命令是：

```bash
python scripts/rag/build_index.py --env-file .env
```

内部流程：

```text
security_playbook.jsonl
  -> DashScope text-embedding-v4
  -> FAISS
  -> outputs/rag/knowledge.faiss
  -> outputs/rag/metadata.json
```

Agent 研判时会根据当前告警内容，比如 C2、加密流量异常、Suricata 规则、Wazuh 告警边界等关键词，检索相关知识，然后让 DeepSeek 结合证据写报告。

### 4.5 Wazuh / Zeek / Suricata 的作用

Wazuh 负责主机侧和平台侧告警。Agent 通过两种方式查 Wazuh：

- Wazuh Server API：查 manager 状态和 agent 列表。
- Wazuh Indexer API：查 `wazuh-alerts-*` 索引里的告警。

如果 Indexer API 失败，代码会回退读取：

```text
/var/ossec/logs/alerts/alerts.json
```

Zeek 负责连接级网络元数据，当前默认读取：

```text
/opt/zeek/spool/zeek/conn.log
```

Suricata 负责 IDS 规则告警，默认读取：

```text
/var/log/suricata/eve.json
```

这三类证据的意义是：模型只能给风险线索，多源日志能帮助判断这个线索是否有上下文支撑。

### 4.6 输出报告

Agent 输出两份文件：

```text
outputs/reports/agent_audit_report.json
outputs/reports/agent_audit_report.md
```

JSON 文件适合给系统或前端使用，里面有输入参数、运行时配置、工具调用轨迹、Agent 消息和最终报告。

Markdown 文件适合给安全运营人员阅读，包含总体结论、时间线、AI 告警摘要、Wazuh/Zeek/Suricata 关联、RAG 知识依据、处置建议和误报边界。

## 5. 你应该特别会讲的 6 个技术点

### 5.1 为什么用旁路架构

我没有直接改原来的 `mineshark-ai.timer` 和 Wazuh 服务，而是新增一个旁路 Agent。这样做的好处是风险小，原来的实时检测链路继续稳定运行，Agent 只是读取已有输出并生成研判报告。即使 Agent 出错，也不会影响 Wazuh 摄取和原始 AI 告警产生。

### 5.2 为什么默认不重新跑模型

真实环境里模型推理已经由 `mineshark-ai.timer` 做了。如果 Agent 每次都重新跑模型，会浪费资源，也可能造成结果不一致。所以 Agent 默认读取 `/var/log/ai_alerts.json`，只有显式加 `--rerun-model` 时才启用离线推理工具。

### 5.3 为什么模型概率不能等于攻击事实

模型只能基于流量元数据给出统计风险，比如包长、方向、IAT 模式像不像恶意流量。它看不到明文，也不了解业务上下文。所以报告里必须说“风险线索”，不能直接说“确定发生攻击”。最终还要结合 Wazuh、Zeek、Suricata、资产归属和人工复核。

### 5.4 RAG 在这里解决什么问题

LLM 本身可能泛泛而谈。RAG 的作用是把本地安全 playbook 和规则解释注入研判过程，让报告能引用更贴近项目场景的知识，比如 C2 通信、加密流量误报、Suricata 规则关联、Wazuh 告警边界等。

### 5.5 `tool_trace` 为什么重要

Agent 调了哪些工具、参数是什么、返回了什么，都记录在 `agent_audit_report.json` 的 `tool_trace` 里。它解决了 LLM 黑盒问题：如果报告结论奇怪，可以回头看 Agent 到底查了哪些证据，有没有查错、有无降级。

### 5.6 Wazuh API 和本地日志回退的意义

优先查 Indexer API 是因为它更接近 Wazuh 的查询能力，可以按时间、IP、文本检索。但实验环境里 API 可能证书、权限、服务状态不稳定，所以我加了本地 `alerts.json` 回退，保证报告不会因为一个接口失败就完全不可用。

## 6. 项目边界和不足

你需要主动讲边界，这会显得你很清醒。

当前边界：

- 第一版是 CLI Agent，不是前端工作台。
- Agent 只读，不写回 Wazuh。
- 不做自动封禁、自动隔离、自动规则修改。
- 模型概率只是风险线索。
- RAG 知识库规模还比较小，主要是 playbook 和规则说明。
- 当前 Zeek 实时 `conn.log` 在 WSL 环境里还需要进一步稳定采集。
- 当前演示告警是受控重放，不是真实攻击。

可以继续优化的方向：

- 做一个前端页面展示 AI 告警、Wazuh 关联、RAG 命中和报告。
- 让 Zeek 和 Suricata 与 AI 告警的时间窗口强关联。
- 扩展 RAG 知识库。
- 加入报告评估和误报反馈机制。
- 支持更多输入格式和更多 Agent 工具。

## 7. 面试官可能追问的问题

### Q1：你这个项目的核心创新点是什么？

不是单独训练一个模型，也不是单独调用 LLM，而是把 AI 流量检测、Wazuh 安全平台、多源日志和 RAG Agent 串成一个可运行的安全研判链路。模型负责发现风险线索，Wazuh/Zeek/Suricata 提供证据，RAG 提供安全知识，LLM 负责组织报告。

### Q2：为什么用 Transformer 做流量检测？

因为流量是序列数据，包长、方向和包间隔都有时序关系。Transformer 可以建模序列中不同位置之间的依赖，比简单统计特征更适合表达连接行为模式。

### Q3：你输入模型的特征是什么？

主要是包长序列、方向序列和包间隔时间。包长反映通信负载，方向反映客户端和服务端交互模式，IAT 反映节奏和周期性。这些都不依赖明文内容，适合加密流量场景。

### Q4：你怎么避免误报？

第一，报告中不把模型概率当攻击事实。第二，Agent 会关联 Wazuh、Zeek、Suricata 证据。第三，RAG 知识库里有误报治理和研判边界。第四，建议人工复核，而不是自动处置。后续还可以加入业务白名单和反馈闭环。

### Q5：为什么要接 Wazuh？

Wazuh 是安全运营平台，负责主机告警、日志汇聚、规则匹配和 Dashboard 展示。AI 模型本身只是一个检测器，接入 Wazuh 后才能进入实际安全运营流程，被告警、检索和关联。

### Q6：Wazuh Server API 和 Indexer API 有什么区别？

Server API 更偏管理面，比如 manager 状态、agent 列表。Indexer API 更偏数据面，用来查 `wazuh-alerts-*` 里的告警。Agent 两个都用：一个看平台和 agent 状态，一个查具体告警证据。

### Q7：RAG 的知识库里放了什么？

放的是安全 playbook 和规则解释，例如 C2 可疑通信、加密流量异常、横向移动、端口异常、Suricata/Wazuh 告警边界、误报治理等。

### Q8：为什么不用 LLM 直接分析所有日志？

日志可能很长，直接塞给 LLM 成本高、上下文容易爆，而且不稳定。工具调用可以先结构化查询，只把相关证据交给 LLM。RAG 也只检索相关知识片段，而不是把整个知识库都塞进去。

### Q9：LangGraph 在这里做什么？

LangGraph 用来构建 ReAct Agent，让 LLM 可以根据任务选择工具、读取工具结果、继续查询，最后生成报告。它比单次 prompt 更适合多步骤调查。

### Q10：如果 DeepSeek API 不通怎么办？

当前 Agent 报告生成依赖 DeepSeek。如果 DeepSeek 不通，CLI 会失败或无法生成最终自然语言报告。后续可以加规则 fallback 报告，或者把工具结果先输出 JSON，让前端/人工继续查看。

### Q11：如果 Wazuh Indexer API 不通怎么办？

代码会回退读取 `/var/ossec/logs/alerts/alerts.json`，并在结果里记录降级原因。这样至少能保留本地告警证据，不至于整条链路不可用。

### Q12：你怎么证明项目跑通了？

我做过一次端到端验证：受控重放一条 MineShark live log，原 AI 模型生成 `/var/log/ai_alerts.json` 告警，Wazuh 摄取后触发规则 `100500`，Agent 再查询 AI 告警、Wazuh、Suricata、RAG，最后生成 `agent_audit_report.md` 和 `agent_audit_report.json`。

### Q13：为什么报告里要保留 JSON？

Markdown 适合人读，JSON 适合系统消费和调试。JSON 里有 `tool_trace`、输入参数、运行时配置和 Agent messages，以后做前端工作台时可以直接复用。

### Q14：这个项目和普通日志分析脚本有什么区别？

普通脚本通常是固定规则和固定字段提取。这个项目有模型风险线索、Wazuh/Zeek/Suricata 多源关联、RAG 安全知识检索，以及 LLM Agent 的工具调用和报告生成。

### Q15：目前最大不足是什么？

目前更偏 CLI 验证和研判原型。真实生产还需要更稳定的 Zeek 实时采集、更大的 RAG 知识库、前端展示、权限管理、任务调度和报告质量评估。

## 8. 你可以现场演示的命令

进入项目：

```bash
cd /opt/mineshark_agent
source .venv/bin/activate
```

构建 RAG：

```bash
python scripts/rag/build_index.py --env-file .env
```

运行 Agent：

```bash
sudo /opt/mineshark_agent/.venv/bin/python scripts/agent/run_agent_audit.py --env-file .env --max-events 5
```

查看报告：

```bash
sed -n '1,160p' outputs/reports/agent_audit_report.md
```

查看工具轨迹：

```bash
python3 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path("outputs/reports/agent_audit_report.json").read_text(encoding="utf-8"))
for item in data.get("tool_trace", []):
    print(item.get("tool"), item.get("arguments"))
PY
```

## 9. 你自己的复述模板

你可以按这个顺序练：

```text
我这个项目主要做加密流量安全研判。
第一步，已有 MineShark AI 引擎从 live log 读取流量元数据，用 Transformer 输出 AI 告警。
第二步，Wazuh 监听 /var/log/ai_alerts.json，把 AI 告警纳入 Wazuh 告警体系。
第三步，我在 demo_jianli 分支里实现 LangGraph Agent，旁路读取 AI 告警、Wazuh、Zeek、Suricata 和 RAG。
第四步，Agent 调用 DeepSeek 生成中文研判报告，同时保留 JSON 结构化结果和工具调用轨迹。
这个系统的重点不是自动处置，而是把模型风险线索变成有证据、有边界、可复核的安全研判报告。
```

## 10. 下一步可以继续补强什么

优先级从高到低：

1. 让 Zeek 在 WSL 环境里稳定产生实时 `conn.log`。
2. 构造一条同时有 AI 告警、Wazuh 告警、Zeek 上下文、Suricata 规则命中的完整演示案例。
3. 做前端工作台，展示 AI 告警、证据链、RAG 命中和报告。
4. 扩展 RAG 知识库。
5. 加入误报反馈和报告质量评估。

