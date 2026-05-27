# MineShark 系统流程图

这份文档用于把 `demo_jianli` 分支从黑盒拆开。建议阅读顺序：

1. 先看“图 1：系统总览图”，理解 WSL Wazuh、MineShark AI、Wazuh、RAG、Agent 之间怎么连。
2. 再看“图 2：代码文件职责图”，理解每个关键文件在项目里做什么。
3. 最后看“图 3：一次完整研判数据流图”，理解一条 AI 告警如何变成最终中文报告。

## 图 1：系统总览图

这张图回答：整个系统有哪些组件，数据从哪里来，到哪里去。

```mermaid
flowchart LR
    subgraph WSL["WSL2 发行版：Wazuh"]
        subgraph Sensors["安全传感器与原始日志"]
            Zeek["Zeek<br/>/opt/zeek/spool/zeek/conn.log"]
            Suricata["Suricata<br/>/var/log/suricata/eve.json"]
            WazuhLogs["Wazuh 本地告警<br/>/var/ossec/logs/alerts/alerts.json"]
        end

        subgraph RealtimeAI["现有实时 AI 检测层"]
            LiveLog["MineShark live log<br/>/root/mineshark_lab/mineshark_live.log"]
            Predict["predict_scan.py<br/>/opt/mineshark_lab/ai_engine/predict_scan.py"]
            Model["Transformer 模型<br/>deep_mineshark_best.pt"]
            AIAlerts["AI 告警 JSONL<br/>/var/log/ai_alerts.json"]
            Timer["systemd timer<br/>mineshark-ai.timer"]
        end

        subgraph WazuhStack["Wazuh 平台"]
            Manager["Wazuh Manager<br/>Server API :55000"]
            Indexer["Wazuh Indexer<br/>Indexer API :9200"]
            Dashboard["Wazuh Dashboard<br/>https://localhost"]
        end

        subgraph AgentProject["MineShark Agent 项目<br/>/opt/mineshark_agent"]
            Env[".env<br/>API Key 与路径配置"]
            RAGBuild["scripts/rag/build_index.py"]
            RAGIndex["FAISS 索引<br/>outputs/rag/"]
            AgentCLI["scripts/agent/run_agent_audit.py"]
            Toolbox["AgentToolbox<br/>src/mineshark/agent/toolbox.py"]
            Reports["研判报告<br/>outputs/reports/*.json + *.md"]
        end
    end

    subgraph Cloud["外部云服务"]
        DashScope["DashScope Embedding<br/>text-embedding-v4"]
        DeepSeek["DeepSeek Chat LLM<br/>deepseek-chat"]
    end

    Timer --> Predict
    LiveLog --> Predict
    Model --> Predict
    Predict --> AIAlerts
    AIAlerts --> Manager
    Manager --> Indexer
    Indexer --> Dashboard

    Env --> RAGBuild
    RAGBuild --> DashScope
    RAGBuild --> RAGIndex

    Env --> AgentCLI
    AgentCLI --> Toolbox
    Toolbox --> AIAlerts
    Toolbox --> Manager
    Toolbox --> Indexer
    Toolbox --> WazuhLogs
    Toolbox --> Zeek
    Toolbox --> Suricata
    Toolbox --> RAGIndex
    Toolbox --> DashScope
    AgentCLI --> DeepSeek
    DeepSeek --> Reports
```

### 图 1 怎么讲给面试官

这个项目采用旁路研判架构。原有实时检测链路不被替换：`mineshark-ai.timer` 定时调用 `/opt/mineshark_lab/ai_engine/predict_scan.py`，读取 MineShark live log，用 `deep_mineshark_best.pt` 推理，再把 AI 告警追加到 `/var/log/ai_alerts.json`。Wazuh 已经监听这个文件，所以 AI 告警会被 Wazuh 摄取并触发规则。

新增的 `demo_jianli` 分支代码位于 `/opt/mineshark_agent`。它不写回 Wazuh，不做自动封禁，只读取 AI 告警、Wazuh API、Wazuh Indexer、Zeek、Suricata 和本地 RAG 索引，然后交给 DeepSeek + LangGraph Agent 生成中文研判报告。

## 图 2：代码文件职责图

这张图回答：项目里每个关键文件干什么，被谁调用。

```mermaid
flowchart TB
    subgraph Entry["命令入口"]
        ScriptAgent["scripts/agent/run_agent_audit.py<br/>薄入口：把项目 src 加入 sys.path，然后调用 Agent CLI"]
        ScriptRAG["scripts/rag/build_index.py<br/>薄入口：调用 RAG 构建 CLI"]
        ScriptLegacy["scripts/report/generate_audit_report.py<br/>旧版离线报告入口，需要可选 ML 依赖"]
        ScriptTrain["scripts/train/train_model.py<br/>训练入口"]
    end

    subgraph Config["配置层"]
        PyProject["pyproject.toml<br/>依赖、可选 ML 依赖、命令行入口"]
        EnvExample[".env.example<br/>环境变量模板，不放真实密钥"]
        RuntimeConfig["src/mineshark/config.py<br/>读取 .env，解析路径、Wazuh、DeepSeek、DashScope 配置"]
    end

    subgraph Agent["Agent 编排层"]
        AgentCLI["src/mineshark/agent/cli.py<br/>解析 CLI 参数，创建 LangGraph ReAct Agent，写 JSON/Markdown 报告"]
        Toolbox["src/mineshark/agent/toolbox.py<br/>把 AI/Wazuh/Zeek/Suricata/RAG 封装成 LangChain tools，并记录 tool_trace"]
    end

    subgraph Tools["工具实现层"]
        AIReader["src/mineshark/sensors/ai_alerts.py<br/>读取 /var/log/ai_alerts.json，支持 JSON/JSONL、IP、时间、阈值过滤"]
        LogReader["src/mineshark/sensors/logs.py<br/>读取 Zeek conn.log 和 Suricata eve.json"]
        WazuhClient["src/mineshark/integrations/wazuh.py<br/>Wazuh Server API 认证、agent 查询、Indexer 告警查询、本地 alerts 回退"]
        RAGStore["src/mineshark/rag/store.py<br/>加载知识 JSONL，构建/读取 FAISS，执行相似度检索"]
        Embedder["src/mineshark/rag/embeddings.py<br/>调用 DashScope OpenAI-compatible embedding API"]
    end

    subgraph DataModel["模型与数据层"]
        ModelCode["src/mineshark/models/traffic_transformer.py<br/>Transformer 流量分类模型结构"]
        LegacyAudit["src/mineshark/reporting/agent_audit.py<br/>旧版离线模型推理与规则报告生成"]
        DataPrep["src/mineshark/data/*.py<br/>把 pcap/log 数据准备成训练或推理格式"]
        TrainCode["src/mineshark/training/*.py<br/>训练循环和 loss"]
    end

    subgraph Files["运行时文件"]
        Knowledge["configs/reporting/security_playbook.jsonl<br/>RAG 知识库原文"]
        RAGOut["outputs/rag/knowledge.faiss + metadata.json<br/>RAG 构建产物"]
        ReportOut["outputs/reports/agent_audit_report.json + .md<br/>Agent 输出产物"]
        Tests["tests/*.py<br/>单元测试：Wazuh、RAG、日志读取、Agent CLI"]
    end

    ScriptAgent --> AgentCLI
    ScriptRAG --> RAGStore
    ScriptLegacy --> LegacyAudit
    ScriptTrain --> TrainCode

    PyProject --> ScriptAgent
    PyProject --> ScriptRAG
    EnvExample --> RuntimeConfig
    RuntimeConfig --> AgentCLI
    RuntimeConfig --> RAGStore

    AgentCLI --> Toolbox
    Toolbox --> AIReader
    Toolbox --> LogReader
    Toolbox --> WazuhClient
    Toolbox --> RAGStore
    RAGStore --> Embedder

    RAGStore --> Knowledge
    RAGStore --> RAGOut
    AgentCLI --> ReportOut

    LegacyAudit --> ModelCode
    TrainCode --> ModelCode
    DataPrep --> TrainCode
    Tests --> AIReader
    Tests --> LogReader
    Tests --> WazuhClient
    Tests --> RAGStore
    Tests --> AgentCLI
```

### 关键文件职责表

| 文件 | 主要职责 | 输入 | 输出 | 被谁调用 |
|---|---|---|---|---|
| `pyproject.toml` | 定义包名、依赖、可选 ML 依赖和命令行入口 | 无 | `mineshark-agent-audit`、`mineshark-build-rag` 等入口 | `pip install -e .` |
| `.env.example` | 提供环境变量模板 | 无 | `.env` 的填写参考 | 人工复制 |
| `src/mineshark/config.py` | 读取 `.env`，把字符串配置转成 `RuntimeConfig` | `.env`、环境变量 | 路径、API URL、密钥、TLS 配置 | Agent CLI、RAG CLI、Wazuh/RAG 工具 |
| `scripts/rag/build_index.py` | RAG 构建脚本入口 | CLI 参数 | 调用 `mineshark.rag.build_index.main()` | 人工执行 |
| `src/mineshark/rag/build_index.py` | 加载知识库，调用 embedding，构建 FAISS | `security_playbook.jsonl`、`.env` | `outputs/rag/knowledge.faiss`、`metadata.json` | `scripts/rag/build_index.py` |
| `src/mineshark/rag/embeddings.py` | 调用 DashScope 向量模型 | 文本列表、`DASHSCOPE_API_KEY` | 向量列表 | RAG 构建与检索 |
| `src/mineshark/rag/store.py` | 管理知识记录、FAISS 建库和检索 | 知识 JSONL、query 文本 | 相似知识片段 | RAG CLI、Agent 工具箱 |
| `scripts/agent/run_agent_audit.py` | Agent 脚本入口 | CLI 参数 | 调用 `mineshark.agent.cli.main()` | 人工执行 |
| `src/mineshark/agent/cli.py` | 创建 LangGraph ReAct Agent，组织输入，写报告 | `.env`、CLI 参数、工具箱 | `agent_audit_report.json`、`.md` | Agent 脚本/命令行 |
| `src/mineshark/agent/toolbox.py` | 把各数据源封装成工具，并记录 `tool_trace` | RuntimeConfig、工具参数 | 结构化工具结果 | LangGraph Agent |
| `src/mineshark/sensors/ai_alerts.py` | 读取实时 AI 告警，支持 JSON/JSONL 和阈值过滤 | `/var/log/ai_alerts.json` | `alerts`、`matched`、`empty` | `query_mineshark_ai_alerts` 工具 |
| `src/mineshark/sensors/logs.py` | 读取 Zeek/Suricata 日志 | `conn.log`、`eve.json` | Zeek events、Suricata alerts | Agent 工具箱 |
| `src/mineshark/integrations/wazuh.py` | 对接 Wazuh Server API 与 Indexer API，失败时读本地 alerts | Wazuh API、Indexer API、本地 alerts | manager 状态、agents、alerts | Agent 工具箱 |
| `src/mineshark/reporting/agent_audit.py` | 旧版离线报告生成器，可选重新跑模型推理 | checkpoint、log 文件、知识库 | 旧版 JSON/Markdown 报告 | `mineshark-audit` 或 `--rerun-model` |
| `src/mineshark/models/traffic_transformer.py` | Transformer 模型结构 | 包长、方向、IAT 张量 | 分类 logits | 训练、旧版推理 |
| `src/mineshark/data/*.py` | 数据准备脚本 | pcap/log/数据集 | 训练或推理输入 | 数据处理命令 |
| `src/mineshark/training/*.py` | 模型训练逻辑 | 数据集、配置 | checkpoint | 训练入口 |
| `configs/reporting/security_playbook.jsonl` | 安全知识库 | 人工维护的 JSONL | RAG 记录 | RAG 构建 |
| `tests/*.py` | 单元测试 | mock HTTP、小日志、小知识库 | 测试结果 | `python -m unittest discover -v` |

## 图 3：一次完整研判数据流图

这张图回答：一条 MineShark AI 告警如何变成最终报告。

```mermaid
sequenceDiagram
    autonumber
    participant LiveLog as "/root/mineshark_lab/mineshark_live.log"
    participant Timer as "mineshark-ai.timer"
    participant Predict as "predict_scan.py"
    participant Model as "deep_mineshark_best.pt"
    participant AIFile as "/var/log/ai_alerts.json"
    participant Wazuh as "Wazuh Manager"
    participant Indexer as "Wazuh Indexer"
    participant AgentCLI as "run_agent_audit.py"
    participant Toolbox as "AgentToolbox"
    participant RAG as "FAISS RAG"
    participant DeepSeek as "DeepSeek Chat"
    participant Reports as "outputs/reports/*.json + *.md"

    Timer->>Predict: 定时启动实时 AI 扫描
    Predict->>LiveLog: 读取新增 MineShark 流量行
    Predict->>Model: 构造张量并执行 Transformer 推理
    Model-->>Predict: 返回恶意概率
    alt 概率 >= threshold
        Predict->>AIFile: 追加 JSONL 告警
        AIFile->>Wazuh: Wazuh logcollector 摄取
        Wazuh->>Indexer: 写入 wazuh-alerts-* 索引
    else 概率 < threshold
        Predict-->>Timer: 不写告警，只更新 state
    end

    AgentCLI->>Toolbox: 创建工具箱和 LangGraph tools
    AgentCLI->>DeepSeek: 发送系统提示和任务上下文
    DeepSeek->>Toolbox: 调用 query_mineshark_ai_alerts
    Toolbox->>AIFile: 读取 AI 告警
    AIFile-->>Toolbox: 返回模型风险线索

    DeepSeek->>Toolbox: 调用 query_wazuh_alerts
    Toolbox->>Indexer: 查询相关 Wazuh 告警
    alt Indexer 查询成功
        Indexer-->>Toolbox: 返回 Wazuh 告警证据
    else Indexer 查询失败
        Toolbox->>Wazuh: 回退读取 /var/ossec/logs/alerts/alerts.json
    end

    DeepSeek->>Toolbox: 调用 query_wazuh_agents
    Toolbox->>Wazuh: 查询 manager/status 与 agents
    Wazuh-->>Toolbox: 返回 Manager 和 Agent 状态

    DeepSeek->>Toolbox: 调用 query_zeek_context
    Toolbox->>Toolbox: 读取 /opt/zeek/spool/zeek/conn.log

    DeepSeek->>Toolbox: 调用 query_suricata_alerts
    Toolbox->>Toolbox: 读取 /var/log/suricata/eve.json

    DeepSeek->>Toolbox: 调用 retrieve_security_knowledge
    Toolbox->>RAG: 用 DashScope embedding 检索 FAISS
    RAG-->>Toolbox: 返回安全知识片段

    Toolbox-->>DeepSeek: 返回所有工具证据
    DeepSeek-->>AgentCLI: 生成中文研判报告正文
    AgentCLI->>Reports: 写入 JSON 报告和 Markdown 报告
```

### 图 3 对应我们已经跑通的实验

本次受控实验里，`/var/log/ai_alerts.json` 中生成了一条真实模型推理告警：

```json
{
  "engine": "deep_mineshark",
  "alert_type": "MineShark_Encrypted_Detection",
  "prediction": "Malware",
  "ai_confidence": 0.999951,
  "threshold": 0.5,
  "uid": "lab_replay_mineshark_20260527063525",
  "src_ip": "104.18.27.120",
  "src_port": 443,
  "dst_ip": "192.168.30.152",
  "dst_port": 57458,
  "proto": "tcp"
}
```

Wazuh 摄取后触发了规则：

```text
rule.id = 100500
rule.level = 12
rule.description = MineShark AI detected malicious encrypted traffic
location = /var/log/ai_alerts.json
```

Agent 报告生成后写入：

```text
/opt/mineshark_agent/outputs/reports/agent_audit_report.json
/opt/mineshark_agent/outputs/reports/agent_audit_report.md
```

## 当前系统边界

- Agent 默认读取 `/var/log/ai_alerts.json`，不重新跑模型。
- 只有加 `--rerun-model` 时，才会启用旧版 Transformer 推理工具。
- Agent 只读 Wazuh、Zeek、Suricata、RAG，不写回 Wazuh。
- 模型概率只能作为风险线索，不能直接当作攻击事实。
- `WAZUH_VERIFY_SSL=false` 是本地自签名证书开发模式，正式环境要配置 CA 并开启校验。

