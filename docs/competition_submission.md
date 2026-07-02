# MineShark 第七题参赛提交说明

## 当前比赛主线

当前参赛口径定为：

**MineShark：面向 Tor 加密流量风险证据识别与大模型辅助研判系统。**

核心任务不是“检测 Tor 恶意用户”，也不是把 Tor 流量直接判为攻击事实。当前阶段要讲清楚的是：

- Tor 是匿名加密通信协议，本身不是恶意行为。
- Tor 用户不等于恶意用户。
- 模型输出是流量侧风险证据，不是最终攻击定性。
- LLM/RAG/Agent 是解释、聚合和报告层，不替代检测模型。
- 单标签页不等于二分类；WFlib CW 是 95 类 closed-world 网站指纹任务，不是当前最终主线。

## 数据与任务口径

当前最终实验主线回到 NetCLR Tor 二分类风险证据基线：

| 项目 | 当前口径 |
| --- | --- |
| 数据 | `NCDrift_inf.csv` vs `NCDrift_sup.csv` |
| 训练视图 | `datasets/experiments/ppi/tor/netclr_drift_binary/normal` vs `datasets/experiments/ppi/tor/netclr_drift_binary/risk` |
| 标签 0 | `netclr_inferior_condition` |
| 标签 1 | `netclr_superior_condition` |
| 模型 | Transformer 二分类 |
| 解释 | NetCLR 网络条件漂移下的风险证据基线，不是恶意/正常标签 |

WFlib CW 单标签页链路已经保留在仓库中，但它应作为备用实验和工程能力证明：

| 项目 | 说明 |
| --- | --- |
| 数据 | `datasets/experiments/ppi/tor/wflib_cw/CW.csv` |
| 天然任务 | 95 类 closed-world website fingerprinting |
| 当前定位 | 备用能力，不作为最终二分类主线 |
| 可讲价值 | 证明项目能处理真实 Tor 单标签页数据、质量检查、训练和评估 |

## NetCLR 最终实验包

数据来源与边界：

```text
datasets/raw/tor/netclr/archives/NCDrift_inf.npz.zip
datasets/raw/tor/netclr/archives/NCDrift_sup.npz.zip
datasets/raw/tor/netclr/extracted/NCDrift_inf/NCDrift_inf.npz
datasets/raw/tor/netclr/extracted/NCDrift_sup/NCDrift_sup.npz
```

PPI 转换与训练视图：

```text
datasets/experiments/ppi/tor/netclr_smoke/NCDrift_inf.csv
datasets/experiments/ppi/tor/netclr_smoke/NCDrift_sup.csv
datasets/experiments/ppi/tor/netclr_drift_binary/normal/NCDrift_inf.csv
datasets/experiments/ppi/tor/netclr_drift_binary/risk/NCDrift_sup.csv
```

质量检查结果：

```text
sample_count = 28312
invalid_rows = 0
class_count = 93
average_sequence_length ~= 127.48
min_sequence_length = 22
max_sequence_length = 128
```

训练命令：

```powershell
D:\Learningformore\Anaconda\envs\traffic_env\python.exe scripts/train/train_model.py `
  --experiment custom `
  --data-format ppi `
  --benign-dir datasets/experiments/ppi/tor/netclr_drift_binary/normal `
  --malware-dir datasets/experiments/ppi/tor/netclr_drift_binary/risk `
  --save-path checkpoints/tor_netclr_drift_binary_gpu_v1.pt `
  --negative-label-name netclr_inferior_condition `
  --positive-label-name netclr_superior_condition `
  --epochs 10 `
  --batch-size 128 `
  --embed-dim 128 `
  --num-heads 4 `
  --num-layers 2 `
  --ff-dim 256 `
  --split-mode random `
  --target-fpr 0.05
```

评估输出：

```text
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/metrics.json
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/report.md
```

当前最佳结果：

| 指标 | 数值 |
| --- | ---: |
| sample_count | 28312 |
| threshold | 0.5664 |
| accuracy | 0.2946 |
| precision | 0.8290 |
| recall | 0.0858 |
| f1 | 0.1555 |
| fpr | 0.0551 |
| fnr | 0.9142 |
| tp | 1838 |
| fp | 379 |
| tn | 6503 |
| fn | 19592 |

结论表述：

低误报约束下 precision 较高，说明模型能给出一部分高置信风险证据；但 recall 很低，说明漏检严重。当前结果适合被包装成“风险证据二分类基线”和“辅助研判输入”，不适合被包装成成熟的 Tor 恶意检测系统。

## 命题定位

参赛方向：第七题“面向加密通信协议的恶意行为检测技术”。

作品名称建议使用：MineShark：面向加密通信协议的风险证据识别与大模型辅助研判系统。

本项目的主线是：在不解密 TLS/SSH/Tor 等加密通信明文的前提下，基于连接元数据、包长序列、方向序列、包间隔、端口和多源安全日志识别风险线索。LLM/RAG/Agent 只作为辅助研判、报告生成和可解释审计能力，不把作品包装成 API 安全审计、源代码漏洞审计或自动化定责系统。

## 赛题成果对齐

| 赛题要求 | MineShark 对应能力 | 主要证据 |
| --- | --- | --- |
| 加密通信流量分析工具 | 读取 MineShark/Zeek/Wazuh/Suricata 日志，聚合连接元数据和告警上下文 | `src/mineshark/sensors/`、`src/mineshark/agent/toolbox.py` |
| 异常行为检测规则或模型 | Transformer 风险分、阈值校准、NetCLR 二分类基线、竞赛场景评估指标 | `src/mineshark/training/train.py`、`scripts/eval/run_tor_binary_eval.py`、`scripts/eval/run_competition_eval.py` |
| 正常流量与风险流量对比 | 覆盖普通加密通信、Tor 条件漂移风险证据、C2 Beacon、加密隧道、SSH 暴力破解后行为 | `tests/fixtures/competition_scenarios/scenarios.jsonl`、`docs/tor_dataset_strategy.md` |
| 可解释研判 | Wazuh、Zeek、Suricata、RAG playbook 与 `tool_trace` 形成证据链 | `scripts/agent/run_agent_audit.py`、`scripts/agent/run_offline_fixture_demo.py` |

## 评测复现

运行竞赛评测：

```bash
python scripts/eval/run_competition_eval.py \
  --scenario-dir tests/fixtures/competition_scenarios \
  --output-dir outputs/competition \
  --threshold 0.70
```

输出文件：

```text
outputs/competition/metrics.json
outputs/competition/comparison.md
outputs/competition/table_data.csv
```

默认 fixture 包含 10 条脱敏样本：5 条正常样本、5 条攻击样本。默认阈值 0.70 下包含一个误报样例和一个漏报样例，用于在作品报告中解释“模型概率是风险线索，不等于攻击事实”。

## 演示路径

### 离线 fallback 演示

离线演示不依赖 DeepSeek、DashScope、Wazuh API 或 FAISS 索引，适合现场网络不可用时使用：

```bash
python scripts/agent/run_offline_fixture_demo.py \
  --fixture-dir tests/fixtures/demo_event \
  --output-dir outputs/offline_demo
```

输出文件：

```text
outputs/offline_demo/offline_agent_report.json
outputs/offline_demo/offline_agent_report.md
```

该报告保留与正式 Agent 相同的核心结构：`preflight`、`evidence_bundle`、`quality_checks`、`tool_trace` 和 `markdown_report`。RAG 在没有 FAISS 索引时会降级读取本地 `knowledge.jsonl`，并在结果中标记 `jsonl_fallback`。

### Live Wazuh/WSL 演示

Live 演示用于展示真实安全平台链路：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\agent\run_wsl_cli_agent_demo.ps1
```

验收链路：

```text
MineShark AI 告警 -> /var/log/ai_alerts.json
  -> Wazuh rule 100500
  -> Agent 查询 Wazuh/Zeek/Suricata/RAG
  -> outputs/reports/agent_audit_report.json
  -> outputs/reports/agent_audit_report.md
  -> MineShark Console 展示
```

Live 演示前必须确认 Wazuh 发行版、Indexer、Manager、Dashboard、Filebeat、Suricata、SSH、项目虚拟环境和 `.env` 均可用。

## 作品报告材料

报告应使用附件 2 模板结构：

1. 摘要
2. 第一章 作品概述
3. 第二章 作品设计与实现
4. 第三章 作品测试与分析
5. 第四章 创新性说明
6. 第五章 总结
7. 参考文献

报告必须匿名，不出现学校、院系、指导教师、队员姓名、手机号、邮箱、API Key、服务器公网地址等身份或敏感信息。建议保留如下图表：

- 系统架构图：MineShark AI、Wazuh、Zeek、Suricata、RAG、Agent、Console。
- 检测流程图：元数据提取、模型判定、阈值校准、多源证据关联。
- NetCLR 实验表：数据来源、转换流程、质量检查、训练参数、评估指标和失败解释。
- WFlib 备用链路说明：单标签页 Tor 数据处理能力，不作为二分类主线。
- 指标表：Accuracy、Precision、Recall、F1、FPR、混淆矩阵。
- 报告样例截图：Markdown 报告和 JSON `tool_trace`。

可用以下命令生成匿名版 DOCX 初稿：

```bash
python scripts/docs/build_competition_report.py \
  --metrics-json outputs/competition/metrics.json \
  --output "E:/哈工大比赛文件/哈工大比赛文件/MineShark_第七题作品报告_匿名版.docx"
```

生成后仍需要团队按报名系统要求补充真实联系人、签字、盖章等非匿名表格材料；这些信息不要写入代码仓库。

## 提交前检查清单

- `python -m unittest discover -v`
- `python scripts/eval/run_competition_eval.py --scenario-dir tests/fixtures/competition_scenarios --output-dir outputs/competition --threshold 0.70`
- `python scripts/agent/run_offline_fixture_demo.py --fixture-dir tests/fixtures/demo_event --output-dir outputs/offline_demo`
- `uv run ruff check src tests`
- `uv run ruff format --check src tests`
- `uv run pytest`
- `cd web/frontend && npm run build`
- 人工检查 DOCX：无模板说明文字、无身份信息、无乱码、无表格溢出。

## 边界表述

建议在答辩中主动说明：

- MineShark 输出风险线索和辅助研判报告，不输出最终攻击定性。
- 当前阶段不声称“检测 Tor 恶意用户”。
- WFlib CW 是单标签页 95 类网站指纹备用实验，不是二分类主线。
- 系统不自动封禁 IP、不隔离主机、不写回 Wazuh 状态、不修改防火墙。
- 模型误报和漏报受业务流量、网络条件、数据来源差异和标签定义影响，需要人工复核。
- LLM 负责组织证据和生成报告，不替代检测模型，也不直接读取全部日志做黑盒判断。
