# 项目结构

仓库采用 Python `src/` 布局，并同时包含传感器、Wazuh 接入、Agent、RAG、Console 和部署脚本。

```text
src/mineshark/
├── agent/          Agent 研判、证据聚合、预检查和质量检查
├── data/           数据准备和数据集读取
├── integrations/   Wazuh Server / Indexer 接入
├── models/         Transformer 模型结构
├── rag/            FAISS 索引和向量检索
├── reporting/      规则化报告和兼容报告入口
├── sensor/         抓包、流聚合、特征、推理、事件和状态
├── sensors/        AI 告警、Zeek、Suricata 数据读取
├── training/       模型训练和损失函数
└── web/            FastAPI API、Console、任务和案件数据库
```

## 目录职责

`src/mineshark/` 是可导入的 Python 包代码。

`scripts/` 是常用命令行工作流的薄封装，按 Agent、数据、部署、RAG 和训练分组。

`configs/` 保存传感器配置、环境模板、报告知识库和实验预设；真实密钥不应写入其中。

`deploy/` 保存 WSL 实验环境、独立 Sensor、Console、systemd、Wazuh 和 Nginx 的受管部署文件。

`docs/` 保存产品化路线、项目交接、部署验收、使用说明和已经明确标记的历史演示资料。

`tests/` 保存脱敏夹具和后端、传感器、Wazuh、案件、任务接口测试。

## 本地产物规则

大文件或运行时生成物只保留在本地：

```text
datasets/
checkpoints/
outputs/
```

源码、文档、配置模板、脚本和包元数据应提交到 Git；数据集、模型权重、报告、日志、RAG 索引和 Console SQLite 不应提交。
