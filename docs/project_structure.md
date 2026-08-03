# 项目结构

仓库采用 Python `src/` 布局，训练分支主要维护数据、模型、评估和算法实验相关代码。

```text
src/mineshark/
├── data/          数据读取、数据准备、Tor PPI 转换和质量检查
├── evaluation/    二分类、多分类和竞赛场景评估
├── models/        Transformer 等模型结构
├── reporting/     兼容报告和模型输出审计
└── training/      训练入口、损失函数、阈值校准和多分类训练
```

## 目录职责

`src/mineshark/` 是可导入的 Python 包代码。

`scripts/` 是数据准备、训练、评估、报告和部署检查的命令行入口。

`configs/` 保存数据集注册表、训练预设、报告知识库和环境模板；真实密钥不应写入其中。

`docs/` 保存训练分支说明、数据集决策、实验边界、部署资料和历史工程资料。

`tests/` 保存脱敏夹具以及数据、训练、评估、Agent、Wazuh 和 Console 测试。

## 本地产物规则

大文件或运行时生成物只保留在本地：

```text
datasets/
checkpoints/
outputs/
```

源码、文档、配置模板、脚本和包元数据应提交到 Git；数据集、模型权重、报告、日志、RAG 索引和前端构建产物不应提交。
