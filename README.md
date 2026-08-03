# MineShark-Tor

> 当前分支的核心目标是优化 AI 流量分析算法模块，不是系统部署主线。`main` 负责集成可交付的系统功能；本分支负责数据、特征、模型、阈值和评估方法的迭代，经过验证的算法改动再整理合入 `main`。

MineShark-Tor 是 AI 流量分析算法模块当前使用的 Tor 加密流量行为识别研究场景。当前研究主线是：

> 面向早期观测与轻量部署的 Tor website fingerprinting / encrypted traffic behavior recognition。

项目目标不是检测“Tor 恶意用户”，也不是把 Tor 流量直接判定为攻击事实。MineShark-Tor 研究的是在不解密通信内容的前提下，基于 Tor trace 的方向序列、时间间隔、burst 结构和统计特征进行被动流量行为识别。

## 算法优化目标

本分支专门用于提高 AI 流量分析模块的准确性、稳定性和可解释性，重点包括：

- 数据集质量审计、标签核对、数据划分和可复现实验准备。
- 特征提取、模型训练、模型评估和模型版本记录。
- 决策阈值校准，尤其是低误报率约束下的 precision、recall、F1、FPR、FNR 和混淆矩阵分析。
- 误报样本、良性对照、跨条件变化和数据分布变化的专项评估。

训练分支中的准确率或 F1 提升不能脱离数据集、阈值和评估划分单独解读。小规模 smoke 结果只用于验证路径和代码，不作为论文或生产效果结论。

系统开发、Console、Wazuh 接入、案件管理和部署相关改动进入 `main`；训练产生的 checkpoint、数据集、日志和实验报告保留在本地，不提交到仓库。

## 当前阶段

当前阶段优先做 **Tor WF 权威数据集专项**，先保证算法训练和评估数据可靠，再进行模型结构和特征迭代。

原因是算法效果不能脱离数据来源和评估划分解读。第一阶段先筛选和验证数据集，再进入 DTB-Fusion 与完整实验。

核心文档：

```text
docs/tor_dataset_survey.md
docs/tor_dataset_decision.md
docs/tor_dataset_strategy.md
configs/datasets/tor_research_registry.json
```

本地数据报告：

```text
outputs/tor_dataset_inventory.md
```

`outputs/` 默认不进入 Git，报告需要在本地生成。

## 数据集策略

主数据集必须优先满足：

- 来自或被近年顶会论文使用，优先 USENIX Security、IEEE S&P、ACM CCS、NDSS、PAM。
- 支持 Tor website fingerprinting / encrypted traffic behavior recognition。
- 数据量足够支撑 closed-world 主实验。
- 最好还能支持 open-world、drift/cross-environment、multi-tab、defense robustness 或 subpage/generalization 中至少一种现实扩展。
- 有公开 artifact、清晰标签和可复现格式。

当前候选：

| 优先级 | 数据集 | 当前角色 |
| --- | --- | --- |
| P0 | NetCLR / NCDrift | realistic WF、跨条件、drift 主候选 |
| P0 | WFlib CW/OW | 标准化复现和 closed-world 备用主候选 |
| P1 | ARES / Multitab-WF-Datasets | 第二阶段 multi-tab 增强 |
| P1 | USENIX Security 2024 subpage-set WF | 真实浏览行为和子页面泛化参考 |
| P1 | PAM 2026 Tor WF dataset index | 数据集权威性索引 |
| P2 | AWF / DF / Wang14 / CUMUL | 经典 baseline 或 related work |

本地已有 NetCLR 和 WFlib，但它们只是候选，不能因为“刚好已有”就直接作为最终主数据。

## 论文路线

第一版论文建议题目方向：

```text
面向早期观测与轻量部署的 Tor 加密流量行为识别方法
```

英文可写为：

```text
Lightweight Early-Stage Tor Encrypted Traffic Recognition via Directional-Temporal-Burst Feature Fusion
```

计划中的方法：

- Direction sequence：方向序列，outgoing/incoming 编码为 +1/-1。
- Timing sequence：packet inter-arrival time。
- Burst features：连续同方向包形成的 burst 数量、长度、持续时间、方向切换等统计特征。
- DTB-Fusion：Direction + Timing + Burst 的轻量级融合模型。

计划中的实验：

- Closed-world 分类。
- Open-world 或 unknown-class 检测，视数据集是否支持。
- Direction / Timing / Burst 消融实验。
- Trace 长度实验：早期观测能力。
- 效率实验：参数量、推理时间、特征提取耗时。

## 项目结构

```text
configs/                  数据集 registry、报告配置、知识库配置
datasets/                 本地数据目录，默认不进入 Git
docs/                     论文路线、数据集策略、项目说明
scripts/data/             Tor trace/PPI 转换和数据质量检查入口
scripts/train/            训练入口
scripts/eval/             评估入口
src/mineshark/data/       数据加载、PPI 解析、数据集 registry
src/mineshark/models/     流量模型
src/mineshark/training/   训练逻辑
src/mineshark/evaluation/ 评估逻辑
tests/                    单元测试和小型 fixture
outputs/                  本地报告与实验输出，默认不进入 Git
```

Agent、RAG、Wazuh、Console 等原有能力仍保留，但它们现在是工程展示和简历加分项，不是第一篇论文的主贡献。

## 数据集专项命令

渲染数据集 registry 和本地 manifest：

```powershell
python scripts/data/render_tor_dataset_inventory.py `
  --local-manifest datasets/experiments/tor_manifest.local.json `
  --require-existing-paths `
  --output outputs/tor_dataset_inventory.md
```

检查 WFlib CW PPI：

```powershell
python scripts/data/check_tor_dataset_quality.py `
  --input datasets/experiments/ppi/tor/wflib_cw `
  --output-json outputs/tor_data_runs/wflib_cw_quality/quality.json `
  --output-md outputs/tor_data_runs/wflib_cw_quality/quality.md
```

检查 NetCLR PPI：

```powershell
python scripts/data/check_tor_dataset_quality.py `
  --input datasets/experiments/ppi/tor/netclr_smoke `
  --output-json outputs/tor_data_runs/netclr_multiclass_quality/quality.json `
  --output-md outputs/tor_data_runs/netclr_multiclass_quality/quality.md
```

## Tor PPI 转换

将 Tor website-fingerprinting JSONL/CSV/trace/NPZ/Numpy 序列转换为项目 PPI CSV：

```powershell
python scripts/data/prepare_tor_ppi.py `
  --input E:/datasets/tor/example `
  --output datasets/experiments/ppi/tor/example.csv `
  --default-app tor `
  --max-len 128
```

PPI 约定：

```text
PPI = [iat_sequence, direction_sequence, size_sequence]
APP = website / behavior label
SOURCE = trace 来源标识
```

## 训练与评估入口

当前已有 Tor 多分类 baseline：

```powershell
python scripts/train/train_tor_multiclass.py --preset tor_cw_multiclass --cpu
```

评估 checkpoint：

```powershell
python scripts/eval/run_tor_multiclass_eval.py `
  --checkpoint checkpoints/tor_cw_multiclass_baseline.pt `
  --data-dir datasets/experiments/ppi/tor/wflib_cw `
  --output-dir outputs/tor_data_runs/cw_multiclass_baseline `
  --max-samples-per-class 20 `
  --cpu
```

完整 DTB-Fusion、消融矩阵和 trace 长度实验将在数据集专项完成后实现。

## 安全与论文表述边界

论文和答辩中必须坚持：

- Tor 是匿名通信系统，Tor 用户不等于恶意用户。
- 本项目研究被动加密流量行为识别，不做主动攻击系统。
- 不把 NetCLR condition pair 说成 normal/malicious。
- MineShark-Tor 输出的是模型预测和实验指标，不是自动安全处置结论。
- 自采 Tor 数据暂不作为第一篇小论文的必要条件，只作为原型系统展示。

## 开发与测试

安装基础包：

```powershell
pip install -e .
```

训练和评估需要 ML 依赖：

```powershell
pip install -e ".[ml]"
```

运行测试：

```powershell
pytest
```

格式检查：

```powershell
ruff check src tests
ruff format --check src tests
```

## Git 跟踪策略

仓库只跟踪代码、配置、测试和文档。以下内容默认不进入 Git：

- 原始数据集和 packet captures。
- 转换后的 PPI CSV。
- checkpoint。
- outputs 下的实验报告。
- 本地虚拟环境和缓存。

这能保证仓库保持轻量，同时本地保留论文实验所需的数据和运行产物。
