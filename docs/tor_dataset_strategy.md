# Tor 数据集策略

## 当前研究定位

MineShark-Tor 当前定位为面向算法优化和论文实验的 Tor website fingerprinting 与加密流量行为识别项目。

第一阶段**不是**模型创新，而是数据集专项阶段：

1. 筛选近年安全和网络领域高水平论文使用的权威 Tor WF 数据集；
2. 核验数据集可用性、规模、标签和可复现性；
3. 在实现 DTB-Fusion 和完整实验前确定主数据集。

这一步替代了早期以竞赛为先的做法，避免只把 NetCLR 描述成 condition-pair 二分类风险证据基线。

## 选择原则

论文主数据集应满足以下原则：

- 优先选择来自 USENIX Security、IEEE S&P、ACM CCS、NDSS 和 PAM 的数据源。
- 支持 Tor website fingerprinting 或 Tor 加密流量行为识别。
- 支持 closed-world 评估，并最好覆盖一种现实扩展：open-world、漂移/跨环境、多标签页、防御鲁棒性或子页面/泛化。
- 具有公开 artifact、清晰标签，以及可转换为 MineShark PPI/trace 的格式。
- 不因为数据集已经存在于本地就直接选用。

## 候选优先级

| 优先级 | 数据集系列 | 角色 |
| --- | --- | --- |
| P0 | NetCLR / NCDrift | realistic WF、跨条件和漂移评估的主候选。 |
| P0 | WFlib CW/OW | 可复现的 closed-world 备用数据和标准 artifact 基线。 |
| P1 | ARES / Multitab-WF-Datasets | 第一阶段论文流水线稳定后的多标签页扩展。 |
| P1 | USENIX Security 2024 subpage-set WF | 数据多样性和真实浏览行为的方法论参考。 |
| P1 | PAM 2026 Tor WF dataset index | 数据集发现和权威性核验。 |
| P2 | AWF / DF / Wang14 / CUMUL | 经典基线和相关工作参考，不作为最新权威主线。 |

## 本地数据状态

已跟踪的元数据位于：

```text
configs/datasets/tor_research_registry.json
datasets/experiments/tor_manifest.local.json
```

本地数据不进入 Git 跟踪。

当前本地候选：

| 数据集 | 本地状态 | 用途 |
| --- | --- | --- |
| NetCLR / NCDrift | 原始压缩包、解压 NPZ 和 PPI CSV 已存在。 | 第一候选；需要继续核验原始数据是否支持 website-class、跨条件和 trace 长度实验。 |
| WFlib CW | 原始压缩包、解压 NPZ 和 95 类 PPI CSV 已存在。 | closed-world 复现和备用主数据集。 |
| AWF | 目录存在但没有文件。 | 尚未准备好，不得声称本地已有可用数据集。 |
| ARES / multi-tab | 尚未下载。 | 保留为第二阶段候选。 |

## 必要报告

数据集阶段应生成并保留以下本地报告：

```powershell
python scripts/data/render_tor_dataset_inventory.py `
  --local-manifest datasets/experiments/tor_manifest.local.json `
  --require-existing-paths `
  --output outputs/tor_dataset_inventory.md
```

转换后 PPI 的质量检查：

```powershell
python scripts/data/check_tor_dataset_quality.py `
  --input datasets/experiments/ppi/tor/wflib_cw `
  --output-json outputs/tor_data_runs/wflib_cw_quality/quality.json `
  --output-md outputs/tor_data_runs/wflib_cw_quality/quality.md
```

NetCLR 需要同时检查旧二分类视图和多分类视图：

```powershell
python scripts/data/check_tor_dataset_quality.py `
  --input datasets/experiments/ppi/tor/netclr_smoke `
  --output-json outputs/tor_data_runs/netclr_multiclass_quality/quality.json `
  --output-md outputs/tor_data_runs/netclr_multiclass_quality/quality.md
```

## 数据集决策门槛

满足以下条件后才能进入 DTB-Fusion：

- `docs/tor_dataset_survey.md` 已记录候选数据集比较。
- `docs/tor_dataset_decision.md` 已说明主数据集和辅助数据集选择。
- `outputs/tor_dataset_inventory.md` 在本地存在。
- 选定本地数据集已有 PPI 质量报告。
- README 已说明数据集选择经过专项筛选。

## 表述边界

论文和答辩材料使用以下表述：

- Tor 是匿名通信系统，Tor 用户默认不等于恶意用户。
- 本项目研究被动加密流量行为识别和 website fingerprinting。
- 数据集权威性、可复现性和现实假设是实验的一等要求。
- NetCLR condition 文件不得描述为 normal 与 malicious 标签。
- MineShark-Tor 自采 trace 是可选的系统展示数据，不是第一篇论文必须使用的主数据集。
