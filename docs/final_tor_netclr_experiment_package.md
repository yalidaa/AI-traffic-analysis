# NetCLR Tor 最终实验证据包

## 用途

本文是当前最终实验包的 Git 索引。

当前任务口径：

```text
Tor 加密流量风险证据二分类基线。
```

本文不是 Tor 恶意检测、Tor 恶意用户检测，也不是 WFlib closed-world website fingerprinting 任务。WFlib CW 当前只作为备用工程能力。对外报告应将 NetCLR 作为可报告的二分类基线，并将模型输出表述为需要分析员复核的流量侧风险证据。

## 实验包位置

已提交的证据索引：

```text
docs/final_tor_netclr_experiment_package.md
```

本地忽略的实验包：

```text
outputs/final_tor_netclr_package/
```

本地实验包包含简要 README、指标摘要 JSON 和 PowerShell 复现命令。它不会重复保存原始数据集、大型 PPI CSV、模型 checkpoint，或包含逐样本记录的 8 MB 完整 `metrics.json`。

## 证据清单

| 证据 | 路径 | 状态 |
| --- | --- | --- |
| NetCLR inferior 原始压缩包 | `datasets/raw/tor/netclr/archives/NCDrift_inf.npz.zip` | 本地存在，已完成 MD5 校验 |
| NetCLR superior 原始压缩包 | `datasets/raw/tor/netclr/archives/NCDrift_sup.npz.zip` | 本地存在，已完成 MD5 校验 |
| Inferior 解压 NPZ | `datasets/raw/tor/netclr/extracted/NCDrift_inf/NCDrift_inf.npz` | 本地存在 |
| Superior 解压 NPZ | `datasets/raw/tor/netclr/extracted/NCDrift_sup/NCDrift_sup.npz` | 本地存在 |
| Smoke PPI inferior CSV | `datasets/experiments/ppi/tor/netclr_smoke/NCDrift_inf.csv` | 本地存在 |
| Smoke PPI superior CSV | `datasets/experiments/ppi/tor/netclr_smoke/NCDrift_sup.csv` | 本地存在 |
| 二分类负类视图 | `datasets/experiments/ppi/tor/netclr_drift_binary/normal/NCDrift_inf.csv` | 本地存在 |
| 二分类正类视图 | `datasets/experiments/ppi/tor/netclr_drift_binary/risk/NCDrift_sup.csv` | 本地存在 |
| 质量 JSON | `outputs/tor_data_runs/netclr_smoke/quality.json` | 本地存在 |
| 质量报告 | `outputs/tor_data_runs/netclr_smoke/quality.md` | 本地存在 |
| 最佳 checkpoint | `checkpoints/tor_netclr_drift_binary_gpu_v1.pt` | 本地存在 |
| 完整评估 JSON | `outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/metrics.json` | 本地存在 |
| 评估报告 | `outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/report.md` | 本地存在 |
| 最终本地摘要 | `outputs/final_tor_netclr_package/` | 生成实验包后本地存在 |

## 数据完整性

| 文件 | MD5 |
| --- | --- |
| `NCDrift_inf.npz.zip` | `1088195a92b4c94641bb468b2314b1bd` |
| `NCDrift_sup.npz.zip` | `0fef8c0bc7e88dc881798d47f61f91b5` |

## 任务语义

| 内部标签 | 报告标签 | 含义 |
| --- | --- | --- |
| `0` | `netclr_inferior_condition` | NetCLR inferior-condition trace 组，作为本二分类基线的负类侧。 |
| `1` | `netclr_superior_condition` | NetCLR superior-condition trace 组，作为本二分类基线的正类风险证据侧。 |

这些标签不是 `normal` 和 `malware`。它们是 NetCLR 网络条件变化下，用于流量侧风险证据分析的 condition-pair 基线。

## 质量摘要

数据质量输出：

```text
outputs/tor_data_runs/netclr_smoke/quality.json
outputs/tor_data_runs/netclr_smoke/quality.md
```

| 项目 | 数值 |
| --- | ---: |
| file_count | 2 |
| sample_count | 28312 |
| invalid_rows | 0 |
| class_count | 93 |
| average_sequence_length | 127.4774 |
| min_sequence_length | 22 |
| max_sequence_length | 128 |
| short_sample_count | 0 |
| empty_direction_sample_count | 0 |

`class_count = 93` 来自转换后 PPI 视图中保留的 NetCLR 原始类别 ID。最终二分类任务不会把这些 ID 当作多分类目标；可报告的二分类视图只是将两个 NetCLR condition 文件分组为负类和正类风险证据侧。

## 训练环境

记录的 GPU 训练环境：

```text
GPU: NVIDIA GeForce RTX 2060, 6 GB
Driver: 555.99
nvidia-smi CUDA runtime: 12.5
Python: `<GPU训练环境>\python.exe`
Torch: 2.5.1+cu121
torch.cuda.is_available(): True
```

项目 `.venv` 中是 CPU 版 Torch，不应用于 GPU 训练。

## 训练命令

```powershell
<GPU训练环境>\python.exe scripts/train/train_model.py `
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

训练摘要：

```text
Using device: cuda
total samples = 28312
best_epoch = 1
best_val_f1 = 0.7674
early stopping at epoch 4
```

最佳 checkpoint：

```text
checkpoints/tor_netclr_drift_binary_gpu_v1.pt
```

## 评估命令

```powershell
<GPU训练环境>\python.exe scripts/eval/run_tor_binary_eval.py `
  --checkpoint checkpoints/tor_netclr_drift_binary_gpu_v1.pt `
  --normal-dir datasets/experiments/ppi/tor/netclr_drift_binary/normal `
  --risk-dir datasets/experiments/ppi/tor/netclr_drift_binary/risk `
  --output-dir outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval `
  --negative-label-name netclr_inferior_condition `
  --positive-label-name netclr_superior_condition `
  --batch-size 256
```

评估输出：

```text
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/metrics.json
outputs/tor_data_runs/netclr_drift_binary_gpu_v1_eval/report.md
```

## 评估结果

| 指标 | 数值 |
| --- | ---: |
| sample_count | 28312 |
| threshold | 0.5664353179 |
| accuracy | 0.2946100593 |
| precision | 0.8290482634 |
| recall | 0.0857676155 |
| f1 | 0.1554531230 |
| fpr | 0.0550712002 |
| fnr | 0.9142323845 |
| tp | 1838 |
| fp | 379 |
| tn | 6503 |
| fn | 19592 |

分组摘要：

| 分组 | 数量 | Accuracy | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: |
| `NCDrift_inf.csv` | 6882 | 0.9449287998 | 0.0000000000 | 0.0550712002 | 0.0000000000 |
| `NCDrift_sup.csv` | 21430 | 0.0857676155 | 0.1579852157 | 0.0000000000 | 0.9142323845 |

## 结果解释

建议使用以下中文表述：

```text
在低误报约束下，NetCLR 二分类基线的 precision 较高，但 recall 很低。这说明模型可以输出一部分高置信流量侧风险证据，但漏检严重。因此当前结果适合用于风险证据优先级排序和辅助研判，不适合包装成成熟的 Tor 恶意检测系统。
```

## 最终结论不得超出的范围

不得声称：

- 模型可以检测恶意 Tor 用户。
- Tor 流量天然具有恶意性。
- WFlib single-tab 等同于二分类任务。
- 当前 recall 已足以支持生产检测。
- LLM/RAG 可以替代检测模型。

可以安全表述为：

- MineShark 可以将真实 Tor 相关流量数据集转换为 PPI 格式。
- NetCLR condition-pair 二分类基线可以生成流量侧风险证据。
- 当前运行点更偏向 precision，而不是 recall。
- Agent/RAG 层可以结合日志和安全手册辅助解释、复核模型证据。

## 报告生成器

`scripts/docs/build_competition_report.py` 默认读取本地摘要：

```text
outputs/final_tor_netclr_package/metrics_summary.json
```

如果本地摘要不存在，脚本会使用内置的 NetCLR 备用摘要和相同的主要指标，使匿名 DOCX 能够在干净检出环境中生成。
