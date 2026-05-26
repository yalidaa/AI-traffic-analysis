# MineShark 训练依赖管理说明

本文档专门记录 `TrafficDetection_LLM` 训练、数据准备和评估相关的 Python 库，避免把训练依赖、Agent 报告依赖和数据集工具混在一起。

## 当前环境

项目当前使用的 Conda 环境：

```text
traffic_env
```

当前 `python` 指向：

```text
D:\Learningformore\Anaconda\envs\traffic_env\python.exe
```

当前已验证的关键库版本：

```text
torch==2.5.1+cu121
numpy==2.2.6
scikit-learn==1.7.2
scipy==1.15.3
pandas==2.3.3
requests==2.32.5
cesnet-datazoo==0.1.15
```

## 训练核心依赖

这些库是运行 `train_ai.py`、`dataset.py`、`model.py`、`loss.py` 的核心依赖。

| 库 | 用途 | 对应代码 |
| --- | --- | --- |
| `torch` | Transformer 模型、DataLoader、优化器、checkpoint 读写 | `model.py`, `loss.py`, `train_ai.py`, `dataset.py` |
| `numpy` | 包间隔裁剪、数据增强、PPI 解析兜底 | `dataset.py` |
| `scikit-learn` | train/val/test 切分、accuracy/F1/report 指标 | `dataset.py`, `train_ai.py` |

最低建议版本：

```text
torch>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
```

当前项目在 `torch==2.5.1+cu121` 上已验证可用。

## 数据准备依赖

本地 Zeek/MineShark 日志转 PPI 主要使用 Python 标准库，不需要额外安装：

```text
argparse
csv
glob
json
gzip
os
pathlib
shutil
```

涉及脚本：

```text
prepare_ppi_from_logs.py
prepare_malware_ppi_from_logs.py
prepare_experiment_data.py
```

注意：`prepare_experiment_data.py` 当前内部使用了 `shutil.rmtree` 清空输出目录。根据本项目操作规则，不应直接运行会递归删除目录的命令或脚本逻辑；如需重建实验数据目录，建议先手动确认/清理目标目录，或后续改造脚本为非递归安全模式。

## CESNET 数据集依赖

只有在导出或 smoke test CESNET 数据集时需要：

```text
cesnet-datazoo
pandas
```

涉及脚本：

```text
prepare_cesnet_benign.py
smoke_cesnet_tls_year22.py
```

用途：

- 下载/读取 `CESNET_TLS_Year22`
- 可选读取 `CESNET_QUIC22`
- 导出带 `PPI` 字段的 benign CSV

如果只训练已经导出的本地 CSV/PPI 文件，不需要重新运行 `cesnet-datazoo`。

## Agent 报告模块依赖

`agent_reporter/agent_audit.py` 属于推理与报告生成模块，不是训练必需项。

依赖记录在：

```text
agent_reporter/requirements-agent.txt
```

主要包括：

```text
requests>=2.31.0
scikit-learn>=1.3.0
torch>=2.0.0
```

用途：

- 加载训练好的 checkpoint
- 对日志连接做推理
- 使用 TF-IDF 检索本地安全知识库
- 可选调用 DeepSeek OpenAI-compatible API 生成中文报告

## 推荐安装方式

如果复现当前训练环境，优先使用已有的 Conda 环境文件：

```powershell
conda env create -f traffic_env.yaml
conda activate traffic_env
```

如果只想在已有环境中补齐训练核心依赖：

```powershell
pip install torch numpy scikit-learn
```

如果需要运行 CESNET 导出脚本：

```powershell
pip install cesnet-datazoo pandas
```

如果需要运行 Agent 报告模块：

```powershell
pip install -r agent_reporter/requirements-agent.txt
```

## 快速验证

在 `TrafficDetection_LLM` 目录下运行：

```powershell
python - <<'PY'
import torch
import numpy
import sklearn

print("torch:", torch.__version__)
print("cuda_available:", torch.cuda.is_available())
print("numpy:", numpy.__version__)
print("sklearn:", sklearn.__version__)
PY
```

如果还需要验证 CESNET 工具：

```powershell
python - <<'PY'
import importlib.metadata as md
print("cesnet-datazoo:", md.version("cesnet-datazoo"))
PY
```

## 文件分工

```text
traffic_env.yaml
```

记录 Conda 环境快照，适合完整复现当前机器环境。

```text
TRAINING_DEPENDENCIES.md
```

记录训练相关依赖的角色、用途、安装建议和注意事项。

```text
agent_reporter/requirements-agent.txt
```

记录报告生成模块的轻量运行依赖。
