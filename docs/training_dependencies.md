# MineShark 训练依赖管理说明

本文档记录 `TrafficDetection_LLM` 重构后的训练、数据准备和报告生成依赖。项目源码位于 `src/mineshark/`，命令入口位于 `scripts/`。

## 当前环境

当前使用的 Conda 环境：

```text
traffic_env
```

环境快照文件：

```text
configs/env/traffic_env.yaml
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

| 库 | 用途 | 对应模块 |
| --- | --- | --- |
| `torch` | Transformer 模型、DataLoader、优化器、checkpoint 读写 | `src/mineshark/models/`, `src/mineshark/training/` |
| `numpy` | 包间隔裁剪、数据增强、PPI 解析兜底 | `src/mineshark/data/dataset.py` |
| `scikit-learn` | train/val/test 切分、accuracy/F1/report 指标 | `src/mineshark/data/dataset.py`, `src/mineshark/training/train.py` |

建议最低版本：

```text
torch>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
```

## 数据准备依赖

本地 MineShark/Zeek 日志转 PPI 主要使用 Python 标准库：

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

涉及模块：

```text
src/mineshark/data/prepare_ppi_from_logs.py
src/mineshark/data/prepare_malware_ppi_from_logs.py
src/mineshark/data/prepare_experiment_data.py
```

注意：`prepare_experiment_data.py` 已调整为不自动递归清空非空目录。如果目标实验目录已有文件，脚本会停止并提示手动处理。

## CESNET 数据集依赖

只有在导出或 smoke test CESNET 数据集时需要：

```text
cesnet-datazoo
pandas
```

涉及模块：

```text
src/mineshark/data/prepare_cesnet_benign.py
src/mineshark/data/smoke_cesnet_tls_year22.py
```

如果只训练已经导出的本地 CSV/PPI 文件，不需要重新运行 `cesnet-datazoo`。

## Agent 报告模块依赖

报告生成模块位于：

```text
src/mineshark/reporting/agent_audit.py
scripts/report/generate_audit_report.py
```

主要依赖：

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

完整复现 Conda 环境：

```powershell
conda env create -f configs/env/traffic_env.yaml
conda activate traffic_env
```

本地开发安装：

```powershell
pip install -e .
```

只补齐训练核心依赖：

```powershell
pip install torch numpy scikit-learn
```

需要 CESNET 导出能力时：

```powershell
pip install cesnet-datazoo pandas
```

## 快速验证

在项目根目录下运行：

```powershell
python - <<'PY'
import torch
import numpy
import sklearn
import mineshark

print("mineshark:", mineshark.__version__)
print("torch:", torch.__version__)
print("cuda_available:", torch.cuda.is_available())
print("numpy:", numpy.__version__)
print("sklearn:", sklearn.__version__)
PY
```

如果尚未执行 `pip install -e .`，可以临时设置：

```powershell
$env:PYTHONPATH="src"
```
