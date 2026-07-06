# MineShark-Tor 数据集选择决策

## 决策结论

当前不把任何本地数据集直接宣布为最终主数据集。第一阶段采用“数据集先行”的策略：先把 NetCLR/NCDrift、WFlib CW、ARES、USENIX 2024 subpage-set、PAM 2026 Tor WF index 放在同一套标准下比较，再确定论文主实验数据。

阶段性默认组合如下：

| 角色 | 数据集 | 当前判断 |
| --- | --- | --- |
| 主候选 | NetCLR / NCDrift | 来自 ACM CCS 2023 相关工作，贴合 realistic WF、网络条件漂移和跨条件评估。本地已有原始数据和 PPI，可优先验证。 |
| 复现/备用主候选 | WFlib CW | ACM CCS 2024 artifact 相关数据，本地已有 105,730 条、95 类 PPI。适合做大规模 closed-world 复现实验。 |
| 第二阶段增强 | ARES / Multitab-WF-Datasets | IEEE S&P 2023 多标签页数据，权威但工程复杂度高，不作为第一阶段必要条件。 |
| 方法论参考 | USENIX Security 2024 subpage-set WF | 用于强调真实浏览行为、子页面、连续访问和数据多样性，不强制第一阶段训练。 |
| 数据集索引 | PAM 2026 Tor WF index | 用于确认公开数据源是否过旧或遗漏，不直接作为训练数据。 |

## 为什么不能直接用旧数据

之前的项目里已经有 NetCLR 和 WFlib，但“本地已有”不是论文数据选择理由。Tor WF 方向的审稿人通常会追问：

- 数据是否来自权威论文或公开 artifact？
- 是否支持 closed-world 之外的真实设置？
- 是否存在 open-world、drift、multi-tab、subpage、defense 等现实因素？
- 数据标签是否清楚，能否复现？
- 是否只是旧数据集上的简单特征融合？

因此，第一篇小论文不能写成“我们随便选了本地某个数据集”。更稳的写法是：

> 本文首先系统调研近年 Tor website fingerprinting 公开数据集，优先选择来自顶会或被顶会工作复用的数据源，并基于任务匹配度、数据规模、可复现性和现实因素覆盖情况确定实验数据。

## 第一阶段判定标准

第一阶段用 1 周完成以下判定：

1. **权威性**：是否来自 USENIX Security、IEEE S&P、ACM CCS、NDSS、PAM，或被这些会议近年论文反复使用。
2. **可复现性**：是否能下载，是否有清楚标签，是否能转换成 PPI/trace。
3. **任务匹配**：是否支持 Tor website fingerprinting / encrypted traffic behavior recognition。
4. **规模**：是否足够支撑 closed-world 主实验。
5. **现实扩展**：是否至少支持 open-world、drift/cross-environment、multi-tab、subpage/generalization、defense robustness 之一。
6. **成本**：下载大小、训练时间、工程改造复杂度是否适合“C 会毕业 + 9 月找实习”的现实节奏。

## 当前推荐路线

### 路线 A：NetCLR 主线

适合论文题目：

> 面向跨条件鲁棒性的 Tor 加密流量行为识别方法

优势：

- 近年顶会相关工作。
- 本地已有数据。
- 能和“真实网络条件变化、drift、少样本/跨环境”叙事结合。

风险：

- 需要把旧二分类风险线索口径改回 website-class 多分类或跨条件评估。
- Timing 信息在当前转换视图里可能不足，需要检查原始 NPZ 是否保留更丰富的时间/特征。

### 路线 B：WFlib CW 主线

适合论文题目：

> 面向早期观测与轻量部署的 Tor 加密流量行为识别方法

优势：

- 本地已有 95 类、105,730 条 PPI。
- closed-world 主实验最容易稳定跑通。
- 适合消融、trace 长度、效率实验。

风险：

- 如果只做 CW，真实性不足，需要加 open-world 或跨数据集补充。
- 容易被认为只是标准数据集上的模型复现。

### 路线 C：ARES multi-tab 增强

适合论文题目：

> 面向多标签页场景的 Tor 加密流量行为识别方法

优势：

- IEEE S&P 2023，多标签页真实性强。
- 方向新，和综述 future challenges 高度对齐。

风险：

- 需要 multi-label 数据加载、指标和模型改造。
- 对第一篇保毕业小论文来说风险偏高，建议第二阶段再做。

## 阶段性决策

第一阶段执行顺序：

1. 保留 NetCLR 和 WFlib 为 P0 候选，不立即宣布最终主数据。
2. 先检查 NetCLR 原始 NPZ 字段，判断是否能做 website-class 多分类、cross-condition split 和 trace length 实验。
3. 同时用 WFlib CW 生成完整质量报告，确认它作为 closed-world fallback 的稳定性。
4. 若 NetCLR 可支撑主线，则论文主数据选 NetCLR，WFlib 做复现实验。
5. 若 NetCLR 解释困难或 timing 信息不足，则主数据选 WFlib CW，NetCLR 做 drift/cross-condition 辅助实验。
6. ARES 暂不纳入第一阶段训练，只保留为后续增强方向。

## 论文表述边界

- 不说“Tor 用户是恶意用户”。
- 不说“检测 Tor 恶意流量”。
- 不把 NCDrift 的 condition pair 继续包装成 normal/malicious。
- 正确表述为：Tor encrypted traffic behavior recognition、Tor website fingerprinting、traffic metadata representation learning。
- 如果使用攻击术语，必须说明这是被动流量分析研究场景，不是主动攻击系统。
