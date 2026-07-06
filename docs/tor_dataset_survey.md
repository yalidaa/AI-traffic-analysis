# Tor WF 权威数据集调研表

本表用于 MineShark-Tor 毕业小论文的数据集专项。目标不是“本地有什么就用什么”，而是先确认数据集是否来自近年顶会、是否公开可复现、是否支撑 Tor website fingerprinting / encrypted traffic behavior recognition，再决定主实验数据。

## 筛选原则

- 优先来源：USENIX Security、IEEE S&P、ACM CCS、NDSS、PAM。
- 必须能支持 closed-world 主实验，最好还能支持 open-world、multi-tab、drift/cross-environment、defense robustness 或 subpage/generalization 之一。
- 必须有公开 artifact、清晰标签、可转换为本项目 PPI/trace 格式。
- AWF、DF、CUMUL、Wang14 等经典数据集可用于 baseline 或 related work，不作为“最新权威主线”的默认选择。

## 候选数据集表

| 论文/会议 | 年份 | 数据集名称 | 下载地址 | 任务类型 | 样本规模 | 类别数 | Open-world | Multi-tab | Drift/跨环境 | 可复现性 | 预计下载大小 | 是否适合本论文 |
| --- | ---: | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| ACM CCS, Realistic Website Fingerprinting by Augmenting Network Traces | 2023 | NetCLR / NCDrift | [ACM DOI](https://dl.acm.org/doi/10.1145/3576915.3616639), [GitHub](https://github.com/SPIN-UMass/Realistic-Website-Fingerprinting-By-Augmenting-Network-Traces), [WFlib Zenodo mirror](https://zenodo.org/records/13731720) | realistic WF, closed/open-world, drift/cross-condition | 本地已转 PPI：28,312 条；WFlib 记录 NCDrift_inf 6,882 条、NCDrift_sup 21,430 条 | 93 | 可扩展 | 否 | 是 | 高，本地已有原始和 PPI 数据 | 本地压缩包约 1.6MB + 5.9MB；已下载 | **P0 主候选**。最贴合“真实网络条件/漂移/少样本”叙事，但要避免继续包装成二分类风险线索。 |
| ACM CCS artifact / WFlib | 2024 | WFlib CW/OW and collected datasets | [Zenodo](https://zenodo.org/records/13731720), [GitHub](https://github.com/Xinhao-Deng/Website-Fingerprinting-Library) | standardized WF attack evaluation | 本地 CW：105,730 条；WFlib 汇总多个 WF 数据集和 attack | CW 本地 95 | OW 可下载 | 含 multi-tab 数据条目 | 部分数据含 defense/drift | 高，CCS 2024 artifact，格式清楚 | Zenodo 总量较大；本地 CW 压缩包约 1.28GB，解压约 8.46GB | **P0 复现/备用主候选**。适合作为 closed-world 大规模复现实验和工程闭环。 |
| IEEE S&P, Robust Multi-tab Website Fingerprinting Attacks in the Wild | 2023 | ARES / Multitab-WF-Datasets | [GitHub](https://github.com/Xinhao-Deng/Multitab-WF-Datasets), [IEEE S&P accepted papers](https://sp2023.ieee-security.org/program-papers.html) | multi-tab WF, multi-label classification | WFlib 记录 Closed_2/3/4/5tab 各 58,000 条，Open_2/3/4/5tab 各 64,000 条 | 100 | 是 | 是 | 主要是多标签页真实假设 | 中高，公开仓库，但工程复杂度更高 | 每个 open/closed tab 包约 GB 级 | **P1 第二阶段候选**。权威且新，但第一篇 C 会小论文直接做 multi-label 风险偏高。 |
| USENIX Security, Stop, Don't Click Here Anymore | 2024 | Subpage / set-aware WF data or methodology | [USENIX page](https://www.usenix.org/conference/usenixsecurity24/presentation/mitseva) | subpage sets, sequential visits, realistic browsing | 论文强调 sets of subpages；需进一步确认 artifact 可得性 | 未定 | 关注真实设置 | 不是主打 multi-tab | 是，子页面/连续访问泛化 | 中，先作为方法论参考 | 未定 | **P1 方法论候选**。适合写动机和 future work，不作为第一阶段必跑数据。 |
| PAM, A Measurement of Genuine Tor Traces for Realistic Website Fingerprinting | 2026 | GTT23 / Tor WF dataset index | [Dataset index](https://www.rwails.org/tor_wf_index.html), [paper page](https://www.robgjansen.com/publications/gtt23-pam2026.html) | genuine Tor traces, realistic WF measurement | 索引覆盖 28 个 Tor WF 数据集；GTT23 关注真实 Tor traces | 未定 | 是，强调真实 open-world | 不是主打 | 是，真实流量差异 | 中，适合权威索引和外部 realism check | 未定 | **P1/P2 权威索引**。用于避免数据集选择过旧，第一阶段不强制训练。 |
| NDSS / AWF | 2018 | AWF / Automated Website Fingerprinting | [NDSS DOI](https://dl.acm.org/doi/10.14722/ndss.2018.23105) | classic single-tab WF | 常见大规模闭/开世界基准 | 多类 | 是 | 否 | 否 | 中，经典复用多 | 未下载；本地目录为空 | **P2 经典 baseline**。不作为最新权威主线。 |
| ACM CCS, Deep Fingerprinting | 2018 | DF | [ACM DOI](https://dl.acm.org/doi/10.1145/3243734.3243768) | classic DL-based WF | 常见闭/开世界基准 | 95 | 是 | 否 | 否 | 中高，经典复用多 | 未下载 | **P2 经典 baseline**。可用于 related work 或后续对比。 |
| Classic WF literature | 2014-2016 | Wang14 / CUMUL | [Wang/Goldberg PDF](https://cypherpunks.ca/~iang/pubs/webfingerprint-wpes.pdf), [CUMUL artifact note](https://www.acsac.org/2022/program/artifacts_competition/CUMUL-final.pdf) | classic handcrafted-feature WF | 中等 | 100 左右 | 是 | 否 | 否 | 中，历史对比价值高 | 未下载 | **P2 经典参考**。不符合“最新权威主线”。 |

## 当前本地状态

| 数据集 | 本地状态 | 备注 |
| --- | --- | --- |
| NetCLR / NCDrift | 已有 raw archive、解压 NPZ、PPI CSV | 可立即做 website-class 多分类和跨条件实验设计。 |
| WFlib CW | 已有 raw archive、解压 NPZ、PPI CSV | 可立即做 95 类 closed-world 复现实验。 |
| AWF | 目录存在但无文件 | 不能写成已具备数据。 |
| ARES / WFlib multi-tab | 未下载 | 等第一阶段决定是否投入 multi-label 工程。 |
| USENIX 2024 subpage | 未下载/未确认 artifact | 先作为动机和选题边界。 |

## 第一阶段建议

1. 先用 NetCLR / NCDrift 验证“近年顶会数据 + drift/cross-condition”的主线是否能清楚讲成论文。
2. 同步保留 WFlib CW 作为大规模 closed-world 复现实验，避免 NetCLR 标签解释过窄。
3. 暂不把 ARES multi-tab 放进第一版主线，除非 closed-world 和 drift 实验已经跑通。
4. 自采 Tor 数据只作为 MineShark-Tor 原型系统展示，不作为第一篇 C 会论文的必要实验。
