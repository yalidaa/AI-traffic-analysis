# MineShark 仓库整理与后续开发交接

更新时间：2026-08-03

> 本文写给完全没有聊天上下文的新会话。接手后先阅读本文，再核对 Git 和远程状态。`docs/project_record.md` 包含重要的产品化与部署历史，但其中关于 `productization` 分支和当时运行状态的描述已有部分过期，不能直接当作当前 Git 状态。

## 一、我们在做什么

本轮任务是整理并同步公开仓库 [yalidaa/AI-traffic-analysis](https://github.com/yalidaa/AI-traffic-analysis)，将已经完成的 MineShark 产品化成果归入主分支，并重新明确长期分支职责：

- `main`：系统开发主线。负责 Sensor、Wazuh、Console、案件、证据、报告、部署和经过验证的算法能力集成。
- `training`：AI 流量分析算法优化主线。负责数据、特征、模型、损失函数、阈值校准、训练、评估和泛化研究。

`training` 的总目标是优化 AI 算法模块，提高准确性、稳定性和低误报运行能力。Tor Website Fingerprinting 只是当前主要研究和验证场景，不是这个分支唯一或永久的产品定义。

必须坚持以下表述边界：

- 模型概率是需要复核的风险线索，不是已经确认的攻击事实。
- Tor 是匿名通信系统，不能把 Tor 用户或 Tor 流量默认描述为恶意。
- 小规模 smoke 实验只能证明路径和代码可运行，不能证明论文效果、真实泛化能力或生产可用性。
- `main` 的系统闭环验收不能替代 `training` 的模型效果验收。

## 二、仓库当前真实状态

远程仓库：

```text
https://github.com/yalidaa/AI-traffic-analysis.git
```

2026-08-03 当前远程核验结果：

```text
main     f45d72e0344291e3f68f89309a4af2cb41c72c73
training b4305f029dfef680a2a8e758907298c604af5069
```

远程目前只有两个业务分支：`main` 和 `training`。

- 旧远程 `demo_jianli` 已删除。
- 旧远程 `productization` 已删除。
- 产品化代码已经进入 `main`，不应再恢复或继续使用远程 `productization`。
- 当前本机工作区已切回 `main`，创建本文前工作树干净并与 `origin/main` 一致。
- 本文 `handoff.md` 已纳入 `main` 的交接资料；新会话接手后仍应先用 `git status --short --branch` 确认工作树，再核对远程状态。

本机还存在 `codex/training-remote-cleanup` 等本地引用，另有 `training` 和 `codex/icc27-open-drift` 被其他 worktree 使用。它们不是新的远程业务分支。不要删除、强制移动或切换这些被占用的本地分支。

另一个训练工作区可能位于 `E:\TrafficDetection_LLM4ccb`，其中有用户自己的未提交改动。本轮没有修改它，后续也不得为了整理本仓库而切换、回退或清理该目录。

## 三、本轮已经完成什么

### 1. 主分支整理

产品化系统成果已经提交到 `main`。关键提交：

```text
51dc162 feat: 同步 MineShark 产品化闭环
ba3035e docs: 统一产品化说明文字
1d8a020 docs: 说明主线与训练分支职责
```

`main` 已明确为系统开发主线。现有能力包括真实流量 Sensor、Wazuh 接入、FastAPI/React Console、告警与案件闭环、证据聚合、报告、WSL 部署文件和中文文档。具体部署成果和历史验证证据见：

```text
docs/project_record.md
README.md
docs/wsl_lab_deployment.md
docs/productization_roadmap.md
```

### 2. 训练分支整理

远程 `training` 已更新到提交：

```text
b4305f0 chore(training): 整理 AI 算法优化分支
```

该提交完成了：

- 将分支核心目标统一为“优化 AI 流量分析算法模块”。
- 明确数据质量、特征、训练、阈值、低误报评估和模型契约职责。
- 明确 `main` 与 `training` 的协作边界。
- 将 Tor WF 定义为当前研究验证场景，而不是分支总目标。
- 中文化 README、训练说明、配置说明、工作流步骤和主要实验文档。
- 将旧 `demo_jianli`、Agent、Wazuh、Console 等文档标为历史工程资料，避免误认为当前训练入口。
- 泛化本机用户名、个人目录、GPU Python 路径和实验地址；文档示例地址改为保留测试网段。
- `.gitignore` 增加 `build/` 和 `.playwright-mcp/`，避免生成物误提交。
- 修复 `ConsoleDatabase.connect()` 退出 `with` 后不关闭 SQLite 连接的问题。
- 增加 SQLite 连接关闭回归测试。

### 3. 隐私与公开仓库边界

本轮只提交源码、测试、配置模板和说明文档。以下内容没有提交：

- 真实 API 密钥、密码、令牌、证书私钥。
- 原始数据集、模型 checkpoint、训练日志、生成报告和 RAG 索引。
- 用户名目录、个人 Conda 路径和真实实验主机地址。
- `node_modules`、前端 `dist`、`build/` 等生成物。

测试文件中的 `super-secret-*` 是固定的虚假测试字符串，用于验证接口不会泄露秘密，不是真实凭据。

## 四、完成时的验证证据

对当前 `main` 文档同步的本轮新鲜验证结果：

```text
Python 测试：106 passed，1 warning
Ruff 静态检查：All checks passed
Ruff 格式检查：65 files already formatted
前端正式构建：成功
Git diff --check：通过
```

前端构建成功时的主包约为 `637.15 kB`，gzip 后约 `196.55 kB`。Vite 仍提示单包超过 `500 kB`，这是性能优化事项，不是本轮阻塞。

测试还有一个非阻断警告：FastAPI TestClient 使用的 `httpx` 接口将迁移到 `httpx2`。不要为了消除这个警告顺手做大规模依赖升级，应单独评估兼容性。

远程推送后已用 `git ls-remote` 确认 `refs/heads/training` 精确指向 `b4305f029dfef680a2a8e758907298c604af5069`。

## 五、当前卡在哪里

当前没有代码实现或远程同步方面的硬阻塞。主要是以下待处理事项和状态风险：

1. `README.md`、`docs/project_record.md`、WSL/Console/Agent/RAG 文档已同步到 `main` 当前状态；后续只需在服务或版本变化时重新核验，不要把历史归档当作现场状态。
2. 本地 `training` 分支引用仍可能停在旧提交 `fb6e1d9`，并且被其他 worktree 占用。远程 `origin/training` 的 `b4305f0` 才是当前事实来源。
3. 前端存在超过 500 kB 的构建提示，尚未拆包。
4. FastAPI/Starlette 测试链存在 `httpx2` 迁移提示，尚未处理。
5. 2026-08-03 现场复核显示 Wazuh Indexer 和 Manager 仍处于 `activating`，其余相关服务为 `active`；RAG 索引为 `local-hash`、10 条、384 维。涉及“当前是否在线”的问题必须重新运行现场检查，不能复述旧结论。

## 六、下一步计划

### 第一优先级：保持 main 文档与现场状态同步

1. 入口、部署、Console、Agent/RAG 和历史资料已经改为指向 `main`，并标注历史快照边界。
2. 保留部署架构、历史验收数据、真实链路和风险边界，不要把历史内容整段删除。
3. 所有新增说明使用中文；版本、RAG provider 和服务状态以现场/脚本为准。
4. 后续文档改动完成后，继续执行测试、Ruff、前端构建和 `git diff --check`。

### 第二优先级：继续 training 的算法优化

除非用户明确要求切换到算法任务，否则不要在 `main` 中直接修改训练逻辑。算法工作建议按以下顺序执行：

1. 从最新 `origin/training` 创建新的 `codex/` 临时分支或独立 worktree，不要占用或清理现有训练工作区。
2. 先确认数据来源、标签语义、训练/验证/测试划分和当前基线，不要先堆模型结构。
3. 固定报告指标：accuracy、precision、recall、F1、FPR、FNR、混淆矩阵、阈值和数据划分。
4. 优先验证低误报运行点和阈值校准，再比较特征、损失函数和模型结构。
5. 加入良性对照、误报样本、跨条件变化和分布变化评估。
6. 所有功能或缺陷修复先写失败测试，确认红灯，再做最小实现。
7. 经过完整评估的算法契约才能整理合入 `main`；checkpoint、数据和实验日志仍只保留在本地。

### main 的后续系统任务

系统开发继续参考 `docs/project_record.md` 和 `docs/productization_roadmap.md`，重点包括：

- 重启或重新登录后的 WSL 计划任务持久化验收。
- Wazuh 本地告警的受控只读权限方案，或明确只以 Indexer 为部署告警源。
- Zeek/Suricata 接入和版本化 evidence bundle。
- 模型大量普通 WLAN 高风险输出的独立校准研究。
- 每次改动后的后端测试、Ruff、前端构建和浏览器验收。

## 七、新会话接手时先执行

在项目根目录执行：

```powershell
rtk git status --short --branch
rtk git remote -v
rtk git ls-remote --heads origin
rtk git log -1 --oneline origin/main
rtk git log -1 --oneline origin/training
```

预期远程结果是：

```text
origin/main     f45d72e
origin/training b4305f0
```

若远程提交已经变化，以新鲜远程结果为准，不要强行回退到本文记录的提交。

Python 验证使用仓库自己的虚拟环境，不要依赖 Windows Store 的 `python` 占位程序：

```powershell
rtk proxy pwsh -NoLogo -NoProfile -Command "& '.\.venv\Scripts\python.exe' -m pytest"
rtk proxy pwsh -NoLogo -NoProfile -Command "& '.\.venv\Scripts\ruff.exe' check src tests"
rtk proxy pwsh -NoLogo -NoProfile -Command "& '.\.venv\Scripts\ruff.exe' format --check src tests"
```

前端构建必须在 `web/frontend` 中执行：

```powershell
rtk proxy pwsh -NoLogo -NoProfile -Command "npm install --ignore-scripts --no-audit --no-fund"
rtk proxy pwsh -NoLogo -NoProfile -Command "npm run build"
```

仅当 `node_modules` 与锁文件不同步时才运行 `npm install`。不要把 `node_modules` 或 `dist` 加入 Git。

## 八、绝对不要再踩的坑

1. **禁止批量清理。** 不得使用 `git clean -fd`、`git clean -fdx`、`git reset --hard`、`git checkout -- <path>`、`Remove-Item -Recurse`、`rm -rf`，也不得删除目录。
2. **不要碰其他脏工作区。** 尤其不要修改或清理 `E:\TrafficDetection_LLM4ccb`；那里可能有用户未提交的训练工作。
3. **不要把本地分支列表当成远程分支列表。** 远程分支用 `git ls-remote --heads origin` 核验。本地 `codex/*` 和被 worktree 占用的分支不等于 GitHub 上还有额外业务分支。
4. **不要恢复 `productization` 或 `demo_jianli` 远程分支。** 它们的有效成果已经进入 `main`，历史演示资料只供追溯。
5. **不要整体合并 main 到 training。** 两个分支职责不同；只迁移经过验证、确实需要的最小算法或接口改动。
6. **不要把 Tor/NetCLR 标签解释错。** NetCLR condition-pair 不是 normal-vs-malware；Tor 用户默认不等于恶意用户。
7. **不要用单一 accuracy 或小样本 F1 宣传效果。** 必须同时报告数据划分、阈值、FPR、FNR、混淆矩阵和适用边界。
8. **不要泄露隐私或凭据。** 公开文档中使用 `<项目根目录>`、`<GPU训练环境>` 和保留测试地址；真实 `.env`、密码、令牌、证书、主机地址和个人目录不得提交。
9. **SQLite 连接上下文必须真正关闭连接。** Python 的原始 `sqlite3.Connection` 在退出 `with` 时只提交或回滚，不会自动关闭；Windows 会因此在临时目录清理时触发 `WinError 32`。保留 `contextmanager` 的 `finally: connection.close()` 和回归测试。
10. **不要把依赖环境错误当成代码错误。** 本轮 `uv` 不在 `PATH`，Windows Store 的 `python` 也不可用；最终使用 `.venv\Scripts\python.exe` 完成测试。
11. **前端清单存在依赖不代表本地已经安装。** 本轮 `package.json` 和锁文件已有 `react-markdown`、`remark-gfm`，但旧 `node_modules` 缺包导致 Vite 无法解析。同步本地依赖后构建通过，不能重复制造无意义的 package 改动。
12. **不要只看构建中间日志。** Vite 可能先输出 bundle 文件再因未解析模块返回失败；必须以最终退出码为准。
13. **不要为了消除警告顺手大重构。** 前端拆包和 `httpx2` 迁移都应单开任务并重新验收。
14. **不要复述过期运行状态。** 服务在线、告警数量、计划任务和浏览器状态都必须现场重查。

## 九、关键文件索引

```text
handoff.md                               本文，当前会话交接入口
README.md                                main 系统说明
docs/project_record.md                   产品化、部署与历史验收记录
docs/productization_roadmap.md           main 系统后续路线
docs/training_branch.md                  training 分支职责说明，仅在 training 提交中存在最新版
docs/tor_dataset_strategy.md             Tor 数据集与实验边界，仅在 training 中重点维护
src/mineshark/web/database.py            SQLite 连接与 Console 存储
tests/test_web_console.py                Console 和连接关闭回归测试
web/frontend/src/App.jsx                 Console 主前端
web/frontend/src/styles.css              Console 样式
deploy/wsl-lab/                           WSL 单机实验部署
deploy/wazuh/mineshark_rules.xml          Wazuh 规则
```

接手原则只有一句话：先核对当前 Git、远程和运行环境，再做最小、可验证、中文说明完整的改动；不要依赖旧会话结论，也不要清理任何不属于当前任务的文件或工作区。
