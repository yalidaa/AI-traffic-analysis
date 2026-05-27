#!/usr/bin/env bash

# MineShark CLI Agent 演示脚本，运行在 Wazuh Linux/WSL 服务器内。
#
# 用途：
#   在 Wazuh 环境里一键跑通 demo_jianli 分支的 CLI Agent 链路。
#
# 安全边界：
#   - 本脚本不删除任何文件或目录。
#   - 本脚本不修改原 VMware 虚拟机。
#   - 本脚本不写入 Wazuh 规则，不做自动封禁或自动处置。
#   - 默认会重新构建 RAG 索引；如果传入 --skip-rag-build，则跳过。
#   - 会运行 Agent，并覆盖生成 outputs/reports/ 下的报告文件。
#
# 使用方式：
#   cd /opt/mineshark_agent
#   bash scripts/agent/run_cli_agent_demo.sh
#
# 可选参数：
#   --skip-rag-build       不重新构建 RAG，直接使用已有 outputs/rag/。
#   --max-events N         传给 Agent 的最大 AI 告警数量，默认 5。
#   --recursion-limit N    LangGraph 最大递归步数，默认 24。
#   --show-lines N         预览 Markdown 报告的行数，默认 120。

set -euo pipefail

PROJECT_DIR="/opt/mineshark_agent"
MAX_EVENTS=5
RECURSION_LIMIT=24
SHOW_LINES=120
SKIP_RAG_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-rag-build)
      SKIP_RAG_BUILD=1
      shift
      ;;
    --max-events)
      MAX_EVENTS="$2"
      shift 2
      ;;
    --recursion-limit)
      RECURSION_LIMIT="$2"
      shift 2
      ;;
    --show-lines)
      SHOW_LINES="$2"
      shift 2
      ;;
    *)
      echo "未知参数: $1" >&2
      exit 2
      ;;
  esac
done

step() {
  local title="$1"
  local why="${2:-}"
  echo
  echo "============================================================"
  echo "$title"
  if [[ -n "$why" ]]; then
    echo "$why"
  fi
  echo "============================================================"
}

cd "$PROJECT_DIR"

step "第 1 步：检查主机、磁盘和项目路径" \
  "目标：确认当前运行在 Wazuh 环境里，并且项目目录存在。"
# 打印 hostname、根分区空间和当前路径，先确认执行环境没有跑错。
hostname
df -hT /
pwd

step "第 2 步：检查 Wazuh 核心服务" \
  "目标：wazuh-indexer、wazuh-manager、wazuh-dashboard、filebeat、suricata、ssh 都应该是 active。"
# Agent 后面要查询 Wazuh API 和日志，所以先确认安全组件都在运行。
systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard filebeat suricata ssh

step "第 3 步：检查 Git 分支和工作区状态" \
  "目标：当前分支应该是 demo_jianli。未跟踪的 egg-info 是安装元数据，不影响运行。"
# 打印当前分支和工作区状态，确认测试的是我们约定的 demo_jianli 代码。
git branch --show-current
git status --short

step "第 4 步：检查 Python 虚拟环境和 Agent CLI" \
  "目标：Python 3.12 可用，并且 run_agent_audit.py 能正常显示帮助信息。"
# 激活项目虚拟环境，确认 Agent CLI 能被导入和执行。
source .venv/bin/activate
python -V
python scripts/agent/run_agent_audit.py --help | head -20

step "第 5 步：检查 .env 关键配置，但不打印真实密钥" \
  "目标：只显示 API Key 和密码是 set 还是 missing，同时显示 DeepSeek 模型名。"
# 安全读取 .env，只判断密钥是否填写，不把真实密钥输出到终端。
python3 - <<'PY'
from pathlib import Path

keys = [
    "DEEPSEEK_API_KEY",
    "DASHSCOPE_API_KEY",
    "WAZUH_PASSWORD",
    "WAZUH_INDEXER_PASSWORD",
    "DEEPSEEK_MODEL",
]

vals = {}
for line in Path(".env").read_text(encoding="utf-8").splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        key, value = line.split("=", 1)
        vals[key] = value.strip()

for key in keys:
    value = vals.get(key, "")
    if "KEY" in key or "PASSWORD" in key:
        ok = bool(value and not value.startswith("your-") and not value.startswith("change-"))
        print(key + "=" + ("set" if ok else "missing"))
    else:
        print(key + "=" + value)
PY

step "第 6 步：检查 MineShark AI 告警文件" \
  "目标：/var/log/ai_alerts.json 至少有一条 AI 告警，这样演示报告才有核心事件。"
# 统计并预览实时 AI 引擎已经产生的告警。
wc -l /var/log/ai_alerts.json
tail -n 3 /var/log/ai_alerts.json

step "第 7 步：确认 AI 告警已经被 Wazuh 摄取" \
  "目标：在 Wazuh alerts 里找到规则 100500 或 MineShark_Encrypted_Detection。"
# 验证 AI 告警是否已经进入 Wazuh 告警链路。
grep -n 'lab_replay_mineshark_20260527063525\|MineShark_Encrypted_Detection\|100500' \
  /var/ossec/logs/alerts/alerts.json | tail -n 5 || true

step "第 8 步：检查已有 RAG 索引文件" \
  "目标：确认 knowledge.faiss 和 metadata.json 是否已经存在。"
# 如果已经构建过 RAG，这里会显示当前 FAISS 索引产物。
ls -lh outputs/rag/knowledge.faiss outputs/rag/metadata.json 2>&1 || true

if [[ "$SKIP_RAG_BUILD" -eq 0 ]]; then
  step "第 9 步：重新构建 RAG 索引" \
    "目标：调用 DashScope embedding，把安全知识库重新生成到 outputs/rag/。"
  # 从 configs/reporting/security_playbook.jsonl 构建 FAISS 知识库索引。
  python scripts/rag/build_index.py --env-file .env
else
  step "第 9 步：跳过 RAG 重新构建" \
    "原因：命令中传入了 --skip-rag-build，将直接使用已有 outputs/rag/。"
fi

step "第 10 步：正式运行 CLI Agent" \
  "目标：调用 DeepSeek，让 Agent 读取 AI/Wazuh/Zeek/Suricata/RAG 并生成研判报告。"
# 以旁路模式运行 LangGraph Agent：只读日志和 API，不写回 Wazuh，不做处置。
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --max-events "$MAX_EVENTS" \
  --recursion-limit "$RECURSION_LIMIT"

step "第 11 步：预览 Markdown 中文报告" \
  "目标：确认报告里出现 MineShark AI、Wazuh、RAG、误报边界等内容。"
# 展示给人阅读的 Markdown 报告前半部分。
sed -n "1,${SHOW_LINES}p" outputs/reports/agent_audit_report.md

step "第 12 步：查看 Agent 工具调用轨迹" \
  "目标：看清楚 Agent 调用了哪些工具，避免 LLM 研判过程变成黑盒。"
# 读取结构化 JSON 报告，摘要打印 tool_trace。
python3 - <<'PY'
import json
from pathlib import Path

path = Path("outputs/reports/agent_audit_report.json")
data = json.loads(path.read_text(encoding="utf-8"))

for index, item in enumerate(data.get("tool_trace", []), start=1):
    tool = item.get("tool")
    args = item.get("arguments")
    result = item.get("result", {})
    summary = ""
    if isinstance(result, dict):
        if "matched" in result:
            summary += " matched=" + str(result.get("matched"))
        if "total_records" in result:
            summary += " total_records=" + str(result.get("total_records"))
        if "source" in result:
            summary += " source=" + str(result.get("source"))
        if result.get("error"):
            summary += " error=" + str(result.get("error"))[:120]
    print(f"{index}. {tool} args={args}{summary}")
PY

step "完成" \
  "报告路径：outputs/reports/agent_audit_report.md 和 outputs/reports/agent_audit_report.json"
