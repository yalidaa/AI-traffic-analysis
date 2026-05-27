<#
MineShark CLI Agent WSL demo runner.

用途：
  在 Windows PowerShell 中一键跑通 WSL2 发行版 Wazuh 里的 demo_jianli 分支 CLI Agent 链路。

安全边界：
  - 不删除任何文件或目录。
  - 不修改原 VMware 虚拟机。
  - 不写回 Wazuh 规则，不做自动封禁或自动处置。
  - 会重新构建 RAG 索引，调用 DashScope embedding，消耗少量额度。
  - 会运行 Agent，调用 DeepSeek，消耗少量对话额度。
  - 会覆盖生成 outputs/reports/agent_audit_report.json 和 .md。

运行方式：
  powershell -ExecutionPolicy Bypass -File .\scripts\agent\run_wsl_cli_agent_demo.ps1

常用参数：
  -SkipRagBuild  跳过 RAG 重新构建，直接使用已有 outputs/rag/
  -ShowReportLines 160  报告预览行数
#>

param(
    [string]$Distro = "Wazuh",
    [string]$LinuxProjectDir = "/opt/mineshark_agent",
    [int]$MaxEvents = 5,
    [int]$RecursionLimit = 24,
    [int]$ShowReportLines = 120,
    [switch]$SkipRagBuild
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param(
        [string]$Title,
        [string]$Why
    )
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    if ($Why) {
        Write-Host $Why -ForegroundColor DarkGray
    }
    Write-Host "============================================================" -ForegroundColor DarkGray
}

function Invoke-Wsl {
    param(
        [string]$User,
        [string]$Command
    )
    wsl -d $Distro -u $User -- bash -lc $Command
}

Write-Step "第 1 步：确认 WSL 发行版状态" "目标：确认 Wazuh 发行版处于 Running 状态。"
wsl -l -v

Write-Step "第 2 步：确认 Wazuh 核心服务是否 active" "目标：Indexer、Manager、Dashboard、Filebeat、Suricata、SSH 都应该是 active。"
Invoke-Wsl -User "root" -Command "systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard filebeat suricata ssh"

Write-Step "第 3 步：确认 MineShark 项目目录和分支" "目标：确认项目在 /opt/mineshark_agent，当前分支是 demo_jianli。"
Invoke-Wsl -User "ubuntu" -Command "cd '$LinuxProjectDir' && pwd && git branch --show-current && git status --short"

Write-Step "第 4 步：确认 Python 虚拟环境和 Agent CLI 可用" "目标：确认 .venv 可用，并且 run_agent_audit.py 能显示帮助。"
Invoke-Wsl -User "ubuntu" -Command "cd '$LinuxProjectDir' && source .venv/bin/activate && python -V && python scripts/agent/run_agent_audit.py --help | head -20"

Write-Step "第 5 步：确认 .env 关键配置已填写" "目标：只显示 set/missing，不打印真实密钥。DeepSeek 模型建议为 deepseek-chat。"
$envCheck = @'
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
'@
$envCheckBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($envCheck))
Invoke-Wsl -User "ubuntu" -Command "cd '$LinuxProjectDir' && python3 -c `"import base64; exec(base64.b64decode('$envCheckBase64').decode('utf-8'))`""

Write-Step "第 6 步：查看 MineShark AI 告警文件" "目标：确认 /var/log/ai_alerts.json 里至少有一条 AI 告警；如果是 0 行，需要先制造或等待告警。"
Invoke-Wsl -User "root" -Command "wc -l /var/log/ai_alerts.json && tail -n 3 /var/log/ai_alerts.json"

Write-Step "第 7 步：确认 AI 告警已被 Wazuh 摄取" "目标：看到 rule.id=100500 或 MineShark_Encrypted_Detection，说明 AI 告警进入 Wazuh。"
Invoke-Wsl -User "root" -Command "grep -n 'lab_replay_mineshark_20260527063525\|MineShark_Encrypted_Detection\|100500' /var/ossec/logs/alerts/alerts.json | tail -n 5 || true"

Write-Step "第 8 步：确认 RAG 索引文件是否存在" "目标：查看 outputs/rag/knowledge.faiss 和 metadata.json 是否存在。"
Invoke-Wsl -User "ubuntu" -Command "cd '$LinuxProjectDir' && ls -lh outputs/rag/knowledge.faiss outputs/rag/metadata.json 2>&1 || true"

if (-not $SkipRagBuild) {
    Write-Step "第 9 步：重新构建 RAG 索引" "目标：调用 DashScope embedding，把 security_playbook.jsonl 重新构建为 FAISS 索引。"
    Invoke-Wsl -User "ubuntu" -Command "cd '$LinuxProjectDir' && source .venv/bin/activate && python scripts/rag/build_index.py --env-file .env"
}
else {
    Write-Step "第 9 步：跳过 RAG 重新构建" "原因：传入了 -SkipRagBuild，将直接使用已有 outputs/rag/。"
}

Write-Step "第 10 步：正式运行 CLI Agent" "目标：调用 DeepSeek，让 Agent 读取 AI/Wazuh/Zeek/Suricata/RAG 并生成报告。"
Invoke-Wsl -User "root" -Command "cd '$LinuxProjectDir' && '$LinuxProjectDir/.venv/bin/python' scripts/agent/run_agent_audit.py --env-file .env --max-events $MaxEvents --recursion-limit $RecursionLimit"

Write-Step "第 11 步：预览 Markdown 报告" "目标：查看报告前 $ShowReportLines 行，确认出现 MineShark AI 告警、Wazuh、RAG、误报边界等内容。"
Invoke-Wsl -User "root" -Command "cd '$LinuxProjectDir' && sed -n '1,${ShowReportLines}p' outputs/reports/agent_audit_report.md"

Write-Step "第 12 步：查看 Agent 工具调用轨迹" "目标：从 JSON 报告中查看 Agent 调用了哪些工具，这是排查黑盒问题的关键。"
$traceScript = @'
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
'@
$traceScriptBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($traceScript))
Invoke-Wsl -User "ubuntu" -Command "cd '$LinuxProjectDir' && python3 -c `"import base64; exec(base64.b64decode('$traceScriptBase64').decode('utf-8'))`""

Write-Step "完成" "报告路径：$LinuxProjectDir/outputs/reports/agent_audit_report.md 和 agent_audit_report.json"
