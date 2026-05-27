#!/usr/bin/env bash

# MineShark CLI Agent demo runner for the Wazuh Linux/WSL server.
#
# Purpose:
#   Run the demo_jianli CLI Agent chain inside the Wazuh environment.
#
# Safety boundary:
#   - This script does not delete files or directories.
#   - This script does not modify the old VMware VM.
#   - This script does not write Wazuh rules or perform automatic blocking.
#   - This script rebuilds the RAG index unless --skip-rag-build is used.
#   - This script runs the Agent and overwrites generated report files under outputs/reports/.
#
# Usage:
#   cd /opt/mineshark_agent
#   bash scripts/agent/run_cli_agent_demo.sh
#
# Options:
#   --skip-rag-build       Use existing outputs/rag/ instead of rebuilding it.
#   --max-events N         Max AI events passed to the Agent. Default: 5.
#   --recursion-limit N    LangGraph recursion limit. Default: 24.
#   --show-lines N         Markdown report preview lines. Default: 120.

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
      echo "Unknown option: $1" >&2
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

step "Step 1: Check host, disk, and project path" \
  "Goal: confirm we are running inside Wazuh and the project directory exists."
# Print hostname, disk usage, and current directory for quick orientation.
hostname
df -hT /
pwd

step "Step 2: Check Wazuh core services" \
  "Goal: wazuh-indexer, wazuh-manager, wazuh-dashboard, filebeat, suricata, and ssh should be active."
# Verify that the security stack is running before the Agent queries Wazuh APIs and logs.
systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard filebeat suricata ssh

step "Step 3: Check Git branch and workspace state" \
  "Goal: the branch should be demo_jianli. Untracked egg-info is harmless."
# Show the current branch and local status so we know which code is being tested.
git branch --show-current
git status --short

step "Step 4: Check Python virtual environment and Agent CLI" \
  "Goal: Python 3.12 and run_agent_audit.py help should work."
# Activate the project virtual environment and verify the Agent CLI is importable.
source .venv/bin/activate
python -V
python scripts/agent/run_agent_audit.py --help | head -20

step "Step 5: Check .env key status without printing secrets" \
  "Goal: show set/missing for API keys and passwords; show DeepSeek model name."
# Read .env safely and do not print actual secrets.
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

step "Step 6: Check MineShark AI alert file" \
  "Goal: /var/log/ai_alerts.json should contain at least one AI alert for a meaningful demo."
# Count and preview existing AI alerts produced by the MineShark real-time AI engine.
wc -l /var/log/ai_alerts.json
tail -n 3 /var/log/ai_alerts.json

step "Step 7: Check whether Wazuh ingested the AI alert" \
  "Goal: find rule 100500 or MineShark_Encrypted_Detection in Wazuh alerts."
# Verify the AI alert entered Wazuh's alert pipeline.
grep -n 'lab_replay_mineshark_20260527063525\|MineShark_Encrypted_Detection\|100500' \
  /var/ossec/logs/alerts/alerts.json | tail -n 5 || true

step "Step 8: Check existing RAG index files" \
  "Goal: knowledge.faiss and metadata.json should exist after RAG build."
# Show current RAG artifacts if they already exist.
ls -lh outputs/rag/knowledge.faiss outputs/rag/metadata.json 2>&1 || true

if [[ "$SKIP_RAG_BUILD" -eq 0 ]]; then
  step "Step 9: Rebuild RAG index" \
    "Goal: call DashScope embeddings and regenerate outputs/rag/."
  # Build the FAISS index from configs/reporting/security_playbook.jsonl.
  python scripts/rag/build_index.py --env-file .env
else
  step "Step 9: Skip RAG rebuild" \
    "Reason: --skip-rag-build was provided."
fi

step "Step 10: Run CLI Agent" \
  "Goal: call DeepSeek and generate JSON/Markdown triage reports."
# Run the LangGraph Agent in sidecar mode. This reads logs and APIs but does not write back to Wazuh.
python scripts/agent/run_agent_audit.py \
  --env-file .env \
  --max-events "$MAX_EVENTS" \
  --recursion-limit "$RECURSION_LIMIT"

step "Step 11: Preview Markdown report" \
  "Goal: verify the report mentions MineShark AI, Wazuh, RAG, and false-positive boundaries."
# Show the first part of the human-readable report.
sed -n "1,${SHOW_LINES}p" outputs/reports/agent_audit_report.md

step "Step 12: Show Agent tool trace" \
  "Goal: inspect which tools the Agent called, so the LLM process is not a black box."
# Read the structured JSON report and summarize tool calls.
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

step "Done" \
  "Reports: outputs/reports/agent_audit_report.md and outputs/reports/agent_audit_report.json"
