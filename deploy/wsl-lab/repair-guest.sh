#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${MINESHARK_PROJECT_ROOT:-/mnt/e/MineShark-product}"
EVENT_FRAGMENT="${PROJECT_ROOT}/deploy/wazuh/ossec-mineshark.conf"
ZEEK_LOG_ROOT="/var/lib/mineshark/zeek-logs"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this repair as root" >&2
  exit 1
fi
source /etc/os-release
if [[ "${ID}" != "ubuntu" || "${VERSION_ID}" != "22.04" ]]; then
  echo "MineShark-Lab requires Ubuntu 22.04" >&2
  exit 1
fi

/opt/mineshark/venv/bin/pip install --quiet tomli==2.0.1
/opt/mineshark/venv/bin/pip install --quiet --no-deps "${PROJECT_ROOT}[sensor,web]"
install -o root -g wazuh -m 0640 "${PROJECT_ROOT}/deploy/wazuh/mineshark_rules.xml" /var/ossec/etc/rules/mineshark_rules.xml
install -d -o mineshark -g mineshark -m 0750 /var/lib/mineshark/outputs /var/lib/mineshark/outputs/rag
install -d -o root -g zeek -m 2770 "${ZEEK_LOG_ROOT}"
install -o root -g mineshark -m 0640 "${PROJECT_ROOT}/configs/reporting/security_playbook.jsonl" /var/lib/mineshark/security_playbook.jsonl
install -o root -g root -m 0644 "${PROJECT_ROOT}/deploy/wsl-lab/mineshark-zeek.service" /etc/systemd/system/mineshark-zeek.service
install -o root -g mineshark -m 0640 "${PROJECT_ROOT}/deploy/wsl-lab/sensor.toml" /etc/mineshark/sensor.toml
python3 - "/opt/zeek/etc/zeekctl.cfg" "${ZEEK_LOG_ROOT}" <<'PY'
from pathlib import Path
import sys

config_path = Path(sys.argv[1])
log_root = sys.argv[2]
lines = config_path.read_text(encoding="utf-8").splitlines()
replaced = False
for index, line in enumerate(lines):
    if line.strip().startswith("LogDir") and "=" in line:
        lines[index] = f"LogDir = {log_root}"
        replaced = True
        break
if not replaced:
    lines.append(f"LogDir = {log_root}")
config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
if ! grep -R -Fq "color-scheme:light" "${PROJECT_ROOT}/web/frontend/dist" && \
  ! grep -R -Eq "color-scheme:[[:space:]]+light" "${PROJECT_ROOT}/web/frontend/dist"; then
  echo "refusing to deploy a frontend build without the approved light color scheme" >&2
  exit 1
fi
install -d -o root -g root -m 0755 /opt/mineshark/web/frontend/dist
cp -a "${PROJECT_ROOT}/web/frontend/dist/." /opt/mineshark/web/frontend/dist/
console_env=/etc/mineshark/console.env
for setting in \
  "MINESHARK_OUTPUT_ROOT=/var/lib/mineshark/outputs" \
  "MINESHARK_KNOWLEDGE_FILE=/var/lib/mineshark/security_playbook.jsonl" \
  "MINESHARK_RAG_INDEX_DIR=/var/lib/mineshark/outputs/rag"; do
  setting_name="${setting%%=*}"
  if ! grep -Fq "${setting_name}=" "${console_env}"; then
    printf '%s\n' "${setting}" >> "${console_env}"
  fi
done
python3 - "${console_env}" <<'PY'
from pathlib import Path
import sys

env_path = Path(sys.argv[1])
updates = {
    "MINESHARK_OUTPUT_ROOT": "/var/lib/mineshark/outputs",
    "MINESHARK_KNOWLEDGE_FILE": "/var/lib/mineshark/security_playbook.jsonl",
    "MINESHARK_RAG_INDEX_DIR": "/var/lib/mineshark/outputs/rag",
    "ZEEK_LOG_DIR": "/var/lib/mineshark/zeek-logs/current",
}
lines = env_path.read_text(encoding="utf-8").splitlines()
seen = set()
updated = []
for line in lines:
    key, separator, _ = line.partition("=")
    if separator and key in updates:
        updated.append(f"{key}={updates[key]}")
        seen.add(key)
    else:
        updated.append(line)
for key, value in updates.items():
    if key not in seen:
        updated.append(f"{key}={value}")
env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
chmod 0755 /etc/mineshark
runuser -u mineshark -- /opt/mineshark/venv/bin/mineshark-build-rag --env-file "${console_env}"
python3 - <<'PY'
from pathlib import Path

nginx_path = Path("/etc/nginx/sites-available/mineshark")
config = nginx_path.read_text(encoding="utf-8")
if "satisfy any;" not in config:
    config = config.replace(
        "    ssl_protocols TLSv1.2 TLSv1.3;",
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "    satisfy any;\n"
        "    allow 127.0.0.1;\n"
        "    allow ::1;\n"
        "    deny all;",
        1,
    )
    nginx_path.write_text(config, encoding="utf-8")
PY
chown -R mineshark:mineshark /var/lib/mineshark /var/log/mineshark
chmod 0750 /var/lib/mineshark /var/log/mineshark
chmod 0640 /var/lib/mineshark/sensor.sqlite3 2>/dev/null || true

python3 - "${EVENT_FRAGMENT}" /var/ossec/etc/ossec.conf <<'PY'
from pathlib import Path
import sys

fragment_path = Path(sys.argv[1])
config_path = Path(sys.argv[2])
fragment = fragment_path.read_text(encoding="utf-8").strip()
config = config_path.read_text(encoding="utf-8")
closing_tag = "</ossec_config>"
if closing_tag not in config:
    raise SystemExit("ossec.conf does not contain </ossec_config>")
config = config.replace(fragment, "", 1)
config = config.replace(closing_tag, f"{fragment}\n{closing_tag}", 1)
config_path.write_text(config, encoding="utf-8")
PY

/opt/mineshark/venv/bin/mineshark-sensor --config /etc/mineshark/sensor.toml validate-config
/var/ossec/bin/wazuh-analysisd -t
nginx -t
systemctl daemon-reload
systemctl enable --now wazuh-indexer wazuh-manager filebeat wazuh-dashboard nginx mineshark-sensor mineshark-console
systemctl enable --now mineshark-zeek
systemctl restart mineshark-zeek mineshark-sensor mineshark-console

echo "MineShark-Lab guest repair completed."
