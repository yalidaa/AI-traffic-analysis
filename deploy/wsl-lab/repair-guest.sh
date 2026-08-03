#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${MINESHARK_PROJECT_ROOT:-/mnt/e/MineShark-product}"
EVENT_FRAGMENT="${PROJECT_ROOT}/deploy/wazuh/ossec-mineshark.conf"

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
chmod 0755 /etc/mineshark
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

echo "MineShark-Lab guest repair completed."
