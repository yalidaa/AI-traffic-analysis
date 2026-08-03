#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${MINESHARK_PROJECT_ROOT:-/mnt/e/MineShark-product}"
MODEL_SHA256="9c40a0145309fcc124583ed1d6c7c82b469e7e39948d9f6da57a2ed5e03cd9c1"
WAZUH_SERIES="${WAZUH_SERIES:-4.14}"
WAZUH_EXPECTED_VERSION="${WAZUH_EXPECTED_VERSION:-4.14.7}"
WAZUH_INSTALL_URL="https://packages.wazuh.com/${WAZUH_SERIES}/wazuh-install.sh"
ZEEK_SERIES="${ZEEK_SERIES:-8.0}"
ZEEK_EXPECTED_VERSION="${ZEEK_EXPECTED_VERSION:-8.0.9}"
ZEEK_REPO_BASE="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04"
ZEEK_APT_SOURCE="/etc/apt/sources.list.d/security-zeek.list"
ZEEK_KEYRING="/etc/apt/keyrings/security-zeek.gpg"
ZEEK_LOG_ROOT="/var/lib/mineshark/zeek-logs"
SURICATA_PACKAGE_VERSION="${SURICATA_PACKAGE_VERSION:-1:6.0.4-3}"
MANAGED_MARKER="# managed-by: mineshark-wsl-lab"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this installer as root" >&2
  exit 1
fi

source /etc/os-release
if [[ "${ID}" != "ubuntu" || "${VERSION_ID}" != "22.04" ]]; then
  echo "MineShark-Lab requires Ubuntu VERSION_ID=\"22.04\"" >&2
  exit 1
fi
if [[ ! -d "${PROJECT_ROOT}" ]]; then
  echo "project directory not found: ${PROJECT_ROOT}" >&2
  exit 1
fi

model_path="${PROJECT_ROOT}/checkpoints/deep_mineshark_legacy_20260304.pt"
actual_model_hash="$(sha256sum "${model_path}" | awk '{print $1}')"
if [[ "${actual_model_hash}" != "${MODEL_SHA256}" ]]; then
  echo "model checkpoint hash mismatch" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /etc/apt/keyrings
if [[ -f "${ZEEK_APT_SOURCE}" ]] && ! grep -Fq "${MANAGED_MARKER}" "${ZEEK_APT_SOURCE}"; then
  echo "refusing to overwrite unmanaged APT source: ${ZEEK_APT_SOURCE}" >&2
  exit 1
fi
curl --fail --silent --show-error --location "${ZEEK_REPO_BASE}/Release.key" \
  | gpg --dearmor --yes --output "${ZEEK_KEYRING}"
cat > "${ZEEK_APT_SOURCE}" <<EOF
${MANAGED_MARKER}
deb [signed-by=${ZEEK_KEYRING}] ${ZEEK_REPO_BASE}/ /
EOF
apt-get update
apt-get install -y ca-certificates curl gnupg nginx apache2-utils openssl python3-pip python3-venv \
  "zeek-${ZEEK_SERIES}" "suricata=${SURICATA_PACKAGE_VERSION}"

if ! dpkg-query -W -f='${Status}' wazuh-manager 2>/dev/null | grep -Fq "install ok installed"; then
  wazuh_work_dir="/var/tmp/mineshark-wazuh-$(date +%Y%m%d%H%M%S)"
  install -d -o root -g root -m 0700 "${wazuh_work_dir}"
  curl --fail --silent --show-error --location "${WAZUH_INSTALL_URL}" --output "${wazuh_work_dir}/wazuh-install.sh"
  bash "${wazuh_work_dir}/wazuh-install.sh" -a
fi

wazuh_version="$(dpkg-query -W -f='${Version}' wazuh-manager)"
if [[ "${wazuh_version}" != "${WAZUH_EXPECTED_VERSION}"* || "${wazuh_version,,}" == *"rc"* ]]; then
  echo "pre-release Wazuh package is not allowed: ${wazuh_version}" >&2
  exit 1
fi

zeek_binary=/opt/zeek/bin/zeek
if [[ ! -x "${zeek_binary}" ]]; then
  echo "Zeek binary not found at ${zeek_binary}" >&2
  exit 1
fi
zeek_version="$(${zeek_binary} --version | awk '{print $NF}')"
if [[ "${zeek_version}" != "${ZEEK_EXPECTED_VERSION}" ]]; then
  echo "unexpected Zeek version: ${zeek_version}" >&2
  exit 1
fi
if ! grep -R -Fq "color-scheme:light" "${PROJECT_ROOT}/web/frontend/dist" && \
  ! grep -R -Eq "color-scheme:[[:space:]]+light" "${PROJECT_ROOT}/web/frontend/dist"; then
  echo "refusing to deploy a frontend build without the approved light color scheme" >&2
  exit 1
fi
install -d -o root -g zeek -m 2770 "${ZEEK_LOG_ROOT}"
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
suricata_version="$(dpkg-query -W -f='${Version}' suricata)"
if [[ "${suricata_version}" != "${SURICATA_PACKAGE_VERSION}" ]]; then
  echo "unexpected Suricata package version: ${suricata_version}" >&2
  exit 1
fi
suricata --build-info >/dev/null
if [[ ! -s /etc/suricata/rules/suricata.rules ]]; then
  suricata-update --suricata-conf /etc/suricata/suricata.yaml -o /etc/suricata/rules
fi
suricata -T -c /etc/suricata/suricata.yaml >/dev/null

id mineshark >/dev/null 2>&1 || useradd --system --home /var/lib/mineshark --shell /usr/sbin/nologin mineshark
for group_name in zeek suricata; do
  getent group "${group_name}" >/dev/null && usermod -a -G "${group_name}" mineshark
done
install -d -o root -g mineshark -m 0750 /etc/mineshark /opt/mineshark/models
chmod 0755 /etc/mineshark
install -d -o root -g root -m 0755 /opt/mineshark/web/frontend/dist
install -d -o mineshark -g mineshark -m 0750 /var/lib/mineshark /var/log/mineshark
install -d -o mineshark -g mineshark -m 0750 /var/lib/mineshark/outputs /var/lib/mineshark/outputs/rag
chown -R mineshark:mineshark /var/lib/mineshark /var/log/mineshark
touch /var/log/mineshark/events.jsonl
chown mineshark:mineshark /var/log/mineshark/events.jsonl
chmod 0640 /var/log/mineshark/events.jsonl

python3 -m venv /opt/mineshark/venv
/opt/mineshark/venv/bin/pip install --upgrade pip
/opt/mineshark/venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
/opt/mineshark/venv/bin/pip install "${PROJECT_ROOT}[sensor,web]"

install -o root -g mineshark -m 0640 "${PROJECT_ROOT}/deploy/wsl-lab/sensor.toml" /etc/mineshark/sensor.toml
install -o root -g mineshark -m 0640 "${PROJECT_ROOT}/configs/sensor/model-manifest.json" /opt/mineshark/models/model-manifest.json
install -o root -g mineshark -m 0640 "${model_path}" /opt/mineshark/models/deep_mineshark_legacy_20260304.pt
install -o root -g mineshark -m 0640 "${PROJECT_ROOT}/configs/reporting/security_playbook.jsonl" /var/lib/mineshark/security_playbook.jsonl
cp -a "${PROJECT_ROOT}/web/frontend/dist/." /opt/mineshark/web/frontend/dist/
install -o root -g root -m 0644 "${PROJECT_ROOT}/deploy/wsl-lab/mineshark-sensor-wsl.service" /etc/systemd/system/mineshark-sensor.service
install -o root -g root -m 0644 "${PROJECT_ROOT}/deploy/wsl-lab/mineshark-zeek.service" /etc/systemd/system/mineshark-zeek.service
install -o root -g root -m 0644 "${PROJECT_ROOT}/deploy/systemd/mineshark-console.service" /etc/systemd/system/mineshark-console.service
install -o root -g root -m 0644 "${PROJECT_ROOT}/deploy/wazuh/mineshark_rules.xml" /var/ossec/etc/rules/mineshark_rules.xml

python3 - "${PROJECT_ROOT}/deploy/wazuh/ossec-mineshark.conf" /var/ossec/etc/ossec.conf <<'PY'
from pathlib import Path
import sys

fragment = Path(sys.argv[1]).read_text(encoding="utf-8").strip()
config_path = Path(sys.argv[2])
config = config_path.read_text(encoding="utf-8")
closing_tag = "</ossec_config>"
if closing_tag not in config:
    raise SystemExit("ossec.conf does not contain </ossec_config>")
config = config.replace(fragment, "", 1)
config_path.write_text(config.replace(closing_tag, f"{fragment}\n{closing_tag}", 1), encoding="utf-8")
PY

password_archive="$(find /var/tmp -maxdepth 2 -type f -name wazuh-install-files.tar -print -quit)"
if [[ -z "${password_archive}" ]]; then
  echo "Wazuh credential archive was not found under /var/tmp" >&2
  exit 1
fi
password_member="$(tar -tf "${password_archive}" | grep -E '(^|/)wazuh-passwords.txt$' | head -n 1)"
password_file=/var/lib/mineshark/wazuh-passwords.txt
tar -xOf "${password_archive}" "${password_member}" > "${password_file}"
chown root:root "${password_file}"
chmod 0600 "${password_file}"

admin_password="$(python3 - "${password_file}" <<'PY'
import re
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
for index, line in enumerate(lines):
    if "indexer_username: 'admin'" in line and index + 1 < len(lines):
        match = re.search(r"indexer_password:\s*'([^']+)'", lines[index + 1])
        if match:
            print(match.group(1))
            break
PY
)"
if [[ -z "${admin_password}" ]]; then
  echo "could not read the generated Wazuh indexer admin password" >&2
  exit 1
fi

wait_for_indexer() {
  for _attempt in $(seq 1 60); do
    if systemctl is-active --quiet wazuh-indexer && \
      curl --fail --silent --insecure --user "admin:${admin_password}" https://127.0.0.1:9200/ >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "Wazuh Indexer did not become ready" >&2
  systemctl status wazuh-indexer --no-pager >&2 || true
  return 1
}

wait_for_indexer

reader_password="$(openssl rand -hex 24)"
curl --fail --silent --show-error --insecure --user "admin:${admin_password}" \
  --request PUT https://127.0.0.1:9200/_plugins/_security/api/roles/mineshark_alert_reader \
  --header 'Content-Type: application/json' \
  --data '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}' >/dev/null
curl --fail --silent --show-error --insecure --user "admin:${admin_password}" \
  --request PUT https://127.0.0.1:9200/_plugins/_security/api/internalusers/mineshark-reader \
  --header 'Content-Type: application/json' \
  --data "{\"password\":\"${reader_password}\",\"backend_roles\":[]}" >/dev/null
curl --fail --silent --show-error --insecure --user "admin:${admin_password}" \
  --request PUT https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/mineshark_alert_reader \
  --header 'Content-Type: application/json' \
  --data '{"users":["mineshark-reader"]}' >/dev/null

console_env=/etc/mineshark/console.env
if [[ -f "${console_env}" ]] && ! grep -Fq "${MANAGED_MARKER}" "${console_env}"; then
  echo "refusing to overwrite unmanaged configuration: ${console_env}" >&2
  exit 1
fi
cat > "${console_env}" <<EOF
${MANAGED_MARKER}
MINESHARK_AI_ALERT_SOURCE=wazuh
MINESHARK_ALLOWED_SENSOR_IDS=singlehost-wlan
MINESHARK_CORS_ALLOWED_ORIGINS=https://localhost:8012
MINESHARK_SENSOR_HEARTBEAT_STALE_SECONDS=45
MINESHARK_FRONTEND_DIST=/opt/mineshark/web/frontend/dist
MINESHARK_OUTPUT_ROOT=/var/lib/mineshark/outputs
MINESHARK_KNOWLEDGE_FILE=/var/lib/mineshark/security_playbook.jsonl
MINESHARK_RAG_INDEX_DIR=/var/lib/mineshark/outputs/rag
MINESHARK_CONSOLE_DATABASE_PATH=/var/lib/mineshark/console.sqlite3
ZEEK_LOG_DIR=/var/lib/mineshark/zeek-logs/current
SURICATA_EVE_PATH=/var/log/suricata/eve.json
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USERNAME=mineshark-reader
WAZUH_INDEXER_PASSWORD=${reader_password}
WAZUH_INDEX_PATTERN=wazuh-alerts-*
WAZUH_VERIFY_SSL=false
EOF
chown root:mineshark "${console_env}"
chmod 0640 "${console_env}"
runuser -u mineshark -- /opt/mineshark/venv/bin/mineshark-build-rag --env-file "${console_env}"

install -d -o root -g root -m 0750 /etc/mineshark/tls
if [[ ! -f /etc/mineshark/tls/privkey.pem ]]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
    -keyout /etc/mineshark/tls/privkey.pem \
    -out /etc/mineshark/tls/fullchain.pem \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
fi
chown root:root /etc/mineshark/tls/privkey.pem /etc/mineshark/tls/fullchain.pem
chmod 0600 /etc/mineshark/tls/privkey.pem
chmod 0644 /etc/mineshark/tls/fullchain.pem
install -d -m 0755 /mnt/e/MineShark-runtime/certs
install -m 0644 /etc/mineshark/tls/fullchain.pem /mnt/e/MineShark-runtime/certs/mineshark-local.crt

console_password="$(openssl rand -hex 12)"
htpasswd -bc /etc/mineshark/htpasswd mineshark "${console_password}" >/dev/null
chown root:www-data /etc/mineshark/htpasswd
chmod 0640 /etc/mineshark/htpasswd
credentials_file=/var/lib/mineshark/console-credentials.txt
printf 'username=mineshark\npassword=%s\n' "${console_password}" > "${credentials_file}"
chown root:root "${credentials_file}"
chmod 0600 "${credentials_file}"

nginx_site=/etc/nginx/sites-available/mineshark
if [[ -f "${nginx_site}" ]] && ! grep -Fq "${MANAGED_MARKER}" "${nginx_site}"; then
  echo "refusing to overwrite unmanaged configuration: ${nginx_site}" >&2
  exit 1
fi
cat > "${nginx_site}" <<EOF
${MANAGED_MARKER}
server {
    listen 8012 ssl;
    listen [::]:8012 ssl;
    server_name localhost;
    ssl_certificate /etc/mineshark/tls/fullchain.pem;
    ssl_certificate_key /etc/mineshark/tls/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    satisfy any;
    allow 127.0.0.1;
    allow ::1;
    deny all;
    auth_basic "MineShark";
    auth_basic_user_file /etc/mineshark/htpasswd;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 60s;
    }
}
EOF
ln -sfn "${nginx_site}" /etc/nginx/sites-enabled/mineshark

/opt/mineshark/venv/bin/mineshark-sensor --config /etc/mineshark/sensor.toml validate-config
/var/ossec/bin/wazuh-analysisd -t
nginx -t
systemctl daemon-reload
systemctl enable --now wazuh-indexer wazuh-manager filebeat wazuh-dashboard nginx mineshark-sensor mineshark-console
systemctl enable --now mineshark-zeek
systemctl restart wazuh-manager mineshark-sensor mineshark-console
wait_for_indexer

echo "MineShark-Lab guest installation completed."
echo "Console credentials: ${credentials_file}"
