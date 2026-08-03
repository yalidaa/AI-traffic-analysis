#!/usr/bin/env bash
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_PATH=/etc/mineshark/console.env
NGINX_PATH=/etc/nginx/sites-available/mineshark
MANAGED_MARKER="# managed-by: mineshark-offline-bundle"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this installer as root" >&2
  exit 1
fi
for path in "${ENV_PATH}" "${NGINX_PATH}"; do
  if [[ -f "${path}" ]] && ! grep -Fq "${MANAGED_MARKER}" "${path}"; then
    echo "refusing to overwrite unmanaged configuration: ${path}" >&2
    exit 1
  fi
done

id mineshark >/dev/null 2>&1 || useradd --system --home /var/lib/mineshark --shell /usr/sbin/nologin mineshark
install -d -o root -g mineshark -m 0750 /etc/mineshark
install -d -o mineshark -g mineshark -m 0750 /var/lib/mineshark /var/log/mineshark
install -d -o root -g root -m 0755 /opt/mineshark/web/frontend
python3 -m venv /opt/mineshark/venv
/opt/mineshark/venv/bin/pip install --no-index --find-links "${BUNDLE_DIR}/wheels" "${BUNDLE_DIR}/wheels/mineshark_traffic_analysis-0.1.0-py3-none-any.whl"
cp -a "${BUNDLE_DIR}/web/frontend/dist" /opt/mineshark/web/frontend/
{ echo "${MANAGED_MARKER}"; cat "${BUNDLE_DIR}/console.env.example"; } > "${ENV_PATH}"
chown root:mineshark "${ENV_PATH}"
chmod 0640 "${ENV_PATH}"
{ echo "${MANAGED_MARKER}"; cat "${BUNDLE_DIR}/nginx/mineshark.conf"; } > "${NGINX_PATH}"
install -o root -g root -m 0644 "${BUNDLE_DIR}/systemd/mineshark-console.service" /etc/systemd/system/mineshark-console.service
systemctl daemon-reload
echo "console files installed; configure credentials, certificates and htpasswd, then run nginx -t"
