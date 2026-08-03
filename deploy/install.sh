#!/usr/bin/env bash
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH=/etc/mineshark/sensor.toml
MANAGED_MARKER="# managed-by: mineshark-offline-bundle"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this installer as root" >&2
  exit 1
fi
if [[ -f "${CONFIG_PATH}" ]] && ! grep -Fq "${MANAGED_MARKER}" "${CONFIG_PATH}"; then
  echo "refusing to overwrite unmanaged configuration: ${CONFIG_PATH}" >&2
  exit 1
fi

id mineshark >/dev/null 2>&1 || useradd --system --home /var/lib/mineshark --shell /usr/sbin/nologin mineshark
for group_name in wireshark zeek suricata; do
  getent group "${group_name}" >/dev/null && usermod -a -G "${group_name}" mineshark
done
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
install -d -o root -g mineshark -m 0750 /etc/mineshark /opt/mineshark/models
install -d -o mineshark -g mineshark -m 0750 /var/lib/mineshark /var/log/mineshark /var/spool/mineshark
python3 -m venv /opt/mineshark/venv
/opt/mineshark/venv/bin/pip install --no-index --find-links "${BUNDLE_DIR}/wheels" "${BUNDLE_DIR}/wheels/mineshark_traffic_analysis-0.1.0-py3-none-any.whl"

{
  echo "${MANAGED_MARKER}"
  sed "1{/^${MANAGED_MARKER}$/d;}" "${BUNDLE_DIR}/configs/sensor.toml"
} > "${CONFIG_PATH}"
chown root:mineshark "${CONFIG_PATH}"
chmod 0640 "${CONFIG_PATH}"
install -o root -g mineshark -m 0640 "${BUNDLE_DIR}/models/model-manifest.json" /opt/mineshark/models/model-manifest.json
install -o root -g mineshark -m 0640 "${BUNDLE_DIR}/models/deep_mineshark_legacy_20260304.pt" /opt/mineshark/models/deep_mineshark_legacy_20260304.pt
install -o root -g root -m 0644 "${BUNDLE_DIR}/systemd/mineshark-capture.service" /etc/systemd/system/mineshark-capture.service
install -o root -g root -m 0644 "${BUNDLE_DIR}/systemd/mineshark-sensor.service" /etc/systemd/system/mineshark-sensor.service
install -o root -g root -m 0644 "${BUNDLE_DIR}/logrotate/mineshark" /etc/logrotate.d/mineshark
systemctl daemon-reload
echo "installation complete; edit interface/sensor_id, run validate-config, then enable services"
