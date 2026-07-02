#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${MINESHARK_ENV_FILE:-${ROOT_DIR}/.env}"
HOST="${MINESHARK_CONSOLE_HOST:-0.0.0.0}"
PORT="${MINESHARK_CONSOLE_PORT:-8008}"

usage() {
  cat <<EOF
MineShark Console production helper

Usage:
  bash scripts/deploy/production_console.sh <command>

Commands:
  install         Create .venv when missing and install Python web dependencies.
  build-frontend Build web/frontend/dist for FastAPI static hosting.
  build-rag      Build FAISS RAG index using the configured .env.
  check          Run read-only production readiness checks.
  serve          Start Console in foreground on ${HOST}:${PORT}.
  systemd-hint   Print systemd install commands and required edits.

Environment:
  MINESHARK_ENV_FILE       Default: ${ENV_FILE}
  MINESHARK_CONSOLE_HOST   Default: ${HOST}
  MINESHARK_CONSOLE_PORT   Default: ${PORT}
EOF
}

require_env_file() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Missing env file: ${ENV_FILE}" >&2
    echo "Create one with: cp .env.production.example .env" >&2
    exit 1
  fi
}

cmd_install() {
  cd "${ROOT_DIR}"
  if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python -m pip install --upgrade pip
  python -m pip install -e ".[web]"
}

cmd_build_frontend() {
  cd "${ROOT_DIR}/web/frontend"
  npm install
  npm run build
}

cmd_build_rag() {
  require_env_file
  cd "${ROOT_DIR}"
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python scripts/rag/build_index.py --env-file "${ENV_FILE}"
}

cmd_check() {
  require_env_file
  cd "${ROOT_DIR}"
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python scripts/deploy/check_production_readiness.py --env-file "${ENV_FILE}" --host "${HOST}" --port "${PORT}"
}

cmd_serve() {
  require_env_file
  cd "${ROOT_DIR}"
  # shellcheck disable=SC1091
  source .venv/bin/activate
  export MINESHARK_ENV_FILE="${ENV_FILE}"
  mineshark-console --host "${HOST}" --port "${PORT}"
}

cmd_systemd_hint() {
  cat <<EOF
Copy and edit the service template:

sudo cp ${ROOT_DIR}/deploy/systemd/mineshark-console.service /etc/systemd/system/mineshark-console.service
sudo systemctl edit --full mineshark-console.service

Check these fields before starting:
  User=<account that can read Wazuh/Zeek/Suricata/MineShark logs>
  WorkingDirectory=${ROOT_DIR}
  Environment=MINESHARK_ENV_FILE=${ENV_FILE}
  ExecStart=${ROOT_DIR}/.venv/bin/mineshark-console --host ${HOST} --port ${PORT}

Then run:
  sudo systemctl daemon-reload
  sudo systemctl enable --now mineshark-console
  systemctl status mineshark-console
  journalctl -u mineshark-console -n 100 --no-pager
EOF
}

command="${1:-}"
case "${command}" in
  install) cmd_install ;;
  build-frontend) cmd_build_frontend ;;
  build-rag) cmd_build_rag ;;
  check) cmd_check ;;
  serve) cmd_serve ;;
  systemd-hint) cmd_systemd_hint ;;
  -h|--help|help|"") usage ;;
  *)
    echo "Unknown command: ${command}" >&2
    usage >&2
    exit 2
    ;;
esac
