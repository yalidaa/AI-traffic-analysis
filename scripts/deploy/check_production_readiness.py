from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

from mineshark.agent.preflight import run_preflight
from mineshark.config import PROJECT_ROOT, RuntimeConfig


def _status_icon(severity: str, ok: bool) -> str:
    if severity == "warning":
        return "WARN"
    return "OK" if ok else "FAIL"


def _short_message(item: Dict[str, Any]) -> str:
    if "path" in item:
        return str(item["path"])
    if "value" in item:
        return str(item["value"])
    if "error" in item:
        return str(item["error"])
    return ""


def _check_frontend_dist(project_root: Path) -> Dict[str, Any]:
    index_html = project_root / "web" / "frontend" / "dist" / "index.html"
    ok = index_html.is_file()
    return {
        "ok": ok,
        "severity": "ok" if ok else "error",
        "path": str(index_html),
        "hint": "Run: cd web/frontend && npm install && npm run build",
    }


def _check_port_available(host: str, port: int) -> Dict[str, Any]:
    bind_host = "0.0.0.0" if host in {"", "::"} else host
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_host, port))
    except OSError as exc:
        return {
            "ok": False,
            "severity": "error",
            "value": f"{host}:{port}",
            "error": str(exc),
            "hint": f"Stop the existing service on port {port} or choose another port.",
        }
    finally:
        sock.close()
    return {"ok": True, "severity": "ok", "value": f"{host}:{port}"}


def _iter_checks(checks: Dict[str, Dict[str, Any]]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for name in sorted(checks):
        yield name, checks[name]


def print_report(result: Dict[str, Any]) -> None:
    print("MineShark production readiness")
    print(f"Project root: {PROJECT_ROOT}")
    print("")
    for name, item in _iter_checks(result["checks"]):
        ok = bool(item.get("ok"))
        severity = str(item.get("severity", "ok" if ok else "error"))
        message = _short_message(item)
        print(f"[{_status_icon(severity, ok):4}] {name}: {message}")
        if item.get("error"):
            print(f"       error: {item['error']}")
        if item.get("hint"):
            print(f"       next: {item['hint']}")

    print("")
    if result["errors"]:
        print("Blocking items:")
        for name in result["errors"]:
            print(f"- {name}")
    if result["warnings"]:
        print("Warnings:")
        for name in result["warnings"]:
            print(f"- {name}")
    if result["ok"]:
        print("Ready for foreground start:")
        print("MINESHARK_ENV_FILE=.env mineshark-console --host 0.0.0.0 --port 8008")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run read-only MineShark production deployment checks.")
    parser.add_argument("--env-file", default=".env", help="Runtime .env file used by MineShark Console.")
    parser.add_argument("--host", default="0.0.0.0", help="Console bind host to check.")
    parser.add_argument("--port", type=int, default=8008, help="Console bind port to check.")
    parser.add_argument("--check-wazuh-api", action="store_true", help="Also check Wazuh server and indexer APIs.")
    parser.add_argument("--allow-warnings", action="store_true", help="Exit 0 when only warnings remain.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = RuntimeConfig.from_env(args.env_file)
    result = run_preflight(config, env_file=args.env_file, check_wazuh_api=args.check_wazuh_api)
    checks = dict(result["checks"])
    checks["frontend_dist"] = _check_frontend_dist(PROJECT_ROOT)
    checks["console_port"] = _check_port_available(args.host, args.port)

    errors = sorted(name for name, item in checks.items() if item.get("severity") == "error")
    warnings = sorted(name for name, item in checks.items() if item.get("severity") == "warning")
    final = {"ok": not errors, "errors": errors, "warnings": warnings, "checks": checks}
    print_report(final)
    if final["ok"] or (args.allow_warnings and not errors):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
