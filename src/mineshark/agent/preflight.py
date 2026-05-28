from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from mineshark.config import PROJECT_ROOT, RuntimeConfig
from mineshark.integrations.wazuh import WazuhIndexerClient, WazuhServerClient
from mineshark.rag.store import INDEX_FILE, METADATA_FILE


def _env_file_status(env_file: Optional[str]) -> Dict[str, Any]:
    candidate = Path(env_file or ".env")
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return {
        "path": str(candidate.resolve()),
        "exists": candidate.exists(),
        "ok": candidate.exists(),
        "severity": "warning" if not candidate.exists() else "ok",
    }


def _path_status(path: Path, *, expect_dir: bool = False, required: bool = True) -> Dict[str, Any]:
    exists = path.exists()
    type_ok = path.is_dir() if expect_dir else path.is_file()
    ok = exists and type_ok
    return {
        "path": str(path),
        "exists": exists,
        "type_ok": type_ok,
        "ok": ok or not required,
        "severity": "error" if required and not ok else "ok",
    }


def _secret_status(value: str, *, required: bool = True) -> Dict[str, Any]:
    ok = bool(value) or not required
    return {
        "set": bool(value),
        "ok": ok,
        "severity": "error" if required and not ok else "ok",
    }


def run_preflight(
    config: RuntimeConfig,
    *,
    env_file: Optional[str] = None,
    check_wazuh_api: bool = False,
) -> Dict[str, Any]:
    checks: Dict[str, Any] = {
        "env_file": _env_file_status(env_file),
        "deepseek_api_key": _secret_status(config.deepseek_api_key),
        "deepseek_model": {
            "value": config.deepseek_model,
            "ok": bool(config.deepseek_model),
            "severity": "ok" if config.deepseek_model else "error",
        },
        "deepseek_base_url": {
            "value": config.deepseek_base_url,
            "ok": bool(config.deepseek_base_url),
            "severity": "ok" if config.deepseek_base_url else "error",
        },
        "dashscope_api_key": _secret_status(config.dashscope_api_key),
        "ai_alerts_path": _path_status(config.mineshark_ai_alerts_path),
        "wazuh_alerts_path": _path_status(config.wazuh_alerts_path),
        "zeek_log_dir": _path_status(config.zeek_log_dir, expect_dir=True),
        "suricata_eve_path": _path_status(config.suricata_eve_path),
        "rag_index": {
            "path": str(config.rag_index_dir),
            "knowledge_faiss": (config.rag_index_dir / INDEX_FILE).exists(),
            "metadata_json": (config.rag_index_dir / METADATA_FILE).exists(),
        },
    }
    checks["rag_index"]["ok"] = bool(checks["rag_index"]["knowledge_faiss"] and checks["rag_index"]["metadata_json"])
    checks["rag_index"]["severity"] = "ok" if checks["rag_index"]["ok"] else "warning"

    if check_wazuh_api:
        try:
            manager_status = WazuhServerClient(config).manager_status()
            checks["wazuh_server_api"] = {"ok": True, "severity": "ok", "manager_status": manager_status}
        except Exception as exc:
            checks["wazuh_server_api"] = {"ok": False, "severity": "warning", "error": str(exc)}
        try:
            alerts = WazuhIndexerClient(config).search_alerts(limit=1)
            checks["wazuh_indexer_api"] = {"ok": True, "severity": "ok", "sample_count": len(alerts)}
        except Exception as exc:
            checks["wazuh_indexer_api"] = {"ok": False, "severity": "warning", "error": str(exc)}

    errors = [name for name, item in checks.items() if item.get("severity") == "error"]
    warnings = [name for name, item in checks.items() if item.get("severity") == "warning"]
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }
