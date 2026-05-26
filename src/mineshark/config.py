from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(env_file: Optional[str] = None) -> None:
    candidate = env_file or os.getenv("MINESHARK_ENV_FILE") or ".env"
    path = Path(candidate)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    try:
        from dotenv import load_dotenv
    except Exception:
        return

    if path.exists():
        load_dotenv(path)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def resolve_project_path(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


@dataclass(frozen=True)
class RuntimeConfig:
    deepseek_api_key: str
    deepseek_base_url: str
    deepseek_model: str

    dashscope_api_key: str
    dashscope_base_url: str
    dashscope_embedding_model: str

    wazuh_base_url: str
    wazuh_username: str
    wazuh_password: str
    wazuh_indexer_url: str
    wazuh_indexer_username: str
    wazuh_indexer_password: str
    wazuh_index_pattern: str
    wazuh_verify_ssl: bool
    wazuh_timeout: int

    zeek_log_dir: Path
    suricata_eve_path: Path
    wazuh_alerts_path: Path
    mineshark_ai_alerts_path: Path
    knowledge_file: Path
    rag_index_dir: Path

    @classmethod
    def from_env(cls, env_file: Optional[str] = None) -> "RuntimeConfig":
        _load_dotenv(env_file)
        return cls(
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY", ""),
            deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            dashscope_api_key=os.getenv("DASHSCOPE_API_KEY", ""),
            dashscope_base_url=os.getenv(
                "DASHSCOPE_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1",
            ),
            dashscope_embedding_model=os.getenv(
                "DASHSCOPE_EMBEDDING_MODEL",
                "text-embedding-v4",
            ),
            wazuh_base_url=os.getenv("WAZUH_BASE_URL", "https://localhost:55000"),
            wazuh_username=os.getenv("WAZUH_USERNAME", "wazuh"),
            wazuh_password=os.getenv("WAZUH_PASSWORD", ""),
            wazuh_indexer_url=os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200"),
            wazuh_indexer_username=os.getenv("WAZUH_INDEXER_USERNAME", "admin"),
            wazuh_indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD", ""),
            wazuh_index_pattern=os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*"),
            wazuh_verify_ssl=_env_bool("WAZUH_VERIFY_SSL", False),
            wazuh_timeout=_env_int("WAZUH_TIMEOUT", 20),
            zeek_log_dir=resolve_project_path(os.getenv("ZEEK_LOG_DIR", "/opt/zeek/spool/zeek")),
            suricata_eve_path=resolve_project_path(
                os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
            ),
            wazuh_alerts_path=resolve_project_path(
                os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
            ),
            mineshark_ai_alerts_path=resolve_project_path(
                os.getenv("MINESHARK_AI_ALERTS_PATH", "/var/log/ai_alerts.json")
            ),
            knowledge_file=resolve_project_path(
                os.getenv("MINESHARK_KNOWLEDGE_FILE", "configs/reporting/security_playbook.jsonl")
            ),
            rag_index_dir=resolve_project_path(os.getenv("MINESHARK_RAG_INDEX_DIR", "outputs/rag")),
        )

    def tls_warning(self) -> str | None:
        if self.wazuh_verify_ssl:
            return None
        return "WAZUH_VERIFY_SSL=false: development mode is using HTTPS without certificate verification."
