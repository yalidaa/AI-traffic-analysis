from __future__ import annotations

import argparse
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from mineshark.agent.cli import (
    DEFAULT_OUTPUT_JSON,
    DEFAULT_OUTPUT_MD,
    run_agent_audit,
    write_report,
)
from mineshark.config import PROJECT_ROOT
from mineshark.web.database import ConsoleDatabase


TaskRunner = Callable[[argparse.Namespace], Dict[str, Any]]
ReportWriter = Callable[[Dict[str, Any], str, str], None]

TASK_TYPES = {"preflight", "evidence-only", "agent-report"}


def _clean_parameters(parameters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    raw = dict(parameters or {})
    allowed = {
        "env_file",
        "alert_id",
        "ip",
        "uid",
        "start_time",
        "end_time",
        "threshold",
        "max_events",
        "top_k",
        "recursion_limit",
        "preflight_check_wazuh_api",
    }
    cleaned = {key: raw[key] for key in allowed if raw.get(key) not in (None, "")}
    if "threshold" in cleaned:
        cleaned["threshold"] = float(cleaned["threshold"])
    if "max_events" in cleaned:
        cleaned["max_events"] = int(cleaned["max_events"])
    if "top_k" in cleaned:
        cleaned["top_k"] = int(cleaned["top_k"])
    if "recursion_limit" in cleaned:
        cleaned["recursion_limit"] = int(cleaned["recursion_limit"])
    return cleaned


def build_agent_args(task_type: str, parameters: Dict[str, Any]) -> argparse.Namespace:
    if task_type not in TASK_TYPES:
        raise ValueError(f"Unsupported task_type: {task_type}")
    params = _clean_parameters(parameters)
    return argparse.Namespace(
        env_file=params.get("env_file"),
        checkpoint="checkpoints/main_in_domain.pt",
        log_file=None,
        ai_alerts_path=None,
        alert_id=params.get("alert_id"),
        ip=params.get("ip"),
        uid=params.get("uid"),
        start_time=params.get("start_time"),
        end_time=params.get("end_time"),
        threshold=float(params.get("threshold", 0.5)),
        max_events=int(params.get("max_events", 5)),
        top_k=int(params.get("top_k", 4)),
        recursion_limit=int(params.get("recursion_limit", 18)),
        preflight_only=task_type == "preflight",
        preflight_check_wazuh_api=bool(params.get("preflight_check_wazuh_api", False)),
        evidence_only=task_type == "evidence-only",
        strict_report_quality=False,
        rerun_model=False,
        task="生成一次谨慎、带证据链的中文安全研判报告。",
        output_json=DEFAULT_OUTPUT_JSON,
        output_md=DEFAULT_OUTPUT_MD,
    )


def summarise_report(report: Dict[str, Any]) -> Dict[str, Any]:
    bundle = report.get("evidence_bundle") or {}
    preflight = report.get("preflight") or {}
    quality = report.get("quality_checks") or {}
    selected_alerts = bundle.get("selected_alerts") or []
    wazuh_alerts = (bundle.get("wazuh_evidence") or {}).get("alerts") or []
    zeek_events = (bundle.get("zeek_context") or {}).get("events") or []
    suricata_alerts = (bundle.get("suricata_alerts") or {}).get("alerts") or []
    rag_matches = (bundle.get("rag_matches") or {}).get("matches") or []
    return {
        "generated_at": report.get("generated_at"),
        "report_status": report.get("report_status"),
        "preflight_ok": preflight.get("ok"),
        "preflight_errors": preflight.get("errors", []),
        "preflight_warnings": preflight.get("warnings", []),
        "quality_missing": quality.get("missing", []),
        "counts": {
            "ai_alerts": len(selected_alerts),
            "wazuh_alerts": len(wazuh_alerts),
            "zeek_events": len(zeek_events),
            "suricata_alerts": len(suricata_alerts),
            "rag_matches": len(rag_matches),
        },
        "missing_sources": bundle.get("missing_sources", []),
        "errors": bundle.get("errors", []),
    }


class TaskManager:
    def __init__(
        self,
        database: ConsoleDatabase,
        *,
        runner: TaskRunner = run_agent_audit,
        writer: ReportWriter = write_report,
        max_workers: int = 1,
    ):
        self.database = database
        self.runner = runner
        self.writer = writer
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="mineshark-console")

    def create_task(self, task_type: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if task_type not in TASK_TYPES:
            raise ValueError(f"Unsupported task_type: {task_type}")
        cleaned = _clean_parameters(parameters)
        task_id = uuid.uuid4().hex
        task = self.database.create_task(task_id, task_type, cleaned)
        self.executor.submit(self._run_task, task_id, task_type, cleaned)
        return task

    def _run_task(self, task_id: str, task_type: str, parameters: Dict[str, Any]) -> None:
        self.database.mark_running(task_id)
        try:
            args = build_agent_args(task_type, parameters)
            report = self.runner(args)
            markdown = str(report.get("markdown_report") or "").strip() + "\n"
            snapshot_json, snapshot_md = self._snapshot_paths(task_id, task_type)

            if task_type == "agent-report":
                self.writer(report, DEFAULT_OUTPUT_JSON, DEFAULT_OUTPUT_MD)

            self.writer(report, str(snapshot_json), str(snapshot_md))
            self.database.finish_task(
                task_id,
                summary=summarise_report(report),
                report=report,
                markdown=markdown,
                output_json_path=str(snapshot_json),
                output_md_path=str(snapshot_md),
            )
        except Exception as exc:
            self.database.fail_task(
                task_id,
                str(exc),
                summary={"traceback": traceback.format_exc(limit=8)},
            )

    @staticmethod
    def _snapshot_paths(task_id: str, task_type: str) -> tuple[Path, Path]:
        directory = PROJECT_ROOT / "outputs" / "console" / "tasks"
        directory.mkdir(parents=True, exist_ok=True)
        stem = f"{task_type}_{task_id}"
        return directory / f"{stem}.json", directory / f"{stem}.md"
