from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from mineshark.agent.evidence import build_evidence_bundle
from mineshark.agent.toolbox import AgentToolbox
from mineshark.config import PROJECT_ROOT, RuntimeConfig
from mineshark.sensors.ai_provider import query_configured_ai_alerts, query_sensor_heartbeats
from mineshark.web.database import ConsoleDatabase
from mineshark.web.tasks import TASK_TYPES, TaskManager


def _require_fastapi():
    try:
        from fastapi import FastAPI, HTTPException, Query
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.staticfiles import StaticFiles
        from pydantic import BaseModel, Field
    except Exception as exc:
        raise RuntimeError("Install the web extra first: pip install -e '.[web]'") from exc
    return FastAPI, HTTPException, Query, CORSMiddleware, StaticFiles, BaseModel, Field


FastAPI, HTTPException, Query, CORSMiddleware, StaticFiles, BaseModel, Field = _require_fastapi()


class TaskCreateRequest(BaseModel):
    task_type: str = Field(..., pattern="^(preflight|evidence-only|agent-report)$")
    parameters: Dict[str, Any] = Field(default_factory=dict)


class CaseCreateRequest(BaseModel):
    alert_key: str = Field(..., min_length=1, max_length=512)
    alert_snapshot: Dict[str, Any] = Field(default_factory=dict)


class CaseDecisionUpdateRequest(BaseModel):
    status: str = Field(..., pattern="^(new|in_review|escalated|closed)$")
    disposition: Optional[str] = Field(default=None, max_length=64)
    owner: Optional[str] = Field(default=None, max_length=128)
    decision_reason: Optional[str] = Field(default=None, max_length=4000)


def _config_summary(config: RuntimeConfig) -> Dict[str, Any]:
    return {
        "deepseek": {
            "model": config.deepseek_model,
            "base_url": config.deepseek_base_url,
            "api_key_set": bool(config.deepseek_api_key),
            "thinking": config.deepseek_thinking,
        },
        "dashscope": {
            "embedding_model": config.dashscope_embedding_model,
            "api_key_set": bool(config.dashscope_api_key),
        },
        "wazuh": {
            "base_url": config.wazuh_base_url,
            "indexer_url": config.wazuh_indexer_url,
            "index_pattern": config.wazuh_index_pattern,
            "verify_ssl": config.wazuh_verify_ssl,
            "server_password_set": bool(config.wazuh_password),
            "indexer_password_set": bool(config.wazuh_indexer_password),
        },
        "paths": {
            "ai_alerts": str(config.mineshark_ai_alerts_path),
            "wazuh_alerts": str(config.wazuh_alerts_path),
            "zeek_log_dir": str(config.zeek_log_dir),
            "suricata_eve": str(config.suricata_eve_path),
            "knowledge_file": str(config.knowledge_file),
            "rag_index_dir": str(config.rag_index_dir),
            "output_root": str(config.output_root),
        },
        "ai_alert_provider": {
            "source": config.mineshark_ai_alert_source,
            "allowed_sensor_ids": list(config.mineshark_allowed_sensor_ids),
        },
    }


def _path_status(path: Path, *, expect_dir: bool = False) -> Dict[str, Any]:
    try:
        exists = path.exists()
        type_ok = path.is_dir() if expect_dir else path.is_file()
        error = None
    except OSError as exc:
        exists = False
        type_ok = False
        error = str(exc)
    status = {"path": str(path), "exists": exists, "type_ok": type_ok, "ok": exists and type_ok}
    if error:
        status["error"] = error
    return status


def _rag_status(config: RuntimeConfig) -> Dict[str, Any]:
    index_dir = config.rag_index_dir
    index_path = index_dir / "knowledge.faiss"
    metadata_path = index_dir / "metadata.json"
    status: Dict[str, Any] = {
        "path": str(index_dir),
        "knowledge_faiss": index_path.exists(),
        "metadata_json": metadata_path.exists(),
    }
    if not metadata_path.exists():
        return status
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        records = metadata.get("records", [])
        status["provider"] = metadata.get("embedding_provider", "unknown")
        status["count"] = int(metadata.get("count", len(records)))
        status["ok"] = status["knowledge_faiss"] and status["metadata_json"] and status["count"] > 0
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        status["ok"] = False
        status["error"] = str(exc)
    return status


def _risk_level(alert: Dict[str, Any]) -> str:
    score = alert.get("_mineshark_score")
    if score is None:
        score = alert.get("malware_probability") or alert.get("probability") or alert.get("risk_score")
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if value >= 0.9:
        return "high"
    if value >= 0.7:
        return "medium"
    if value >= 0.5:
        return "low"
    return "informational"


def _case_alert_key(alert: Dict[str, Any]) -> Optional[str]:
    for field in ("_mineshark_alert_id", "alert_id", "_mineshark_uid", "uid"):
        value = alert.get(field)
        if value not in (None, ""):
            return str(value)
    return None


def _source_health(
    config: RuntimeConfig,
    *,
    ai_alert_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if config.mineshark_ai_alert_source == "wazuh":
        configured = bool(config.wazuh_indexer_url and config.mineshark_allowed_sensor_ids)
        probe = ai_alert_result or {}
        probe_ok = configured and probe.get("error") is None and probe.get("exists", True) is not False
        ai_alerts = {
            "provider": "wazuh",
            "configured": configured,
            "ok": probe_ok,
            "indexer_url": config.wazuh_indexer_url,
            "index_pattern": config.wazuh_index_pattern,
            "allowed_sensor_ids": list(config.mineshark_allowed_sensor_ids),
        }
        if probe.get("error"):
            ai_alerts["error"] = probe["error"]
        wazuh_alerts = {
            "provider": "wazuh_indexer",
            "source_file": probe.get("source_file", f"wazuh://{config.wazuh_index_pattern}"),
            "exists": probe.get("exists", False),
            "ok": probe_ok,
            "matched": probe.get("matched", 0),
        }
        if probe.get("error"):
            wazuh_alerts["error"] = probe["error"]
    else:
        ai_alerts = {"provider": "local", **_path_status(config.mineshark_ai_alerts_path)}
        wazuh_alerts = {"provider": "local", **_path_status(config.wazuh_alerts_path)}
    return {
        "ai_alerts": ai_alerts,
        "wazuh_alerts": wazuh_alerts,
        "zeek": _path_status(config.zeek_log_dir, expect_dir=True),
        "suricata": _path_status(config.suricata_eve_path),
        "rag_index": _rag_status(config),
    }


def create_app(
    *,
    env_file: Optional[str] = None,
    database_path: str | Path | None = None,
    database: Optional[ConsoleDatabase] = None,
    task_manager: Optional[TaskManager] = None,
) -> Any:
    app = FastAPI(title="MineShark Console", version="0.1.0")
    startup_config = RuntimeConfig.from_env(env_file)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(startup_config.cors_allowed_origins),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    selected_database_path = database_path if database_path is not None else startup_config.console_database_path
    db = database or ConsoleDatabase(selected_database_path)
    manager = task_manager or TaskManager(db)

    def config() -> RuntimeConfig:
        return RuntimeConfig.from_env(env_file)

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        runtime = config()
        ai_alert_result = None
        if runtime.mineshark_ai_alert_source == "wazuh":
            ai_alert_result = query_configured_ai_alerts(runtime, min_probability=None, limit=1)
        return {
            "status": "ok",
            "project_root": str(PROJECT_ROOT),
            "config": _config_summary(runtime),
            "sources": _source_health(runtime, ai_alert_result=ai_alert_result),
            "sensors": query_sensor_heartbeats(runtime),
            "database": db.stats(),
        }

    @app.get("/api/overview")
    def overview() -> Dict[str, Any]:
        runtime = config()
        alerts_result = query_configured_ai_alerts(runtime, min_probability=0.5, limit=50)
        alerts = alerts_result.get("alerts", [])
        risk_counts = {"high": 0, "medium": 0, "low": 0, "informational": 0, "unknown": 0}
        for alert in alerts:
            risk_counts[_risk_level(alert)] += 1
        reports = db.list_reports(limit=5)
        latest_report = reports[0] if reports else None
        tasks = db.list_tasks(limit=8)
        return {
            "generated_at": alerts_result.get("source_file"),
            "alerts": {
                "source_file": alerts_result.get("source_file"),
                "exists": alerts_result.get("exists"),
                "total_records": alerts_result.get("total_records", 0),
                "matched": alerts_result.get("matched", 0),
                "risk_counts": risk_counts,
                "latest": alerts[:8],
                "error": alerts_result.get("error"),
            },
            "sources": _source_health(
                runtime,
                ai_alert_result=alerts_result if runtime.mineshark_ai_alert_source == "wazuh" else None,
            ),
            "tasks": tasks,
            "latest_report": latest_report,
        }

    @app.get("/api/alerts")
    def alerts(
        ip: Optional[str] = None,
        uid: Optional[str] = None,
        alert_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        threshold: float = Query(0.5, ge=0.0, le=1.0),
        limit: int = Query(50, ge=1, le=100),
    ) -> Dict[str, Any]:
        runtime = config()
        return query_configured_ai_alerts(
            runtime,
            ip=ip,
            uid=uid,
            alert_id=alert_id,
            start_time=start_time,
            end_time=end_time,
            min_probability=threshold,
            limit=limit,
        )

    @app.get("/api/evidence")
    def evidence(
        ip: Optional[str] = None,
        uid: Optional[str] = None,
        alert_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        threshold: float = Query(0.5, ge=0.0, le=1.0),
        max_events: int = Query(5, ge=1, le=50),
        top_k: int = Query(4, ge=1, le=20),
    ) -> Dict[str, Any]:
        runtime = config()
        toolbox = AgentToolbox(
            config=runtime,
            threshold=threshold,
            max_events=max_events,
            top_k=top_k,
        )
        bundle = build_evidence_bundle(
            toolbox,
            alert_id=alert_id,
            uid=uid,
            ip=ip,
            start_time=start_time,
            end_time=end_time,
            threshold=threshold,
            max_events=max_events,
            top_k=top_k,
        )
        return {"evidence_bundle": bundle, "tool_trace": toolbox.trace}

    @app.get("/api/tasks")
    def list_tasks(limit: int = Query(20, ge=1, le=100)) -> Dict[str, Any]:
        return {"tasks": db.list_tasks(limit=limit)}

    @app.get("/api/cases")
    def list_cases(limit: int = Query(20, ge=1, le=100)) -> Dict[str, Any]:
        return {"cases": db.list_cases(limit=limit)}

    @app.post("/api/cases", status_code=201)
    def create_case(request: CaseCreateRequest) -> Dict[str, Any]:
        try:
            case = db.create_case(alert_key=request.alert_key, alert_snapshot=request.alert_snapshot)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"case": case}

    @app.post("/api/cases/sync")
    def sync_cases(
        threshold: float = Query(0.5, ge=0.0, le=1.0),
        limit: int = Query(100, ge=1, le=500),
    ) -> Dict[str, Any]:
        runtime = config()
        alerts_result = query_configured_ai_alerts(
            runtime,
            min_probability=threshold,
            limit=limit,
        )
        created = 0
        skipped_existing = 0
        skipped_unidentified = 0
        for alert in alerts_result.get("alerts", []):
            alert_key = _case_alert_key(alert)
            if not alert_key:
                skipped_unidentified += 1
                continue
            _, was_created = db.create_case_if_absent(alert_key=alert_key, alert_snapshot=alert)
            if was_created:
                created += 1
            else:
                skipped_existing += 1
        return {
            "source_file": alerts_result.get("source_file"),
            "matched_alerts": alerts_result.get("matched", 0),
            "created": created,
            "skipped_existing": skipped_existing,
            "skipped_unidentified": skipped_unidentified,
            "source_error": alerts_result.get("error"),
        }

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str) -> Dict[str, Any]:
        case = db.get_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        return {"case": case}

    @app.patch("/api/cases/{case_id}")
    def update_case(case_id: str, request: CaseDecisionUpdateRequest) -> Dict[str, Any]:
        if not db.get_case(case_id):
            raise HTTPException(status_code=404, detail="Case not found")
        case = db.update_case_decision(
            case_id,
            status=request.status,
            disposition=request.disposition,
            owner=request.owner,
            decision_reason=request.decision_reason,
        )
        return {"case": case}

    @app.post("/api/tasks", status_code=202)
    def create_task(request: TaskCreateRequest) -> Dict[str, Any]:
        if request.task_type not in TASK_TYPES:
            raise HTTPException(status_code=400, detail="Unsupported task_type")
        try:
            task = manager.create_task(request.task_type, request.parameters)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"task": task}

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: str) -> Dict[str, Any]:
        task = db.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        return {"task": task}

    @app.get("/api/reports")
    def list_reports(limit: int = Query(20, ge=1, le=100)) -> Dict[str, Any]:
        return {"reports": db.list_reports(limit=limit)}

    @app.get("/api/reports/{report_id}")
    def get_report(report_id: str) -> Dict[str, Any]:
        report = db.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"report": report}

    frontend_dist = startup_config.frontend_dist
    if frontend_dist.exists():
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")

    return app


app = create_app()
