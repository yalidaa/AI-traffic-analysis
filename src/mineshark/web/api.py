from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from mineshark.agent.evidence import build_evidence_bundle
from mineshark.agent.toolbox import AgentToolbox
from mineshark.config import PROJECT_ROOT, RuntimeConfig
from mineshark.sensors.ai_alerts import query_mineshark_ai_alerts
from mineshark.web.database import ConsoleDatabase, DEFAULT_DATABASE_PATH
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
            "rag_index_dir": str(config.rag_index_dir),
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


def _source_health(config: RuntimeConfig) -> Dict[str, Any]:
    return {
        "ai_alerts": _path_status(config.mineshark_ai_alerts_path),
        "wazuh_alerts": _path_status(config.wazuh_alerts_path),
        "zeek": _path_status(config.zeek_log_dir, expect_dir=True),
        "suricata": _path_status(config.suricata_eve_path),
        "rag_index": {
            "path": str(config.rag_index_dir),
            "knowledge_faiss": (config.rag_index_dir / "knowledge.faiss").exists(),
            "metadata_json": (config.rag_index_dir / "metadata.json").exists(),
        },
    }


def create_app(
    *,
    env_file: Optional[str] = None,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    database: Optional[ConsoleDatabase] = None,
    task_manager: Optional[TaskManager] = None,
) -> Any:
    app = FastAPI(title="MineShark Console", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    db = database or ConsoleDatabase(database_path)
    manager = task_manager or TaskManager(db)

    def config() -> RuntimeConfig:
        return RuntimeConfig.from_env(env_file)

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        runtime = config()
        return {
            "status": "ok",
            "project_root": str(PROJECT_ROOT),
            "config": _config_summary(runtime),
            "sources": _source_health(runtime),
            "database": db.stats(),
        }

    @app.get("/api/overview")
    def overview() -> Dict[str, Any]:
        runtime = config()
        alerts_result = query_mineshark_ai_alerts(runtime.mineshark_ai_alerts_path, min_probability=0.5, limit=50)
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
            "sources": _source_health(runtime),
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
        return query_mineshark_ai_alerts(
            runtime.mineshark_ai_alerts_path,
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

    frontend_dist = PROJECT_ROOT / "web" / "frontend" / "dist"
    if frontend_dist.exists():
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")

    return app


app = create_app()
