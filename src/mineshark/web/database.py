from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from mineshark.config import PROJECT_ROOT, resolve_project_path


DEFAULT_DATABASE_PATH = PROJECT_ROOT / "outputs" / "console" / "mineshark_console.sqlite3"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, default=str)


def _json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


class ConsoleDatabase:
    """Small SQLite task/report store for the MineShark Console."""

    def __init__(self, path: str | Path = DEFAULT_DATABASE_PATH):
        self.path = resolve_project_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def init_schema(self) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    parameters_json TEXT NOT NULL,
                    summary_json TEXT,
                    error TEXT,
                    report_json TEXT,
                    report_markdown TEXT,
                    output_json_path TEXT,
                    output_md_path TEXT
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    alert_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    disposition TEXT,
                    owner TEXT,
                    decision_reason TEXT,
                    alert_snapshot_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_cases_alert_key ON cases(alert_key)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_cases_updated_at ON cases(updated_at DESC)")

    def create_task(self, task_id: str, task_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO tasks (id, task_type, status, created_at, parameters_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (task_id, task_type, "queued", now, _json_dumps(parameters)),
            )
        task = self.get_task(task_id)
        if task is None:
            raise RuntimeError(f"Task {task_id} was not persisted.")
        return task

    def create_case(self, *, alert_key: str, alert_snapshot: Dict[str, Any]) -> Dict[str, Any]:
        case, _ = self.create_case_if_absent(alert_key=alert_key, alert_snapshot=alert_snapshot)
        return case

    def create_case_if_absent(
        self,
        *,
        alert_key: str,
        alert_snapshot: Dict[str, Any],
    ) -> tuple[Dict[str, Any], bool]:
        if not alert_key.strip():
            raise ValueError("alert_key is required")
        case_id = uuid.uuid4().hex
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM cases WHERE alert_key = ? ORDER BY created_at DESC LIMIT 1",
                (alert_key.strip(),),
            ).fetchone()
            if existing:
                return self._case_from_row(existing), False
            connection.execute(
                """
                INSERT INTO cases (
                    id, alert_key, status, disposition, owner, decision_reason,
                    alert_snapshot_json, created_at, updated_at, closed_at
                )
                VALUES (?, ?, ?, NULL, NULL, NULL, ?, ?, ?, NULL)
                """,
                (case_id, alert_key.strip(), "new", _json_dumps(alert_snapshot), now, now),
            )
            row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise RuntimeError(f"Case {case_id} was not persisted.")
        return self._case_from_row(row), True

    def update_case_decision(
        self,
        case_id: str,
        *,
        status: str,
        disposition: Optional[str],
        owner: Optional[str],
        decision_reason: Optional[str],
    ) -> Dict[str, Any]:
        if status not in {"new", "in_review", "escalated", "closed"}:
            raise ValueError(f"Unsupported case status: {status}")
        now = utc_now()
        closed_at = now if status == "closed" else None
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE cases
                   SET status = ?,
                       disposition = ?,
                       owner = ?,
                       decision_reason = ?,
                       updated_at = ?,
                       closed_at = ?
                 WHERE id = ?
                """,
                (status, disposition, owner, decision_reason, now, closed_at, case_id),
            )
        if cursor.rowcount != 1:
            raise ValueError(f"Case not found: {case_id}")
        case = self.get_case(case_id)
        if case is None:
            raise RuntimeError(f"Case {case_id} disappeared after update.")
        return case

    def mark_running(self, task_id: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE tasks SET status = ?, started_at = ? WHERE id = ?",
                ("running", utc_now(), task_id),
            )

    def finish_task(
        self,
        task_id: str,
        *,
        summary: Dict[str, Any],
        report: Dict[str, Any],
        markdown: str,
        output_json_path: Optional[str] = None,
        output_md_path: Optional[str] = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE tasks
                   SET status = ?,
                       finished_at = ?,
                       summary_json = ?,
                       error = NULL,
                       report_json = ?,
                       report_markdown = ?,
                       output_json_path = ?,
                       output_md_path = ?
                 WHERE id = ?
                """,
                (
                    "succeeded",
                    utc_now(),
                    _json_dumps(summary),
                    _json_dumps(report),
                    markdown,
                    output_json_path,
                    output_md_path,
                    task_id,
                ),
            )

    def fail_task(self, task_id: str, error: str, *, summary: Optional[Dict[str, Any]] = None) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE tasks
                   SET status = ?,
                       finished_at = ?,
                       summary_json = ?,
                       error = ?
                 WHERE id = ?
                """,
                ("failed", utc_now(), _json_dumps(summary or {}), error, task_id),
            )

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._task_from_row(row) if row else None

    def list_tasks(self, limit: int = 20) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [self._task_from_row(row) for row in rows]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return self._case_from_row(row) if row else None

    def get_case_by_alert_key(self, alert_key: str) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM cases WHERE alert_key = ? ORDER BY created_at DESC LIMIT 1",
                (alert_key,),
            ).fetchone()
        return self._case_from_row(row) if row else None

    def list_cases(self, limit: int = 20) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [self._case_from_row(row) for row in rows]

    def list_reports(self, limit: int = 20) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM tasks
                 WHERE report_json IS NOT NULL OR report_markdown IS NOT NULL
                 ORDER BY finished_at DESC, created_at DESC
                 LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [self._report_from_row(row) for row in rows]

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM tasks
                 WHERE id = ? AND (report_json IS NOT NULL OR report_markdown IS NOT NULL)
                """,
                (report_id,),
            ).fetchone()
        return self._report_from_row(row) if row else None

    def stats(self) -> Dict[str, Any]:
        with self.connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            reports = connection.execute(
                "SELECT COUNT(*) FROM tasks WHERE report_json IS NOT NULL OR report_markdown IS NOT NULL"
            ).fetchone()[0]
        return {"path": str(self.path), "exists": self.path.exists(), "tasks": total, "reports": reports}

    @staticmethod
    def _task_from_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "task_type": row["task_type"],
            "status": row["status"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "parameters": _json_loads(row["parameters_json"], {}),
            "summary": _json_loads(row["summary_json"], {}),
            "error": row["error"],
            "output_json_path": row["output_json_path"],
            "output_md_path": row["output_md_path"],
            "has_report": bool(row["report_json"] or row["report_markdown"]),
        }

    @staticmethod
    def _case_from_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "alert_key": row["alert_key"],
            "status": row["status"],
            "disposition": row["disposition"],
            "owner": row["owner"],
            "decision_reason": row["decision_reason"],
            "alert_snapshot": _json_loads(row["alert_snapshot_json"], {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "closed_at": row["closed_at"],
        }

    @staticmethod
    def _report_from_row(row: sqlite3.Row) -> Dict[str, Any]:
        summary = _json_loads(row["summary_json"], {})
        report = _json_loads(row["report_json"], {})
        markdown = row["report_markdown"] or ""
        return {
            "id": row["id"],
            "task_type": row["task_type"],
            "status": row["status"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "parameters": _json_loads(row["parameters_json"], {}),
            "summary": summary,
            "error": row["error"],
            "report": report,
            "markdown": markdown,
            "output_json_path": row["output_json_path"],
            "output_md_path": row["output_md_path"],
        }
