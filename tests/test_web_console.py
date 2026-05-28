import argparse
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None

if FASTAPI_AVAILABLE:
    from fastapi.testclient import TestClient

    from mineshark.web.api import create_app
from mineshark.web.database import ConsoleDatabase
from mineshark.web.tasks import TaskManager, build_agent_args


def write_env(root: Path) -> Path:
    env_file = root / ".env"
    env_file.write_text(
        "\n".join(
            [
                "DEEPSEEK_API_KEY=super-secret-deepseek",
                "DASHSCOPE_API_KEY=super-secret-dashscope",
                "WAZUH_PASSWORD=super-secret-wazuh",
                "WAZUH_INDEXER_PASSWORD=super-secret-indexer",
                f"MINESHARK_AI_ALERTS_PATH={root / 'ai_alerts.json'}",
                f"WAZUH_ALERTS_PATH={root / 'alerts.json'}",
                f"ZEEK_LOG_DIR={root}",
                f"SURICATA_EVE_PATH={root / 'eve.json'}",
                f"MINESHARK_RAG_INDEX_DIR={root / 'rag'}",
            ]
        ),
        encoding="utf-8",
    )
    (root / "ai_alerts.json").write_text(
        json.dumps(
            {
                "alert_id": "demo-alert-001",
                "uid": "Cdemo1",
                "timestamp": "2026-05-28T10:00:00+08:00",
                "src_ip": "10.0.0.5",
                "dst_ip": "203.0.113.10",
                "malware_probability": 0.93,
            }
        ),
        encoding="utf-8",
    )
    (root / "alerts.json").write_text("", encoding="utf-8")
    (root / "eve.json").write_text("", encoding="utf-8")
    (root / "rag").mkdir()
    return env_file


def fake_runner(args: argparse.Namespace):
    mode = "preflight" if args.preflight_only else "evidence-only" if args.evidence_only else "agent-report"
    return {
        "generated_at": "2026-05-28T12:00:00+00:00",
        "input": {"mode": mode, "alert_id": args.alert_id},
        "preflight": {"ok": True, "errors": [], "warnings": []},
        "evidence_bundle": {
            "selected_alerts": [{"alert_id": args.alert_id or "demo-alert-001"}],
            "wazuh_evidence": {"alerts": [{}]},
            "zeek_context": {"events": [{}]},
            "suricata_alerts": {"alerts": [{}]},
            "rag_matches": {"matches": [{}]},
            "missing_sources": [],
            "errors": [],
        },
        "quality_checks": {"status": "complete", "missing": []},
        "report_status": "complete",
        "markdown_report": f"# {mode}\n\n报告正文",
    }


class WebConsoleStorageTests(unittest.TestCase):
    def test_database_saves_full_report_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = ConsoleDatabase(Path(tmp) / "console.sqlite3")
            db.create_task("task-1", "agent-report", {"alert_id": "demo-alert-001"})
            db.mark_running("task-1")
            db.finish_task(
                "task-1",
                summary={"report_status": "complete"},
                report={"markdown_report": "# 报告", "safe": True},
                markdown="# 报告\n",
                output_json_path="outputs/console/tasks/task-1.json",
                output_md_path="outputs/console/tasks/task-1.md",
            )
            reports = db.list_reports()
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0]["report"]["safe"], True)
            self.assertEqual(db.get_report("task-1")["markdown"], "# 报告\n")

    def test_task_manager_runs_all_supported_modes_and_writes_default_agent_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = ConsoleDatabase(Path(tmp) / "console.sqlite3")
            writes = []

            def fake_writer(report, output_json, output_md):
                writes.append((output_json, output_md))
                Path(output_json).parent.mkdir(parents=True, exist_ok=True)
                Path(output_json).write_text(json.dumps(report), encoding="utf-8")
                Path(output_md).write_text(report["markdown_report"], encoding="utf-8")

            manager = TaskManager(db, runner=fake_runner, writer=fake_writer)
            task_ids = [
                manager.create_task("preflight")["id"],
                manager.create_task("evidence-only", {"alert_id": "demo-alert-001"})["id"],
                manager.create_task("agent-report", {"alert_id": "demo-alert-001"})["id"],
            ]
            deadline = time.time() + 10
            while time.time() < deadline:
                tasks = [db.get_task(task_id) for task_id in task_ids]
                if all(task["status"] == "succeeded" for task in tasks):
                    break
                time.sleep(0.05)
            self.assertTrue(all(db.get_task(task_id)["status"] == "succeeded" for task_id in task_ids))
            self.assertEqual(len(db.list_reports()), 3)
            self.assertTrue(any(output_json.endswith("agent_audit_report.json") for output_json, _ in writes))

    def test_build_agent_args_never_enables_rerun_model(self):
        args = build_agent_args("agent-report", {"threshold": "0.7", "max_events": "3"})
        self.assertFalse(args.rerun_model)
        self.assertFalse(args.preflight_only)
        self.assertFalse(args.evidence_only)
        self.assertEqual(args.threshold, 0.7)
        self.assertEqual(args.max_events, 3)


@unittest.skipUnless(FASTAPI_AVAILABLE, "fastapi is not installed")
class WebConsoleApiTests(unittest.TestCase):
    def test_health_redacts_secret_values_and_alerts_query_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = write_env(root)
            app = create_app(env_file=str(env_file), database_path=root / "console.sqlite3")
            client = TestClient(app)

            health = client.get("/api/health")
            self.assertEqual(health.status_code, 200)
            payload_text = json.dumps(health.json(), ensure_ascii=False)
            self.assertIn("api_key_set", payload_text)
            self.assertNotIn("super-secret", payload_text)

            alerts = client.get("/api/alerts", params={"threshold": 0.5})
            self.assertEqual(alerts.status_code, 200)
            self.assertEqual(alerts.json()["matched"], 1)

    def test_preflight_task_can_be_created_and_polled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = write_env(root)
            app = create_app(env_file=str(env_file), database_path=root / "console.sqlite3")
            client = TestClient(app)

            created = client.post("/api/tasks", json={"task_type": "preflight", "parameters": {}})
            self.assertEqual(created.status_code, 202)
            task_id = created.json()["task"]["id"]
            deadline = time.time() + 10
            task = None
            while time.time() < deadline:
                response = client.get(f"/api/tasks/{task_id}")
                task = response.json()["task"]
                if task["status"] in {"succeeded", "failed"}:
                    break
                time.sleep(0.05)
            self.assertEqual(task["status"], "succeeded")
            self.assertTrue(client.get("/api/reports").json()["reports"])


if __name__ == "__main__":
    unittest.main()
