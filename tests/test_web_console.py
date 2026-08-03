import argparse
import importlib.util
import json
import re
import sys
import tempfile
import time
import unittest
from unittest import mock
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


def contrast_ratio(foreground: str, background: str) -> float:
    def luminance(color: str) -> float:
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    foreground_luminance = luminance(foreground)
    background_luminance = luminance(background)
    lighter = max(foreground_luminance, background_luminance)
    darker = min(foreground_luminance, background_luminance)
    return (lighter + 0.05) / (darker + 0.05)


class FrontendCommandCenterContractTests(unittest.TestCase):
    def test_overview_exposes_leadership_decision_signals(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")

        for label in ("当前风险", "证据覆盖", "处置闭环", "本地部署"):
            with self.subTest(label=label):
                self.assertIn(label, app_source)

    def test_frontend_declares_a_favicon_without_a_network_request(self):
        index_source = (ROOT / "web" / "frontend" / "index.html").read_text(encoding="utf-8")

        self.assertIn('rel="icon"', index_source)
        self.assertIn('href="data:,"', index_source)

    def test_overview_exposes_a_clickable_evidence_rail(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        overview_source = app_source.split("function OverviewPage", 1)[1].split("function AlertsPage", 1)[0]

        self.assertIn('className="evidence-rail', overview_source)
        for label in ("模型信号", "证据接入", "人工案件", "最终结论"):
            with self.subTest(label=label):
                self.assertIn(label, overview_source)
        for view in ("alerts", "evidence", "cases"):
            with self.subTest(view=view):
                self.assertIn(f'setActiveView("{view}")', overview_source)

    def test_overview_uses_a_status_strip_without_a_single_sample_risk_chart(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        overview_source = app_source.split("function OverviewPage", 1)[1].split("function AlertsPage", 1)[0]

        self.assertIn('className="status-strip', overview_source)
        self.assertNotIn("<h2>风险分布</h2>", overview_source)
        self.assertNotIn('className="command-metric', overview_source)

    def test_frontend_uses_the_approved_light_command_center_tokens(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        css_source = (ROOT / "web" / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")

        self.assertIn('benign: "良性流量"', app_source)
        self.assertIn("aria-label={title || label}", app_source)
        self.assertIn("iconOnly = false", app_source)
        for token in (
            "--canvas: #F3F6F8;",
            "--sidebar: #F8FAFB;",
            "--surface: #FFFFFF;",
            "--surface-raised: #EDF2F5;",
            "--surface-strong: #E3EBEF;",
            "--border: #D7E0E4;",
            "--border-strong: #B8C5CB;",
            "--control-border: #7A8D96;",
            "--text-primary: #172126;",
            "--text-secondary: #42535B;",
            "--text-muted: #657780;",
            "--accent: #1769AA;",
            "--accent-hover: #0F568E;",
            "--evidence: #0A7F86;",
            "--evidence-text: #086B71;",
            "--risk: #C44752;",
            "--risk-text: #A73440;",
            "--warning: #976300;",
            "--success: #217A56;",
            "color-scheme: light;",
        ):
            with self.subTest(token=token):
                self.assertIn(token, css_source)
        self.assertIn("grid-template-columns: 232px minmax(0, 1fr);", css_source)

    def test_frontend_palette_is_centralized_in_root_tokens(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        css_source = (ROOT / "web" / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")
        color_literal = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)")
        _, component_css = css_source.split("}", 1)

        self.assertEqual(color_literal.findall(app_source), [])
        self.assertEqual(color_literal.findall(component_css), [])

    def test_frontend_palette_meets_contrast_contract(self):
        css_source = (ROOT / "web" / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")
        root_css = css_source.split("}", 1)[0]
        tokens = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6});", root_css))

        for token in (
            "text-primary",
            "text-secondary",
            "text-muted",
            "accent",
            "evidence",
            "risk",
            "warning",
            "success",
        ):
            with self.subTest(token=token):
                self.assertGreaterEqual(contrast_ratio(tokens[token], tokens["surface"]), 4.5)

        self.assertGreaterEqual(contrast_ratio(tokens["control-border"], tokens["surface"]), 3.0)
        self.assertGreaterEqual(contrast_ratio(tokens["risk-text"], tokens["risk-soft"]), 4.5)
        self.assertGreaterEqual(contrast_ratio(tokens["evidence-text"], tokens["evidence-soft"]), 4.5)

    def test_light_theme_keeps_interaction_and_status_color_roles_separate(self):
        css_source = (ROOT / "web" / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")

        button_block = re.search(r"\.button\s*\{([^}]*)\}", css_source, re.DOTALL).group(1)
        nav_blocks = re.findall(r"\.nav-item\.active\s*\{([^}]*)\}", css_source, re.DOTALL)
        input_blocks = re.findall(
            r"input,\s*select,\s*textarea,\s*\.case-form input,\s*\.case-form select,\s*\.case-form textarea\s*\{([^}]*)\}",
            css_source,
            re.DOTALL,
        )
        risk_blocks = re.findall(r"\.risk-high\s*\{([^}]*)\}", css_source, re.DOTALL)

        self.assertIn("background: var(--accent);", button_block)
        self.assertIn("background: var(--accent-soft);", nav_blocks[-1])
        self.assertIn("box-shadow: inset 2px 0 0 var(--accent);", nav_blocks[-1])
        self.assertIn("border: 1px solid var(--control-border);", input_blocks[-1])
        self.assertIn("background: var(--surface);", input_blocks[-1])
        self.assertIn("color: var(--risk-text);", risk_blocks[-1])

    def test_secondary_workspaces_share_the_analyst_workbench_contract(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        css_source = (ROOT / "web" / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")

        for label in (
            "指挥台",
            "研判",
            "交付留痕",
            "当前筛选范围",
            "调查上下文",
            "原始告警快照",
            "案件时间线",
            "事实快照",
            "证据台账",
            "查询窗口",
            "缺失原因",
            "报告队列",
            "可追溯阅读器",
            "任务时间线",
            "错误信息",
        ):
            with self.subTest(label=label):
                self.assertIn(label, app_source)

        for token in ("--surface-strong:", "--focus-ring:", "--table-row-height:"):
            with self.subTest(token=token):
                self.assertIn(token, css_source)

    def test_overview_keeps_single_sample_reporting_honest(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        overview_source = app_source.split("function OverviewPage", 1)[1].split("function AlertsPage", 1)[0]

        self.assertIn("样本不足以形成趋势", overview_source)
        self.assertIn("latestAlerts.length > 1", overview_source)

    def test_frontend_does_not_treat_the_overview_source_path_as_a_refresh_time(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")

        self.assertIn("const [lastRefreshedAt", app_source)
        self.assertIn("setLastRefreshedAt(new Date().toISOString())", app_source)
        self.assertNotIn("overview?.generated_at || health?.generated_at", app_source)

    def test_evidence_ledger_explains_missing_paths_and_indexes(self):
        app_source = (ROOT / "web" / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")

        self.assertIn("路径不存在", app_source)
        self.assertIn("索引缺失", app_source)
        self.assertIn("Indexer 未连接，已回退本地日志", app_source)
        self.assertIn("未限定结束时间", app_source)


class WebConsoleStorageTests(unittest.TestCase):
    def test_database_tracks_a_triage_case_from_alert_to_analyst_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = ConsoleDatabase(Path(tmp) / "console.sqlite3")
            case = db.create_case(
                alert_key="demo-alert-001",
                alert_snapshot={
                    "alert_id": "demo-alert-001",
                    "uid": "Cdemo1",
                    "src_ip": "10.0.0.5",
                    "malware_probability": 0.93,
                },
            )

            self.assertEqual(case["status"], "new")
            self.assertEqual(case["alert_key"], "demo-alert-001")
            self.assertEqual(case["alert_snapshot"]["uid"], "Cdemo1")
            self.assertIsNone(case["disposition"])

            updated = db.update_case_decision(
                case["id"],
                status="closed",
                disposition="benign",
                owner="analyst-a",
                decision_reason="Zeek and Wazuh evidence did not corroborate the model signal.",
            )

            self.assertEqual(updated["status"], "closed")
            self.assertEqual(updated["disposition"], "benign")
            self.assertEqual(updated["owner"], "analyst-a")
            self.assertIn("did not corroborate", updated["decision_reason"])
            self.assertEqual(db.list_cases()[0]["id"], case["id"])

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
    def test_wazuh_mode_health_does_not_require_a_local_ai_alert_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = write_env(root)
            with env_file.open("a", encoding="utf-8") as handle:
                handle.write("\nMINESHARK_AI_ALERT_SOURCE=wazuh\n")
                handle.write("MINESHARK_ALLOWED_SENSOR_IDS=sensor-01\n")
            (root / "ai_alerts.json").unlink()

            with mock.patch(
                "mineshark.web.api.query_sensor_heartbeats",
                return_value={"provider": "wazuh", "sensors": [], "error": "offline"},
            ):
                health = TestClient(create_app(env_file=str(env_file))).get("/api/health").json()

            self.assertEqual(health["sources"]["ai_alerts"]["provider"], "wazuh")
            self.assertTrue(health["sources"]["ai_alerts"]["configured"])
            self.assertNotIn("path", health["sources"]["ai_alerts"])

    def test_deployed_frontend_and_database_paths_come_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            frontend = root / "frontend"
            frontend.mkdir()
            (frontend / "index.html").write_text("deployed-console", encoding="utf-8")
            env_file = write_env(root)
            with env_file.open("a", encoding="utf-8") as handle:
                handle.write(f"\nMINESHARK_FRONTEND_DIST={frontend}\n")
                handle.write(f"MINESHARK_CONSOLE_DATABASE_PATH={root / 'deployed.sqlite3'}\n")

            app = create_app(env_file=str(env_file))
            client = TestClient(app)

            self.assertIn("deployed-console", client.get("/").text)
            self.assertTrue((root / "deployed.sqlite3").exists())

    def test_case_sync_creates_each_alert_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = write_env(root)
            app = create_app(env_file=str(env_file), database_path=root / "console.sqlite3")
            client = TestClient(app)

            first_sync = client.post("/api/cases/sync", params={"threshold": 0.5})
            self.assertEqual(first_sync.status_code, 200)
            self.assertEqual(first_sync.json()["created"], 1)
            self.assertEqual(first_sync.json()["skipped_existing"], 0)
            self.assertEqual(client.get("/api/cases").json()["cases"][0]["alert_key"], "demo-alert-001")

            second_sync = client.post("/api/cases/sync", params={"threshold": 0.5})
            self.assertEqual(second_sync.status_code, 200)
            self.assertEqual(second_sync.json()["created"], 0)
            self.assertEqual(second_sync.json()["skipped_existing"], 1)
            self.assertEqual(len(client.get("/api/cases").json()["cases"]), 1)

    def test_case_can_be_captured_and_closed_through_the_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = write_env(root)
            app = create_app(env_file=str(env_file), database_path=root / "console.sqlite3")
            client = TestClient(app)

            created = client.post(
                "/api/cases",
                json={
                    "alert_key": "demo-alert-001",
                    "alert_snapshot": {"uid": "Cdemo1", "malware_probability": 0.93},
                },
            )
            self.assertEqual(created.status_code, 201)
            case_id = created.json()["case"]["id"]
            self.assertEqual(created.json()["case"]["status"], "new")

            updated = client.patch(
                f"/api/cases/{case_id}",
                json={
                    "status": "closed",
                    "disposition": "benign",
                    "owner": "analyst-a",
                    "decision_reason": "The network evidence did not corroborate the model signal.",
                },
            )
            self.assertEqual(updated.status_code, 200)
            self.assertEqual(updated.json()["case"]["disposition"], "benign")
            self.assertEqual(updated.json()["case"]["owner"], "analyst-a")
            self.assertEqual(client.get("/api/cases").json()["cases"][0]["id"], case_id)

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

            cors = client.options(
                "/api/health",
                headers={
                    "Origin": "https://evil.example",
                    "Access-Control-Request-Method": "GET",
                },
            )
            self.assertNotIn("access-control-allow-origin", cors.headers)

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
