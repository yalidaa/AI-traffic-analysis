import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.agent.evidence import build_evidence_bundle
from mineshark.agent.preflight import run_preflight
from mineshark.agent.quality import evaluate_report_quality
from mineshark.config import RuntimeConfig
from mineshark.integrations.wazuh import read_local_alerts
from mineshark.sensors.ai_alerts import query_mineshark_ai_alerts
from mineshark.sensors.logs import query_suricata_alerts, query_zeek_context


def make_config(root):
    return RuntimeConfig(
        deepseek_api_key="",
        deepseek_base_url="https://api.deepseek.com",
        deepseek_model="deepseek-v4-pro",
        dashscope_api_key="",
        dashscope_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        dashscope_embedding_model="text-embedding-v4",
        wazuh_base_url="https://wazuh.local:55000",
        wazuh_username="user",
        wazuh_password="pass",
        wazuh_indexer_url="https://wazuh.local:9200",
        wazuh_indexer_username="admin",
        wazuh_indexer_password="secret",
        wazuh_index_pattern="wazuh-alerts-*",
        wazuh_verify_ssl=False,
        wazuh_timeout=1,
        zeek_log_dir=root,
        suricata_eve_path=root / "eve.json",
        wazuh_alerts_path=root / "alerts.json",
        mineshark_ai_alerts_path=root / "ai_alerts.json",
        knowledge_file=root / "knowledge.jsonl",
        rag_index_dir=root / "rag",
    )


class FakeToolbox:
    def __init__(self):
        self.trace = []

    def _record(self, name, args, result):
        self.trace.append({"tool": name, "arguments": args, "result": result})
        return result

    def query_mineshark_ai_alerts(self, **kwargs):
        return self._record(
            "query_mineshark_ai_alerts",
            kwargs,
            {
                "alerts": [
                    {
                        "alert_id": "demo-alert-001",
                        "uid": "Cdemo1",
                        "src_ip": "10.0.0.5",
                        "dst_ip": "203.0.113.10",
                        "_mineshark_score": 0.93,
                        "_mineshark_timestamp": "2026-05-28T10:00:00+08:00",
                    }
                ],
                "error": None,
            },
        )

    def query_wazuh_alerts(self, **kwargs):
        return self._record("query_wazuh_alerts", kwargs, {"alerts": [{"rule": {"id": "100500"}}], "error": None})

    def query_zeek_context(self, **kwargs):
        return self._record("query_zeek_context", kwargs, {"events": [{"uid": "Cdemo1"}], "error": None})

    def query_suricata_alerts(self, **kwargs):
        return self._record(
            "query_suricata_alerts",
            kwargs,
            {"alerts": [{"alert": {"signature": "Possible C2"}}], "error": None},
        )

    def retrieve_security_knowledge(self, *args, **kwargs):
        return self._record(
            "retrieve_security_knowledge",
            {"query": args[0], **kwargs},
            {"matches": [{"title": "C2 Beacon Evidence"}], "error": None},
        )


class AgentEnhancementTests(unittest.TestCase):
    def test_evidence_bundle_aggregates_sources_and_trace(self):
        toolbox = FakeToolbox()
        bundle = build_evidence_bundle(toolbox, alert_id="demo-alert-001", max_events=5)
        self.assertEqual(bundle["query_keys"]["uid"], "Cdemo1")
        self.assertEqual(bundle["query_keys"]["ip"], "10.0.0.5")
        self.assertEqual(bundle["missing_sources"], [])
        self.assertEqual([item["tool"] for item in toolbox.trace][0], "query_mineshark_ai_alerts")

    def test_report_quality_complete_and_incomplete(self):
        bundle = build_evidence_bundle(FakeToolbox(), alert_id="demo-alert-001")
        good = (
            "MineShark AI 告警摘要\nWazuh 告警\nZeek 连接上下文和 Suricata 证据\n"
            "RAG 知识依据\n误报与局限性：模型概率只是风险线索，需要人工复核。"
        )
        self.assertEqual(evaluate_report_quality(good, bundle)["status"], "complete")
        bad = "只有一句结论"
        result = evaluate_report_quality(bad, bundle)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("limitations", result["missing"])

    def test_preflight_reports_missing_configuration_and_wazuh_api_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root)

            class BrokenServerClient:
                def __init__(self, _config):
                    pass

                def manager_status(self):
                    raise RuntimeError("server down")

            class BrokenIndexerClient:
                def __init__(self, _config):
                    pass

                def search_alerts(self, limit=1):
                    raise RuntimeError("indexer down")

            with patch("mineshark.agent.preflight.WazuhServerClient", BrokenServerClient), patch(
                "mineshark.agent.preflight.WazuhIndexerClient", BrokenIndexerClient
            ):
                result = run_preflight(config, env_file=str(root / ".env"), check_wazuh_api=True)

            self.assertFalse(result["ok"])
            self.assertIn("deepseek_api_key", result["errors"])
            self.assertIn("wazuh_server_api", result["warnings"])
            self.assertEqual(result["checks"]["wazuh_indexer_api"]["error"], "indexer down")

    def test_preflight_records_permission_errors_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root)

            def fake_exists(self):
                if str(self).endswith("alerts.json"):
                    raise PermissionError("permission denied")
                return False

            with patch.object(Path, "exists", fake_exists):
                result = run_preflight(config, env_file=str(root / ".env"))

            self.assertFalse(result["ok"])
            self.assertIn("wazuh_alerts_path", result["errors"])
            self.assertIn("permission denied", result["checks"]["wazuh_alerts_path"]["error"])

    def test_demo_fixture_contains_correlated_event(self):
        fixture = ROOT / "tests" / "fixtures" / "demo_event"
        ai = query_mineshark_ai_alerts(
            fixture / "ai_alerts.json",
            uid="Cdemo1",
            alert_id="demo-alert-001",
            min_probability=0.5,
        )
        wazuh = read_local_alerts(fixture / "alerts.json", ip="10.0.0.5", text="100500")
        zeek = query_zeek_context(fixture / "conn.log", uid="Cdemo1", ip="10.0.0.5")
        suricata = query_suricata_alerts(fixture / "eve.json", ip="10.0.0.5")
        self.assertEqual(ai["matched"], 1)
        self.assertEqual(wazuh[0]["rule"]["id"], "100500")
        self.assertEqual(zeek["events"][0]["uid"], "Cdemo1")
        self.assertIn("C2", suricata["alerts"][0]["alert"]["signature"])


if __name__ == "__main__":
    unittest.main()
