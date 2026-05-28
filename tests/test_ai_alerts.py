import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.agent.toolbox import AgentToolbox
from mineshark.config import RuntimeConfig
from mineshark.sensors.ai_alerts import query_mineshark_ai_alerts


def make_config(tmp_path):
    return RuntimeConfig(
        deepseek_api_key="",
        deepseek_base_url="https://api.deepseek.com/v1",
        deepseek_model="deepseek-chat",
        dashscope_api_key="",
        dashscope_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        dashscope_embedding_model="text-embedding-v4",
        wazuh_base_url="https://localhost:55000",
        wazuh_username="wazuh",
        wazuh_password="",
        wazuh_indexer_url="https://localhost:9200",
        wazuh_indexer_username="admin",
        wazuh_indexer_password="",
        wazuh_index_pattern="wazuh-alerts-*",
        wazuh_verify_ssl=False,
        wazuh_timeout=5,
        zeek_log_dir=tmp_path,
        suricata_eve_path=tmp_path / "eve.json",
        wazuh_alerts_path=tmp_path / "alerts.json",
        mineshark_ai_alerts_path=tmp_path / "ai_alerts.json",
        knowledge_file=tmp_path / "knowledge.jsonl",
        rag_index_dir=tmp_path / "rag",
    )


class MineSharkAiAlertsTests(unittest.TestCase):
    def test_empty_ai_alerts_file_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ai_alerts.json"
            path.write_text("", encoding="utf-8")
            result = query_mineshark_ai_alerts(path)
            self.assertTrue(result["exists"])
            self.assertTrue(result["empty"])
            self.assertEqual(result["alerts"], [])

    def test_jsonl_filters_ip_threshold_and_skips_invalid_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ai_alerts.json"
            records = [
                {"timestamp": "2026-05-26T14:00:00+08:00", "src_ip": "10.0.0.1", "malware_probability": 0.91},
                "not-json",
                {"timestamp": "2026-05-26T14:01:00+08:00", "src_ip": "10.0.0.2", "malware_probability": 0.95},
                {"timestamp": "2026-05-26T14:02:00+08:00", "src_ip": "10.0.0.1", "malware_probability": 0.2},
            ]
            path.write_text(
                "\n".join(item if isinstance(item, str) else json.dumps(item) for item in records),
                encoding="utf-8",
            )
            result = query_mineshark_ai_alerts(path, ip="10.0.0.1", min_probability=0.5)
            self.assertEqual(result["invalid_lines"], 1)
            self.assertEqual(result["matched"], 1)
            self.assertEqual(result["alerts"][0]["src_ip"], "10.0.0.1")

    def test_jsonl_filters_uid_and_alert_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ai_alerts.json"
            path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "alert_id": "demo-alert-001",
                                "uid": "Cdemo1",
                                "src_ip": "10.0.0.1",
                                "malware_probability": 0.91,
                            }
                        ),
                        json.dumps(
                            {
                                "alert_id": "demo-alert-002",
                                "uid": "Cdemo2",
                                "src_ip": "10.0.0.1",
                                "malware_probability": 0.92,
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )
            result = query_mineshark_ai_alerts(
                path,
                uid="Cdemo1",
                alert_id="demo-alert-001",
                min_probability=0.5,
            )
            self.assertEqual(result["matched"], 1)
            self.assertEqual(result["alerts"][0]["_mineshark_uid"], "Cdemo1")
            self.assertEqual(result["alerts"][0]["_mineshark_alert_id"], "demo-alert-001")

    def test_agent_tool_records_ai_alert_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_config(root)
            config.mineshark_ai_alerts_path.write_text(
                json.dumps({"alerts": [{"src_ip": "10.0.0.1", "score": 0.8}]}),
                encoding="utf-8",
            )
            toolbox = AgentToolbox(config=config, threshold=0.5)
            result = toolbox.query_mineshark_ai_alerts(ip="10.0.0.1")
            self.assertEqual(result["matched"], 1)
            self.assertEqual(toolbox.trace[0]["tool"], "query_mineshark_ai_alerts")


if __name__ == "__main__":
    unittest.main()
