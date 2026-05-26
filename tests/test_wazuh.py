import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.config import RuntimeConfig
from mineshark.integrations.wazuh import WazuhIndexerClient, WazuhServerClient, read_local_alerts


def make_config(tmp_path):
    return RuntimeConfig(
        deepseek_api_key="",
        deepseek_base_url="https://api.deepseek.com/v1",
        deepseek_model="deepseek-chat",
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
        wazuh_timeout=5,
        zeek_log_dir=tmp_path,
        suricata_eve_path=tmp_path / "eve.json",
        wazuh_alerts_path=tmp_path / "alerts.json",
        mineshark_ai_alerts_path=tmp_path / "ai_alerts.json",
        knowledge_file=tmp_path / "knowledge.jsonl",
        rag_index_dir=tmp_path / "rag",
    )


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class WazuhClientTests(unittest.TestCase):
    def test_server_client_authenticates_and_queries_agents(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            client = WazuhServerClient(config)
            calls = []

            def fake_get(url, **kwargs):
                calls.append((url, kwargs))
                if url.endswith("/security/user/authenticate"):
                    return Response({"data": {"token": "abc"}})
                return Response({"data": {"affected_items": []}})

            client.session.get = fake_get
            result = client.agents(limit=3)
            self.assertEqual(result["data"]["affected_items"], [])
            self.assertIn("Bearer abc", calls[-1][1]["headers"]["Authorization"])

    def test_indexer_client_posts_query_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            client = WazuhIndexerClient(config)
            captured = {}

            def fake_post(url, **kwargs):
                captured["url"] = url
                captured["json"] = kwargs["json"]
                return Response({"hits": {"hits": [{"_source": {"rule": {"id": "1001"}}}]}})

            client.session.post = fake_post
            result = client.search_alerts(ip="10.0.0.1", text="malware", limit=1)
            self.assertEqual(result[0]["rule"]["id"], "1001")
            self.assertIn("wazuh-alerts-*", captured["url"])
            self.assertEqual(captured["json"]["size"], 1)

    def test_read_local_alerts_filters_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            alerts = Path(tmp) / "alerts.json"
            alerts.write_text(
                "\n".join(
                    [
                        json.dumps({"data": {"srcip": "10.0.0.1"}, "rule": {"id": "1"}}),
                        json.dumps({"data": {"srcip": "10.0.0.2"}, "rule": {"id": "2"}}),
                    ]
                ),
                encoding="utf-8",
            )
            result = read_local_alerts(alerts, ip="10.0.0.1")
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["rule"]["id"], "1")


if __name__ == "__main__":
    unittest.main()
