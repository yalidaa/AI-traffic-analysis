import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.agent.cli import build_user_request, serialise_messages


class FakeMessage:
    type = "ai"
    content = "报告内容"
    name = "assistant"
    tool_calls = [{"name": "query_wazuh_alerts"}]


class AgentCliTests(unittest.TestCase):
    def test_serialise_messages_keeps_tool_calls(self):
        result = serialise_messages([FakeMessage()])
        self.assertEqual(result[0]["content"], "报告内容")
        self.assertEqual(result[0]["tool_calls"][0]["name"], "query_wazuh_alerts")

    def test_build_user_request_includes_runtime_context(self):
        args = argparse.Namespace(
            task="生成报告",
            ai_alerts_path="/var/log/ai_alerts.json",
            log_file="sample.log",
            ip="10.0.0.1",
            uid=None,
            start_time=None,
            end_time=None,
            threshold=0.7,
            max_events=5,
            top_k=4,
            rerun_model=False,
        )
        text = build_user_request(args)
        self.assertIn("10.0.0.1", text)
        self.assertIn("sample.log", text)
        self.assertIn("/var/log/ai_alerts.json", text)
        self.assertIn("sidecar_read_existing_ai_alerts", text)


if __name__ == "__main__":
    unittest.main()
