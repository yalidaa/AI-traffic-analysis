import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.agent.cli import build_llm_kwargs, build_user_request, serialise_messages
from mineshark.config import RuntimeConfig


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
            alert_id="demo-alert-001",
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
        self.assertIn("demo-alert-001", text)
        self.assertIn("/var/log/ai_alerts.json", text)
        self.assertIn("sidecar_read_existing_ai_alerts", text)

    def test_build_llm_kwargs_enables_thinking_without_temperature(self):
        config = RuntimeConfig(
            deepseek_api_key="key",
            deepseek_base_url="https://api.deepseek.com",
            deepseek_model="deepseek-v4-pro",
            dashscope_api_key="",
            dashscope_base_url="",
            dashscope_embedding_model="",
            wazuh_base_url="",
            wazuh_username="",
            wazuh_password="",
            wazuh_indexer_url="",
            wazuh_indexer_username="",
            wazuh_indexer_password="",
            wazuh_index_pattern="",
            wazuh_verify_ssl=False,
            wazuh_timeout=5,
            zeek_log_dir=ROOT,
            suricata_eve_path=ROOT / "eve.json",
            wazuh_alerts_path=ROOT / "alerts.json",
            mineshark_ai_alerts_path=ROOT / "ai_alerts.json",
            knowledge_file=ROOT / "knowledge.jsonl",
            rag_index_dir=ROOT / "rag",
            deepseek_thinking="enabled",
            deepseek_reasoning_effort="high",
            deepseek_max_tokens=8192,
        )
        kwargs = build_llm_kwargs(config)
        self.assertNotIn("temperature", kwargs)
        self.assertEqual(kwargs["extra_body"]["thinking"]["type"], "enabled")
        self.assertEqual(kwargs["reasoning_effort"], "high")

    def test_build_llm_kwargs_disables_thinking_for_tool_agent(self):
        config = RuntimeConfig(
            deepseek_api_key="key",
            deepseek_base_url="https://api.deepseek.com",
            deepseek_model="deepseek-v4-pro",
            dashscope_api_key="",
            dashscope_base_url="",
            dashscope_embedding_model="",
            wazuh_base_url="",
            wazuh_username="",
            wazuh_password="",
            wazuh_indexer_url="",
            wazuh_indexer_username="",
            wazuh_indexer_password="",
            wazuh_index_pattern="",
            wazuh_verify_ssl=False,
            wazuh_timeout=5,
            zeek_log_dir=ROOT,
            suricata_eve_path=ROOT / "eve.json",
            wazuh_alerts_path=ROOT / "alerts.json",
            mineshark_ai_alerts_path=ROOT / "ai_alerts.json",
            knowledge_file=ROOT / "knowledge.jsonl",
            rag_index_dir=ROOT / "rag",
            deepseek_thinking="enabled",
            deepseek_reasoning_effort="high",
            deepseek_max_tokens=8192,
        )
        kwargs = build_llm_kwargs(config, allow_thinking=False)
        self.assertEqual(kwargs["extra_body"]["thinking"]["type"], "disabled")
        self.assertEqual(kwargs["temperature"], 0.2)
        self.assertNotIn("reasoning_effort", kwargs)

    def test_build_llm_kwargs_keeps_legacy_model_configurable(self):
        config = RuntimeConfig(
            deepseek_api_key="key",
            deepseek_base_url="https://api.deepseek.com/v1",
            deepseek_model="deepseek-chat",
            dashscope_api_key="",
            dashscope_base_url="",
            dashscope_embedding_model="",
            wazuh_base_url="",
            wazuh_username="",
            wazuh_password="",
            wazuh_indexer_url="",
            wazuh_indexer_username="",
            wazuh_indexer_password="",
            wazuh_index_pattern="",
            wazuh_verify_ssl=False,
            wazuh_timeout=5,
            zeek_log_dir=ROOT,
            suricata_eve_path=ROOT / "eve.json",
            wazuh_alerts_path=ROOT / "alerts.json",
            mineshark_ai_alerts_path=ROOT / "ai_alerts.json",
            knowledge_file=ROOT / "knowledge.jsonl",
            rag_index_dir=ROOT / "rag",
        )
        kwargs = build_llm_kwargs(config)
        self.assertEqual(kwargs["model"], "deepseek-chat")
        self.assertEqual(kwargs["temperature"], 0.2)
        self.assertNotIn("extra_body", kwargs)


if __name__ == "__main__":
    unittest.main()
