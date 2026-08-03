import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from mineshark.agent.toolbox import AgentToolbox
from mineshark.sensors.ai_provider import (
    query_configured_ai_alerts,
    query_sensor_evidence_snapshots,
    query_sensor_heartbeats,
)
from tests.test_wazuh import make_config


class FakeIndexer:
    records = []
    calls = []

    def __init__(self, _config):
        pass

    def search_mineshark_events(self, **kwargs):
        self.calls.append(kwargs)
        return list(self.records)


class AiAlertProviderTests(unittest.TestCase):
    def test_wazuh_evidence_snapshots_are_filtered_by_alert_and_sensor(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(
                make_config(Path(tmp)),
                mineshark_ai_alert_source="wazuh",
                mineshark_allowed_sensor_ids=("sensor-01",),
            )
            FakeIndexer.records = [
                {
                    "data": {
                        "schema_version": 1,
                        "event_type": "evidence_snapshot",
                        "event_id": "snapshot-1",
                        "alert_event_id": "alert-1",
                        "sensor_id": "sensor-01",
                        "evidence": {"zeek": {"events": [{"uid": "C1"}]}},
                    }
                },
                {
                    "data": {
                        "schema_version": 1,
                        "event_type": "evidence_snapshot",
                        "event_id": "snapshot-2",
                        "alert_event_id": "alert-2",
                        "sensor_id": "sensor-01",
                    }
                },
            ]
            with patch("mineshark.sensors.ai_provider.WazuhIndexerClient", FakeIndexer):
                result = query_sensor_evidence_snapshots(config, alert_event_id="alert-1")

            self.assertEqual(len(result["snapshots"]), 1)
            self.assertEqual(result["snapshots"][0]["event_id"], "snapshot-1")

    def test_agent_toolbox_uses_the_configured_wazuh_ai_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(
                make_config(Path(tmp)),
                mineshark_ai_alert_source="wazuh",
                mineshark_allowed_sensor_ids=("sensor-01",),
            )
            FakeIndexer.records = [
                {
                    "data": {
                        "schema_version": 1,
                        "event_type": "ai_alert",
                        "event_id": "central-event",
                        "sensor_id": "sensor-01",
                        "malware_probability": 0.93,
                    }
                }
            ]
            with patch("mineshark.sensors.ai_provider.WazuhIndexerClient", FakeIndexer):
                result = AgentToolbox(config=config).query_mineshark_ai_alerts()

            self.assertEqual(result["provider"], "wazuh")
            self.assertEqual(result["alerts"][0]["event_id"], "central-event")

    def test_wazuh_provider_allows_only_known_schema_and_allowed_sensors(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(
                make_config(Path(tmp)),
                mineshark_ai_alert_source="wazuh",
                mineshark_allowed_sensor_ids=("sensor-01",),
            )
            FakeIndexer.calls = []
            FakeIndexer.records = [
                {
                    "@timestamp": "2026-07-29T00:00:00Z",
                    "rule": {"id": "110101", "level": 12},
                    "data": {
                        "schema_version": 1,
                        "event_type": "ai_alert",
                        "event_id": "event-1",
                        "sensor_id": "sensor-01",
                        "malware_probability": 0.93,
                    },
                },
                {"data": {"schema_version": 2, "event_type": "ai_alert", "sensor_id": "sensor-01"}},
                {"data": {"schema_version": 1, "event_type": "ai_alert", "sensor_id": "sensor-99"}},
                {
                    "data": {
                        "schema_version": 1,
                        "event_type": "ai_alert",
                        "event_id": "event-1",
                        "sensor_id": "sensor-01",
                        "malware_probability": 0.93,
                    }
                },
            ]
            with patch("mineshark.sensors.ai_provider.WazuhIndexerClient", FakeIndexer):
                result = query_configured_ai_alerts(config, min_probability=0.5, limit=20)

            self.assertEqual(result["matched"], 1)
            self.assertEqual(result["quarantined"], 2)
            self.assertEqual(result["duplicates"], 1)
            self.assertEqual(result["alerts"][0]["event_id"], "event-1")
            self.assertEqual(result["alerts"][0]["_wazuh_rule"]["id"], "110101")
            self.assertEqual(FakeIndexer.calls[0]["sensor_ids"], ("sensor-01",))

    def test_wazuh_provider_requires_an_explicit_sensor_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(make_config(Path(tmp)), mineshark_ai_alert_source="wazuh")
            result = query_configured_ai_alerts(config)
            self.assertIn("allowed sensor", result["error"])
            self.assertEqual(result["alerts"], [])

    def test_heartbeat_health_marks_stale_and_missing_sensors(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(
                make_config(Path(tmp)),
                mineshark_ai_alert_source="wazuh",
                mineshark_allowed_sensor_ids=("sensor-01", "sensor-02"),
            )
            FakeIndexer.records = [
                {
                    "data": {
                        "schema_version": 1,
                        "event_type": "sensor_heartbeat",
                        "event_id": "heartbeat-1",
                        "sensor_id": "sensor-01",
                        "observed_at": "2026-07-29T00:00:00+00:00",
                        "model_id": "legacy-model",
                        "last_capture_at": "2026-07-28T23:59:59+00:00",
                        "capture_backlog": 0,
                        "capture_drop_status": "unknown",
                    }
                }
            ]
            with patch("mineshark.sensors.ai_provider.WazuhIndexerClient", FakeIndexer):
                health = query_sensor_heartbeats(
                    config,
                    now=datetime(2026, 7, 29, 0, 2, tzinfo=timezone.utc),
                )

            by_id = {item["sensor_id"]: item for item in health["sensors"]}
            self.assertEqual(by_id["sensor-01"]["status"], "stale")
            self.assertEqual(by_id["sensor-02"]["status"], "missing")


if __name__ == "__main__":
    unittest.main()
