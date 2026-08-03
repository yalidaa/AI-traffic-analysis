import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mineshark.config import RuntimeConfig


class RuntimeConfigTests(unittest.TestCase):
    def test_parses_wazuh_alert_source_sensor_allowlist_and_cors_origins(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "deploy.env"
            env_file.write_text(
                "\n".join(
                    [
                        "MINESHARK_AI_ALERT_SOURCE=wazuh",
                        "MINESHARK_ALLOWED_SENSOR_IDS=sensor-01,sensor-02,sensor-01",
                        "MINESHARK_CORS_ALLOWED_ORIGINS=https://console.example,https://backup.example",
                        f"MINESHARK_CONSOLE_DATABASE_PATH={Path(tmp) / 'console.sqlite3'}",
                        f"MINESHARK_FRONTEND_DIST={Path(tmp) / 'frontend'}",
                    ]
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                config = RuntimeConfig.from_env(str(env_file))

            self.assertEqual(config.mineshark_ai_alert_source, "wazuh")
            self.assertEqual(config.mineshark_allowed_sensor_ids, ("sensor-01", "sensor-02"))
            self.assertEqual(
                config.cors_allowed_origins,
                ("https://console.example", "https://backup.example"),
            )
            self.assertEqual(config.console_database_path, (Path(tmp) / "console.sqlite3").resolve())
            self.assertEqual(config.frontend_dist, (Path(tmp) / "frontend").resolve())

    def test_rejects_unknown_ai_alert_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "bad.env"
            env_file.write_text("MINESHARK_AI_ALERT_SOURCE=shared-file\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "MINESHARK_AI_ALERT_SOURCE"):
                    RuntimeConfig.from_env(str(env_file))

    def test_parses_integer_runtime_settings_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "timeouts.env"
            env_file.write_text(
                "WAZUH_TIMEOUT=12\nMINESHARK_SENSOR_HEARTBEAT_STALE_SECONDS=60\n",
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {}, clear=True):
                config = RuntimeConfig.from_env(str(env_file))

            self.assertEqual(config.wazuh_timeout, 12)
            self.assertEqual(config.sensor_heartbeat_stale_seconds, 60)

    def test_explicit_env_file_overrides_a_previously_loaded_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_env = root / "first.env"
            second_env = root / "second.env"
            first_alerts = root / "first-alerts.json"
            second_alerts = root / "second-alerts.json"
            first_env.write_text(f"MINESHARK_AI_ALERTS_PATH={first_alerts}\n", encoding="utf-8")
            second_env.write_text(f"MINESHARK_AI_ALERTS_PATH={second_alerts}\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {}, clear=True):
                RuntimeConfig.from_env(str(first_env))
                config = RuntimeConfig.from_env(str(second_env))

            self.assertEqual(config.mineshark_ai_alerts_path, second_alerts.resolve())


if __name__ == "__main__":
    unittest.main()
