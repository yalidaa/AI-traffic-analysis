import json
import tempfile
import time
import unittest
from unittest import mock
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from mineshark.sensor.cli import build_parser, discover_closed_captures, main


class SensorCliTests(unittest.TestCase):
    def test_sensor_supports_python_310_toml_parser_fallback(self):
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        config_source = Path(__file__).resolve().parents[1] / "src" / "mineshark" / "sensor" / "config.py"
        self.assertIn("tomli", pyproject.read_text(encoding="utf-8"))
        self.assertIn("except ModuleNotFoundError", config_source.read_text(encoding="utf-8"))

    def test_exposes_required_public_commands(self):
        parser = build_parser()
        help_text = parser.format_help()
        for command in ("validate-config", "run", "replay", "status"):
            self.assertIn(command, help_text)

    def test_status_reads_last_status_without_loading_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            status = root / "status.json"
            status.write_text(json.dumps({"schema_version": 1, "sensor_id": "sensor-01"}), encoding="utf-8")
            config = root / "sensor.toml"
            config.write_text(
                "\n".join(
                    [
                        'sensor_id="sensor-01"',
                        'interface="ens192"',
                        "[capture]",
                        "snaplen=128",
                        "rotate_seconds=5",
                        "ring_files=60",
                        "[output]",
                        f'status_path="{status.as_posix()}"',
                    ]
                ),
                encoding="utf-8",
            )
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["--config", str(config), "status"])

            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(output.getvalue())["sensor_id"], "sensor-01")

    def test_discovery_skips_current_capture_until_it_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "mineshark_00001.pcapng"
            current = root / "mineshark_00002.pcapng"
            old.write_bytes(b"old")
            current.write_bytes(b"current")
            now = time.time()
            old.touch()
            current.touch()
            old_time = now - 10
            import os

            os.utime(old, (old_time, old_time))
            os.utime(current, (now, now))

            self.assertEqual(
                discover_closed_captures(root, rotate_seconds=5, now=now),
                [old],
            )
            self.assertEqual(
                discover_closed_captures(root, rotate_seconds=5, now=now + 7),
                [old, current],
            )

    def test_discovery_skips_a_file_removed_during_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gone = root / "mineshark_gone.pcapng"
            stable = root / "mineshark_stable.pcapng"
            gone.write_bytes(b"gone")
            stable.write_bytes(b"stable")
            now = time.time()
            gone.touch()
            stable.touch()
            os_times = {gone: now - 10, stable: now - 10}
            import os

            for path, timestamp in os_times.items():
                os.utime(path, (timestamp, timestamp))

            original_stat = Path.stat

            def flaky_stat(path: Path):
                if path.name == gone.name:
                    raise FileNotFoundError(path)
                return original_stat(path)

            with mock.patch.object(Path, "stat", flaky_stat):
                self.assertEqual(discover_closed_captures(root, rotate_seconds=5, now=now), [stable])


if __name__ == "__main__":
    unittest.main()
