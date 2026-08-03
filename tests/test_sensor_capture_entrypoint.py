import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mineshark.sensor.capture import capture_main


class CaptureEntrypointTests(unittest.TestCase):
    def test_execs_dumpcap_from_the_verified_config_without_a_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "sensor.toml"
            config.write_text(
                "\n".join(
                    [
                        'sensor_id="sensor-01"',
                        'interface="ens192"',
                        'bpf="tcp"',
                        "[capture]",
                        'dumpcap_path="/usr/bin/dumpcap"',
                        f'spool_dir="{(root / "spool").as_posix()}"',
                        "snaplen=128",
                        "rotate_seconds=5",
                        "ring_files=60",
                    ]
                ),
                encoding="utf-8",
            )
            with patch("mineshark.sensor.capture.os.execv") as execv:
                self.assertEqual(capture_main(["--config", str(config)]), 0)

            command = execv.call_args.args[1]
            self.assertEqual(execv.call_args.args[0], "/usr/bin/dumpcap")
            self.assertEqual(command[1:5], ["-i", "ens192", "-f", "tcp"])
            self.assertTrue((root / "spool").is_dir())


if __name__ == "__main__":
    unittest.main()
