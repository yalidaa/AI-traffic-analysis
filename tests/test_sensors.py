import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.sensors.logs import query_suricata_alerts, query_zeek_context


class SensorLogTests(unittest.TestCase):
    def test_query_zeek_context_filters_by_ip_and_uid(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            (log_dir / "conn.log").write_text(
                "\n".join(
                    [
                        "#separator \\x09",
                        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto",
                        "1.0\tC1\t10.0.0.1\t12345\t8.8.8.8\t53\tudp",
                        "2.0\tC2\t10.0.0.2\t12345\t1.1.1.1\t443\ttcp",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            result = query_zeek_context(log_dir, ip="10.0.0.1", uid="C1")
            self.assertEqual(len(result["events"]), 1)
            self.assertEqual(result["events"][0]["id.resp_h"], "8.8.8.8")

    def test_query_suricata_alerts_filters_by_ip_and_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            eve_path = Path(tmp) / "eve.json"
            records = [
                {
                    "event_type": "alert",
                    "timestamp": "2026-05-26T01:00:00Z",
                    "src_ip": "10.0.0.1",
                    "dest_ip": "8.8.8.8",
                    "alert": {"signature": "ET MALWARE Test"},
                },
                {
                    "event_type": "dns",
                    "src_ip": "10.0.0.1",
                    "dest_ip": "8.8.4.4",
                },
            ]
            eve_path.write_text("\n".join(json.dumps(x) for x in records), encoding="utf-8")
            result = query_suricata_alerts(eve_path, ip="10.0.0.1", signature="malware")
            self.assertEqual(len(result["alerts"]), 1)
            self.assertEqual(result["alerts"][0]["alert"]["signature"], "ET MALWARE Test")


if __name__ == "__main__":
    unittest.main()
