import json
import socket
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

import dpkt

from mineshark.sensor.config import SensorConfig
from mineshark.sensor.runtime import SensorRuntime, capture_signature


def _frame(*, src: str, sport: int, dst: str, dport: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, flags=flags, data=payload)
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src),
        dst=socket.inet_aton(dst),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    ip.len = len(ip)
    return bytes.fromhex("00112233445566778899aabb0800") + bytes(ip)


def _write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle, snaplen=128)
        for timestamp, frame in packets:
            writer.writepkt(frame, ts=timestamp)
        writer.close()


def _write_pcapng_with_stats(
    path: Path,
    packets: list[tuple[float, bytes]],
    *,
    received: int,
    dropped: int,
) -> None:
    with path.open("wb") as handle:
        writer = dpkt.pcapng.Writer(handle, snaplen=128)
        for timestamp, frame in packets:
            writer.writepkt(frame, ts=timestamp)
        writer.close()
    options = struct.pack("<HHQ", 4, 8, received) + struct.pack("<HHQ", 5, 8, dropped) + struct.pack("<HH", 0, 0)
    body = struct.pack("<III", 0, 0, 0) + options
    block_length = 12 + len(body)
    with path.open("ab") as handle:
        handle.write(struct.pack("<II", 5, block_length) + body + struct.pack("<I", block_length))


def _config(root: Path) -> SensorConfig:
    checkpoint = root / "model.pt"
    checkpoint.write_bytes(b"model")
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "model_id": "legacy-model",
                "checkpoint_sha256": sha256(b"model").hexdigest(),
                "threshold": 0.5,
                "architecture": {
                    "embed_dim": 128,
                    "num_heads": 4,
                    "num_layers": 2,
                    "ff_dim": 256,
                    "dropout": 0.1,
                    "num_classes": 2,
                },
                "feature_profile": {
                    "name": "legacy-zeek-v1",
                    "max_len": 128,
                    "capture_packets": 20,
                    "min_packets": 3,
                    "max_pkt_size": 2000,
                    "max_iat": 10.0,
                    "time_semantics": "since_flow_start",
                    "packet_length_semantics": "tcp_payload_plus_54",
                    "direction_semantics": "tcp_initiator",
                },
            }
        ),
        encoding="utf-8",
    )
    (root / "zeek").mkdir()
    (root / "zeek" / "conn.log").write_text("", encoding="utf-8")
    (root / "eve.json").write_text("", encoding="utf-8")
    config_path = root / "sensor.toml"
    config_path.write_text(
        "\n".join(
            [
                'sensor_id="sensor-01"',
                'interface="ens192"',
                'bpf="tcp"',
                "[capture]",
                f'spool_dir="{(root / "spool").as_posix()}"',
                "snaplen=128",
                "rotate_seconds=5",
                "ring_files=60",
                "[flow]",
                "idle_timeout_seconds=30",
                "active_timeout_seconds=120",
                "[model]",
                f'checkpoint_path="{checkpoint.as_posix()}"',
                f'manifest_path="{manifest.as_posix()}"',
                "threshold=0.5",
                "[output]",
                f'events_path="{(root / "events.jsonl").as_posix()}"',
                f'status_path="{(root / "status.json").as_posix()}"',
                f'state_path="{(root / "state.sqlite3").as_posix()}"',
                "[evidence]",
                f'zeek_log_dir="{(root / "zeek").as_posix()}"',
                f'suricata_eve_path="{(root / "eve.json").as_posix()}"',
            ]
        ),
        encoding="utf-8",
    )
    return SensorConfig.load(config_path)


class FakeScorer:
    def __init__(self, probability: float):
        self.probability = probability
        self.flows = []

    def validate(self) -> None:
        return None

    def score(self, flow):
        self.flows.append(flow)
        return self.probability


class SensorRuntimeTests(unittest.TestCase):
    def test_heartbeat_reports_dumpcap_drop_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root)
            capture = root / "stats.pcapng"
            _write_pcapng_with_stats(
                capture,
                [
                    (1.0, _frame(src="10.0.0.2", sport=1, dst="10.0.0.3", dport=2, flags=0x02)),
                    (1.1, _frame(src="10.0.0.3", sport=2, dst="10.0.0.2", dport=1, flags=0x12)),
                    (1.2, _frame(src="10.0.0.2", sport=1, dst="10.0.0.3", dport=2, flags=0x11)),
                ],
                received=1000,
                dropped=2,
            )
            runtime = SensorRuntime(config, scorer=FakeScorer(0.1))
            runtime.process_capture(capture)

            heartbeat = runtime.emit_heartbeat()

            self.assertEqual(heartbeat["capture_received_packets"], 1000)
            self.assertEqual(heartbeat["capture_dropped_packets"], 2)
            self.assertEqual(heartbeat["capture_drop_rate"], 0.002)
            self.assertEqual(heartbeat["capture_drop_status"], "reported")

    def test_idle_flow_is_inferred_without_waiting_for_another_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root)
            capture = root / "idle.pcap"
            _write_pcap(
                capture,
                [
                    (1.0, _frame(src="10.0.0.2", sport=1, dst="10.0.0.3", dport=2, flags=0x02)),
                    (1.1, _frame(src="10.0.0.3", sport=2, dst="10.0.0.2", dport=1, flags=0x12)),
                    (1.2, _frame(src="10.0.0.2", sport=1, dst="10.0.0.3", dport=2, flags=0x10)),
                ],
            )
            scorer = FakeScorer(0.93)
            runtime = SensorRuntime(config, scorer=scorer)
            runtime.process_capture(capture)

            result = runtime.expire_flows(now=31.2)

            self.assertEqual(result["flows_inferred"], 1)
            self.assertEqual(result["alerts_emitted"], 1)
            self.assertEqual(runtime.assembler.active_count, 0)

    def test_restores_cross_file_flow_and_emits_traceable_events_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root)
            first_capture = root / "capture-1.pcap"
            second_capture = root / "capture-2.pcap"
            _write_pcap(
                first_capture,
                [
                    (10.0, _frame(src="10.0.0.2", sport=51000, dst="203.0.113.10", dport=443, flags=0x02)),
                    (10.1, _frame(src="203.0.113.10", sport=443, dst="10.0.0.2", dport=51000, flags=0x12)),
                ],
            )
            _write_pcap(
                second_capture,
                [(10.4, _frame(src="10.0.0.2", sport=51000, dst="203.0.113.10", dport=443, flags=0x11))],
            )

            first_runtime = SensorRuntime(config, scorer=FakeScorer(0.93))
            first_result = first_runtime.process_capture(first_capture)
            self.assertEqual(first_result["alerts_emitted"], 0)
            self.assertEqual(first_result["active_flows"], 1)

            scorer = FakeScorer(0.93)
            restored_runtime = SensorRuntime(config, scorer=scorer)
            second_result = restored_runtime.process_capture(second_capture)
            restored_runtime.emit_heartbeat(observed_at=datetime(2026, 7, 29, tzinfo=timezone.utc))

            self.assertEqual(second_result["alerts_emitted"], 1)
            self.assertEqual(scorer.flows[0].signed_packet_sizes, (54, -54, 54))
            events = [json.loads(line) for line in config.output.events_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(
                [event["event_type"] for event in events],
                [
                    "ai_alert",
                    "evidence_snapshot",
                    "sensor_heartbeat",
                ],
            )
            alert = events[0]
            self.assertEqual(alert["sensor_id"], "sensor-01")
            self.assertEqual(alert["model"]["sha256"], config.model_manifest.checkpoint_sha256)
            self.assertEqual(alert["features"]["signed_packet_sizes"], [54, -54, 54])
            self.assertEqual(events[1]["alert_event_id"], alert["event_id"])

            before = config.output.events_path.read_bytes()
            duplicate = restored_runtime.process_capture(second_capture)
            self.assertTrue(duplicate["skipped_already_processed"])
            self.assertTrue(restored_runtime.capture_processed(second_capture))
            self.assertFalse(restored_runtime.capture_processed(root / "missing.pcap"))
            self.assertEqual(config.output.events_path.read_bytes(), before)

            status = json.loads(config.output.status_path.read_text(encoding="utf-8"))
            self.assertEqual(status["model_id"], "legacy-model")
            self.assertEqual(status["active_flows"], 0)
            self.assertEqual(status["capture_drop_status"], "unknown")

    def test_below_threshold_flow_is_inferred_but_not_alerted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root)
            capture = root / "benign.pcap"
            _write_pcap(
                capture,
                [
                    (1.0, _frame(src="10.0.0.2", sport=1, dst="10.0.0.3", dport=2, flags=0x02)),
                    (1.1, _frame(src="10.0.0.3", sport=2, dst="10.0.0.2", dport=1, flags=0x12)),
                    (1.2, _frame(src="10.0.0.2", sport=1, dst="10.0.0.3", dport=2, flags=0x11)),
                ],
            )
            scorer = FakeScorer(0.1)
            result = SensorRuntime(config, scorer=scorer).process_capture(capture)

            self.assertEqual(result["flows_inferred"], 1)
            self.assertEqual(result["alerts_emitted"], 0)
            self.assertFalse(config.output.events_path.exists())

    def test_capture_signature_is_content_based(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "a.pcap"
            second = root / "b.pcap"
            first.write_bytes(b"same")
            second.write_bytes(b"same")
            self.assertEqual(capture_signature(first), capture_signature(second))


if __name__ == "__main__":
    unittest.main()
