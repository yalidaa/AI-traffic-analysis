import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from mineshark.sensor.events import build_ai_alert, build_evidence_snapshot
from mineshark.sensor.flow import FlowAssembler, PacketObservation
from mineshark.sensor.manifest import ModelManifest
from mineshark.sensor.state import SensorStateStore


ROOT = Path(__file__).resolve().parents[1]


class SensorPackageContractTests(unittest.TestCase):
    def test_sensor_package_and_cli_are_exposed(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIsNotNone(importlib.util.find_spec("mineshark.sensor"))
        self.assertIn("sensor = [", pyproject)
        self.assertIn('"dpkt==1.9.8"', pyproject)
        self.assertIn('mineshark-sensor = "mineshark.sensor.cli:main"', pyproject)


class ModelManifestTests(unittest.TestCase):
    def test_manifest_validates_checkpoint_and_legacy_feature_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkpoint = root / "model.pt"
            checkpoint.write_bytes(b"verified-model")
            digest = sha256(checkpoint.read_bytes()).hexdigest()
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "model_id": "deep-mineshark-legacy-20260304",
                        "checkpoint_sha256": digest,
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

            manifest = ModelManifest.load(manifest_path, checkpoint)

            self.assertEqual(manifest.model_id, "deep-mineshark-legacy-20260304")
            self.assertEqual(manifest.feature_profile.capture_packets, 20)
            self.assertEqual(manifest.feature_profile.time_semantics, "since_flow_start")
            self.assertEqual(manifest.architecture.embed_dim, 128)

    def test_manifest_rejects_checkpoint_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkpoint = root / "model.pt"
            checkpoint.write_bytes(b"wrong-model")
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "model_id": "test-model",
                        "checkpoint_sha256": "0" * 64,
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

            with self.assertRaisesRegex(ValueError, "checkpoint SHA-256 mismatch"):
                ModelManifest.load(manifest_path, checkpoint)


class FlowAssemblerTests(unittest.TestCase):
    @staticmethod
    def packet(
        timestamp: float,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        ip_length: int,
        tcp_flags: int,
    ) -> PacketObservation:
        return PacketObservation(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="tcp",
            ip_length=ip_length,
            tcp_flags=tcp_flags,
        )

    def test_syn_sets_direction_and_legacy_offsets_are_cumulative(self):
        assembler = FlowAssembler(max_packets=3, min_packets=3, idle_timeout=30.0, active_timeout=120.0)

        self.assertEqual(assembler.add(self.packet(10.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02)), [])
        self.assertEqual(assembler.add(self.packet(10.2, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12)), [])
        completed = assembler.add(self.packet(10.5, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x10))

        self.assertEqual(len(completed), 1)
        flow = completed[0]
        self.assertEqual(flow.src_ip, "10.0.0.2")
        self.assertEqual(flow.dst_ip, "203.0.113.10")
        self.assertEqual(flow.signed_packet_sizes, (60, -60, 52))
        self.assertEqual(flow.time_offsets, (0.0, 0.2, 0.5))
        self.assertEqual(flow.close_reason, "max_packets")

    def test_first_observed_packet_sets_direction_when_syn_is_missing(self):
        assembler = FlowAssembler(max_packets=4, min_packets=2, idle_timeout=5.0, active_timeout=120.0)
        assembler.add(self.packet(1.0, "192.0.2.5", 443, "10.0.0.8", 53000, 120, 0x10))
        assembler.add(self.packet(1.4, "10.0.0.8", 53000, "192.0.2.5", 443, 64, 0x10))

        completed = assembler.expire(7.0)

        self.assertEqual(completed[0].signed_packet_sizes, (120, -64))
        self.assertEqual(completed[0].close_reason, "idle_timeout")

    def test_fin_closes_a_flow_only_after_minimum_packet_count(self):
        assembler = FlowAssembler(max_packets=20, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
        assembler.add(self.packet(1.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02))
        assembler.add(self.packet(1.1, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12))

        completed = assembler.add(self.packet(1.2, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x11))

        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].close_reason, "tcp_close")

    def test_syn_ack_seen_first_still_identifies_the_tcp_initiator(self):
        assembler = FlowAssembler(max_packets=20, min_packets=2, idle_timeout=30.0, active_timeout=120.0)
        assembler.add(self.packet(1.0, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12))
        completed = assembler.add(self.packet(1.1, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x11))

        self.assertEqual(completed[0].src_ip, "10.0.0.2")
        self.assertEqual(completed[0].signed_packet_sizes, (-60, 52))

    def test_late_original_syn_corrects_fallback_direction_for_out_of_order_capture(self):
        assembler = FlowAssembler(max_packets=20, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
        assembler.add(self.packet(1.0, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x10))
        assembler.add(self.packet(1.1, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02))
        completed = assembler.add(self.packet(1.2, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x11))

        self.assertEqual(completed[0].src_ip, "10.0.0.2")
        self.assertEqual(completed[0].signed_packet_sizes, (-60, 60, 52))

    def test_retransmitted_packet_is_retained_in_the_legacy_observation_sequence(self):
        assembler = FlowAssembler(max_packets=4, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
        packet = self.packet(1.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02)
        assembler.add(packet)
        assembler.add(packet)
        assembler.add(self.packet(1.1, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12))
        completed = assembler.add(self.packet(1.2, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x11))

        self.assertEqual(completed[0].signed_packet_sizes, (60, 60, -60, 52))

    def test_packets_after_legacy_capture_limit_do_not_create_a_second_flow(self):
        assembler = FlowAssembler(max_packets=3, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
        completed = []
        completed.extend(assembler.add(self.packet(1.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02)))
        completed.extend(assembler.add(self.packet(1.1, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12)))
        completed.extend(assembler.add(self.packet(1.2, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x10)))
        assembler.add(self.packet(1.3, "10.0.0.2", 51000, "203.0.113.10", 443, 100, 0x10))
        assembler.add(self.packet(1.4, "203.0.113.10", 443, "10.0.0.2", 51000, 100, 0x10))
        extra = assembler.add(self.packet(1.5, "10.0.0.2", 51000, "203.0.113.10", 443, 100, 0x11))

        self.assertEqual(len(completed), 1)
        self.assertEqual(extra, [])
        self.assertEqual(assembler.flush_all(), [])

    def test_new_syn_reuses_a_five_tuple_after_a_truncated_connection_closed(self):
        assembler = FlowAssembler(max_packets=3, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
        for packet in (
            self.packet(1.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02),
            self.packet(1.1, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12),
            self.packet(1.2, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x10),
        ):
            assembler.add(packet)
        assembler.add(self.packet(1.3, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x11))

        self.assertEqual(assembler.add(self.packet(2.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02)), [])
        self.assertEqual(assembler.active_count, 1)

    def test_active_flow_survives_sqlite_state_restore_across_capture_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = SensorStateStore(Path(tmp) / "sensor.sqlite3")
            first = FlowAssembler(max_packets=20, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
            first.add(self.packet(1.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02))
            first.add(self.packet(1.1, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12))
            state.save_active_flows(first.snapshot())

            restored = FlowAssembler(max_packets=20, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
            restored.restore(state.load_active_flows())
            completed = restored.add(self.packet(1.2, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x11))

            self.assertEqual(len(completed), 1)
            self.assertEqual(completed[0].signed_packet_sizes, (60, -60, 52))
            self.assertEqual(restored.active_count, 0)


class SensorEventAndStateTests(unittest.TestCase):
    def test_evidence_snapshot_recursively_removes_payload_and_packet_bytes(self):
        alert = {
            "event_id": "alert-1",
            "sensor_id": "sensor-01",
            "observed_at": "2026-07-29T00:00:00+00:00",
            "flow": {"src_ip": "10.0.0.2", "dst_ip": "203.0.113.10"},
        }
        snapshot = build_evidence_snapshot(
            alert,
            zeek={
                "events": [
                    {
                        "uid": "C1",
                        "payload": "clear-text",
                        "nested": {"packet": "base64-packet", "signature": "known"},
                    }
                ]
            },
            suricata={
                "alerts": [
                    {
                        "src_ip": "10.0.0.2",
                        "payload_printable": "password=secret",
                        "alert": {"signature": "test signature"},
                    }
                ]
            },
            window_start="2026-07-28T23:59:30+00:00",
            window_end="2026-07-29T00:00:30+00:00",
        )

        snapshot_text = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("clear-text", snapshot_text)
        self.assertNotIn("base64-packet", snapshot_text)
        self.assertNotIn("password=secret", snapshot_text)
        self.assertIn("test signature", snapshot_text)
        self.assertIn("C1", snapshot_text)

    def test_ai_alert_is_deterministic_and_contains_replayable_features(self):
        assembler = FlowAssembler(max_packets=3, min_packets=3, idle_timeout=30.0, active_timeout=120.0)
        packets = [
            FlowAssemblerTests.packet(1.0, "10.0.0.2", 51000, "203.0.113.10", 443, 60, 0x02),
            FlowAssemblerTests.packet(1.1, "203.0.113.10", 443, "10.0.0.2", 51000, 60, 0x12),
            FlowAssemblerTests.packet(1.3, "10.0.0.2", 51000, "203.0.113.10", 443, 52, 0x10),
        ]
        completed = []
        for packet in packets:
            completed.extend(assembler.add(packet))
        observed_at = datetime(2026, 7, 29, tzinfo=timezone.utc)

        first = build_ai_alert(
            completed[0],
            sensor_id="sensor-01",
            model_id="deep-mineshark-legacy-20260304",
            model_sha256="a" * 64,
            threshold=0.5,
            malware_probability=0.93,
            observed_at=observed_at,
        )
        second = build_ai_alert(
            completed[0],
            sensor_id="sensor-01",
            model_id="deep-mineshark-legacy-20260304",
            model_sha256="a" * 64,
            threshold=0.5,
            malware_probability=0.93,
            observed_at=observed_at,
        )

        self.assertEqual(first["event_id"], second["event_id"])
        self.assertEqual(first["event_type"], "ai_alert")
        self.assertEqual(first["risk_level"], "high")
        self.assertEqual(first["features"]["signed_packet_sizes"], [60, -60, 52])
        self.assertEqual(first["features"]["time_offsets"], [0.0, 0.1, 0.3])
        self.assertNotIn("payload", first)

    def test_state_store_rejects_duplicate_alert_and_tracks_capture_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SensorStateStore(Path(tmp) / "sensor.sqlite3")
            event = {"event_id": "evt-1", "event_type": "ai_alert", "sensor_id": "sensor-01"}

            self.assertTrue(store.record_alert_once(event))
            self.assertFalse(store.record_alert_once(event))
            self.assertFalse(store.capture_processed("capture-1"))
            store.mark_capture_processed("capture-1", packet_count=42)
            self.assertTrue(store.capture_processed("capture-1"))

    def test_capture_commit_persists_flow_state_and_signature_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SensorStateStore(Path(tmp) / "sensor.sqlite3")
            flows = [
                {
                    "state_type": "active",
                    "src_ip": "10.0.0.2",
                    "src_port": 51000,
                    "dst_ip": "203.0.113.10",
                    "dst_port": 443,
                    "protocol": "tcp",
                    "started_at": 1.0,
                    "last_seen_at": 1.1,
                    "signed_packet_sizes": [54, -54],
                    "time_offsets": [0.0, 0.1],
                    "direction_confirmed": True,
                }
            ]

            store.commit_capture("capture-atomic", packet_count=2, active_flows=flows)

            self.assertTrue(store.capture_processed("capture-atomic"))
            self.assertEqual(store.load_active_flows(), flows)


if __name__ == "__main__":
    unittest.main()
