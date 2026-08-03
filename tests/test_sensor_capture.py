import json
import socket
import struct
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

import dpkt

from mineshark.sensor.capture import CaptureReadError, build_dumpcap_command, read_capture
from mineshark.sensor.config import SensorConfig
from mineshark.sensor.features import encode_legacy_zeek_features
from mineshark.sensor.flow import CompletedFlow


def _ethernet_ipv4_tcp(*, payload: bytes, vlan: bool = False) -> bytes:
    tcp = dpkt.tcp.TCP(sport=51000, dport=443, seq=1, flags=dpkt.tcp.TH_SYN, data=payload)
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_aton("10.0.0.2"),
        dst=socket.inet_aton("203.0.113.10"),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    ip.len = len(ip)
    ethernet_header = bytes.fromhex("00112233445566778899aabb")
    if vlan:
        return ethernet_header + b"\x81\x00\x00\x64\x08\x00" + bytes(ip)
    return ethernet_header + b"\x08\x00" + bytes(ip)


def _ethernet_ipv6_tcp(*, payload: bytes) -> bytes:
    tcp = dpkt.tcp.TCP(sport=443, dport=52000, seq=2, flags=dpkt.tcp.TH_ACK, data=payload)
    tcp.off = 5
    ip = dpkt.ip6.IP6(
        src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        nxt=dpkt.ip.IP_PROTO_TCP,
        hlim=64,
        data=tcp,
    )
    ip.plen = len(tcp)
    return bytes.fromhex("00112233445566778899aabb86dd") + bytes(ip)


class SensorConfigTests(unittest.TestCase):
    def test_loads_production_capture_and_model_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
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
            config_path = root / "sensor.toml"
            config_path.write_text(
                "\n".join(
                    [
                        'sensor_id = "sensor-01"',
                        'interface = "ens192"',
                        'bpf = "tcp"',
                        "[capture]",
                        'dumpcap_path = "/usr/bin/dumpcap"',
                        f'spool_dir = "{(root / "spool").as_posix()}"',
                        "snaplen = 128",
                        "rotate_seconds = 5",
                        "ring_files = 60",
                        "[flow]",
                        "idle_timeout_seconds = 30",
                        "active_timeout_seconds = 120",
                        "[model]",
                        f'checkpoint_path = "{checkpoint.as_posix()}"',
                        f'manifest_path = "{manifest.as_posix()}"',
                        "threshold = 0.5",
                        "[output]",
                        f'events_path = "{(root / "events.jsonl").as_posix()}"',
                        f'status_path = "{(root / "status.json").as_posix()}"',
                        f'state_path = "{(root / "state.sqlite3").as_posix()}"',
                    ]
                ),
                encoding="utf-8",
            )

            config = SensorConfig.load(config_path, verify_model=True)

            self.assertEqual(config.sensor_id, "sensor-01")
            self.assertEqual(config.capture.snaplen, 128)
            self.assertEqual(config.model_manifest.feature_profile.capture_packets, 20)
            self.assertEqual(
                build_dumpcap_command(config),
                [
                    "/usr/bin/dumpcap",
                    "-i",
                    "ens192",
                    "-f",
                    "tcp",
                    "-s",
                    "128",
                    "-b",
                    "duration:5",
                    "-b",
                    "files:60",
                    "-w",
                    str(root / "spool" / "mineshark.pcapng"),
                    "-q",
                ],
            )

    def test_rejects_capture_settings_that_break_the_retention_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sensor.toml"
            path.write_text(
                'sensor_id="s"\ninterface="eth0"\n[capture]\nsnaplen=0\nrotate_seconds=5\nring_files=60\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "snaplen must be 128"):
                SensorConfig.load(path, verify_model=False)


class CaptureReaderTests(unittest.TestCase):
    def test_reads_dumpcap_interface_drop_counters_from_pcapng(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stats.pcapng"
            with path.open("wb") as handle:
                writer = dpkt.pcapng.Writer(handle, snaplen=128)
                writer.writepkt(_ethernet_ipv4_tcp(payload=b"x"), ts=20.0)
                writer.close()
            options = struct.pack("<HHQ", 4, 8, 1000) + struct.pack("<HHQ", 5, 8, 2) + struct.pack("<HH", 0, 0)
            body = struct.pack("<III", 0, 0, 0) + options
            block_length = 12 + len(body)
            with path.open("ab") as handle:
                handle.write(struct.pack("<II", 5, block_length) + body + struct.pack("<I", block_length))

            stats = read_capture(path).stats

            self.assertEqual(stats.interface_received_packets, 1000)
            self.assertEqual(stats.interface_dropped_packets, 2)
            self.assertEqual(stats.drop_status, "reported")

    def test_reads_vlan_ipv4_and_ipv6_tcp_from_pcap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "traffic.pcap"
            with path.open("wb") as handle:
                writer = dpkt.pcap.Writer(handle, snaplen=128)
                writer.writepkt(_ethernet_ipv4_tcp(payload=b"0123456789", vlan=True), ts=10.0)
                writer.writepkt(_ethernet_ipv6_tcp(payload=b"abcde"), ts=10.2)
                writer.close()

            result = read_capture(path)

            self.assertEqual(result.stats.total_packets, 2)
            self.assertEqual(result.stats.tcp_packets, 2)
            self.assertEqual(result.packets[0].ip_length, 64)
            self.assertEqual(result.packets[0].src_ip, "10.0.0.2")
            self.assertEqual(result.packets[1].ip_length, 59)
            self.assertEqual(result.packets[1].src_ip, "2001:db8::1")

    def test_reads_pcapng_and_rejects_corrupt_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcapng = root / "traffic.pcapng"
            with pcapng.open("wb") as handle:
                writer = dpkt.pcapng.Writer(handle, snaplen=128)
                writer.writepkt(_ethernet_ipv4_tcp(payload=b"x"), ts=20.0)
                writer.close()
            self.assertEqual(read_capture(pcapng).stats.tcp_packets, 1)

            corrupt = root / "corrupt.pcap"
            corrupt.write_bytes(b"not-a-capture")
            with self.assertRaises(CaptureReadError):
                read_capture(corrupt)


class LegacyFeatureTests(unittest.TestCase):
    def test_encodes_exact_legacy_tensor_values_and_padding(self):
        flow = CompletedFlow(
            src_ip="10.0.0.2",
            src_port=51000,
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="tcp",
            started_at=10.0,
            ended_at=10.5,
            signed_packet_sizes=(54, -64, 2501),
            time_offsets=(0.0, 0.2, 11.0),
            close_reason="tcp_close",
        )

        encoded = encode_legacy_zeek_features(flow, max_len=5, max_pkt_size=2000, max_iat=10.0)

        self.assertEqual(encoded.sizes, (55, 65, 2001, 0, 0))
        self.assertEqual(encoded.directions, (1, 2, 1, 0, 0))
        self.assertEqual(encoded.iats, (0.0, 0.2, 10.0, 0.0, 0.0))
        self.assertEqual(encoded.mask, (True, True, True, False, False))


if __name__ == "__main__":
    unittest.main()
