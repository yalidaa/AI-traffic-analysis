import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from mineshark.sensor.inference import validate_checkpoint_config
from mineshark.sensor.manifest import ModelManifest


class CheckpointCompatibilityTests(unittest.TestCase):
    def _manifest(self, root: Path) -> ModelManifest:
        checkpoint = root / "model.pt"
        checkpoint.write_bytes(b"model")
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "model_id": "deep-mineshark-legacy-20260304",
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
        return ModelManifest.load(manifest, checkpoint)

    def test_accepts_recovered_checkpoint_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._manifest(Path(tmp))
            validate_checkpoint_config(
                {
                    "max_len": 128,
                    "max_pkt_size": 2000,
                    "max_iat": 10.0,
                    "min_packets": 3,
                    "embed_dim": 128,
                    "num_heads": 4,
                    "num_layers": 2,
                    "ff_dim": 256,
                    "dropout": 0.1,
                },
                manifest,
            )

    def test_rejects_checkpoint_configuration_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._manifest(Path(tmp))
            with self.assertRaisesRegex(ValueError, "checkpoint config mismatch: max_len"):
                validate_checkpoint_config(
                    {
                        "max_len": 20,
                        "max_pkt_size": 2000,
                        "max_iat": 10.0,
                        "min_packets": 3,
                        "embed_dim": 128,
                        "num_heads": 4,
                        "num_layers": 2,
                        "ff_dim": 256,
                        "dropout": 0.1,
                    },
                    manifest,
                )


if __name__ == "__main__":
    unittest.main()
