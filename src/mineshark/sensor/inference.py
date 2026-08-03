from __future__ import annotations

from pathlib import Path
from typing import Any

from mineshark.sensor.features import encode_legacy_zeek_features
from mineshark.sensor.flow import CompletedFlow
from mineshark.sensor.manifest import ModelManifest


def validate_checkpoint_config(config: dict[str, Any], manifest: ModelManifest) -> None:
    expected = {
        "max_len": manifest.feature_profile.max_len,
        "max_pkt_size": manifest.feature_profile.max_pkt_size,
        "max_iat": manifest.feature_profile.max_iat,
        "min_packets": manifest.feature_profile.min_packets,
        "embed_dim": manifest.architecture.embed_dim,
        "num_heads": manifest.architecture.num_heads,
        "num_layers": manifest.architecture.num_layers,
        "ff_dim": manifest.architecture.ff_dim,
        "dropout": manifest.architecture.dropout,
    }
    for field, expected_value in expected.items():
        if field not in config:
            raise ValueError(f"checkpoint config missing: {field}")
        actual_value = config[field]
        if isinstance(expected_value, float):
            matches = abs(float(actual_value) - expected_value) <= 1e-12
        else:
            matches = int(actual_value) == expected_value
        if not matches:
            raise ValueError(f"checkpoint config mismatch: {field} expected {expected_value}, got {actual_value}")


class TorchTransformerScorer:
    def __init__(self, manifest: ModelManifest, checkpoint_path: str | Path, *, device: str = "cpu"):
        self.manifest = manifest
        self.checkpoint_path = Path(checkpoint_path)
        self.device = device
        self._torch = None
        self._model = None

    def validate(self) -> None:
        self._ensure_loaded()

    def score(self, flow: CompletedFlow) -> float:
        self._ensure_loaded()
        profile = self.manifest.feature_profile
        features = encode_legacy_zeek_features(
            flow,
            max_len=profile.max_len,
            max_pkt_size=profile.max_pkt_size,
            max_iat=profile.max_iat,
        )
        torch = self._torch
        model = self._model
        sizes = torch.tensor([features.sizes], dtype=torch.long, device=self.device)
        iats = torch.tensor([features.iats], dtype=torch.float32, device=self.device).unsqueeze(-1)
        directions = torch.tensor([features.directions], dtype=torch.long, device=self.device)
        mask = torch.tensor([features.mask], dtype=torch.bool, device=self.device)
        with torch.inference_mode():
            _, logits = model(sizes, iats, directions, attention_mask=mask)
            return float(torch.softmax(logits, dim=1)[0, 1].item())

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        try:
            import torch
            from mineshark.models.traffic_transformer import TrafficTransformer
        except ImportError as exc:
            raise RuntimeError("Torch inference dependencies are missing; install the ml extra") from exc

        try:
            checkpoint = torch.load(self.checkpoint_path, map_location=self.device, weights_only=False)
        except TypeError:
            checkpoint = torch.load(self.checkpoint_path, map_location=self.device)
        if not isinstance(checkpoint, dict) or "config" not in checkpoint or "model_state_dict" not in checkpoint:
            raise ValueError("unsupported checkpoint structure")
        checkpoint_config = checkpoint["config"]
        if not isinstance(checkpoint_config, dict):
            raise ValueError("checkpoint config must be an object")
        validate_checkpoint_config(checkpoint_config, self.manifest)

        architecture = self.manifest.architecture
        profile = self.manifest.feature_profile
        model = TrafficTransformer(
            vocab_size=profile.max_pkt_size + 2,
            seq_len=profile.max_len,
            embed_dim=architecture.embed_dim,
            num_heads=architecture.num_heads,
            num_layers=architecture.num_layers,
            ff_dim=architecture.ff_dim,
            dropout=architecture.dropout,
            num_classes=architecture.num_classes,
        )
        model.load_state_dict(checkpoint["model_state_dict"])
        model.to(self.device)
        model.eval()
        self._torch = torch
        self._model = model
