from __future__ import annotations

from dataclasses import dataclass

from mineshark.sensor.flow import CompletedFlow


@dataclass(frozen=True)
class EncodedFeatures:
    sizes: tuple[int, ...]
    iats: tuple[float, ...]
    directions: tuple[int, ...]
    mask: tuple[bool, ...]


def encode_legacy_zeek_features(
    flow: CompletedFlow,
    *,
    max_len: int,
    max_pkt_size: int,
    max_iat: float,
) -> EncodedFeatures:
    sequence_length = min(len(flow.signed_packet_sizes), len(flow.time_offsets), max_len)
    sizes: list[int] = []
    directions: list[int] = []
    iats: list[float] = []
    for signed_size, offset in zip(
        flow.signed_packet_sizes[:sequence_length],
        flow.time_offsets[:sequence_length],
    ):
        sizes.append(min(abs(int(signed_size)), max_pkt_size) + 1)
        directions.append(1 if signed_size > 0 else 2 if signed_size < 0 else 0)
        iats.append(min(max(float(offset), 0.0), max_iat))

    padding = max_len - sequence_length
    mask = [True] * sequence_length + [False] * padding
    sizes.extend([0] * padding)
    directions.extend([0] * padding)
    iats.extend([0.0] * padding)
    return EncodedFeatures(
        sizes=tuple(sizes),
        iats=tuple(iats),
        directions=tuple(directions),
        mask=tuple(mask),
    )
