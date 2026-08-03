from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Tuple


@dataclass(frozen=True)
class PacketObservation:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    ip_length: int
    tcp_flags: int


@dataclass(frozen=True)
class CompletedFlow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    started_at: float
    ended_at: float
    signed_packet_sizes: tuple[int, ...]
    time_offsets: tuple[float, ...]
    close_reason: str


@dataclass
class _FlowState:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    started_at: float
    last_seen_at: float
    signed_packet_sizes: list[int]
    time_offsets: list[float]
    direction_confirmed: bool


@dataclass
class _SuppressedFlow:
    started_at: float
    last_seen_at: float


class FlowAssembler:
    def __init__(self, *, max_packets: int, min_packets: int, idle_timeout: float, active_timeout: float):
        if max_packets < 1 or min_packets < 1 or min_packets > max_packets:
            raise ValueError("invalid packet limits")
        self.max_packets = max_packets
        self.min_packets = min_packets
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self._flows: Dict[Tuple[Tuple[str, int], Tuple[str, int], str], _FlowState] = {}
        self._suppressed: Dict[Tuple[Tuple[str, int], Tuple[str, int], str], _SuppressedFlow] = {}

    @property
    def active_count(self) -> int:
        return len(self._flows)

    def add(self, packet: PacketObservation) -> list[CompletedFlow]:
        if packet.protocol.lower() != "tcp":
            return []
        key = _flow_key(packet)
        suppressed = self._suppressed.get(key)
        original_syn = bool(packet.tcp_flags & 0x02) and not bool(packet.tcp_flags & 0x10)
        if suppressed is not None:
            if original_syn:
                self._suppressed.pop(key, None)
            else:
                suppressed.last_seen_at = max(suppressed.last_seen_at, packet.timestamp)
                if packet.tcp_flags & 0x05:
                    self._suppressed.pop(key, None)
                return []
        flow = self._flows.get(key)
        if flow is None:
            syn = bool(packet.tcp_flags & 0x02)
            ack = bool(packet.tcp_flags & 0x10)
            if syn and ack:
                src_ip, src_port = packet.dst_ip, packet.dst_port
                dst_ip, dst_port = packet.src_ip, packet.src_port
            else:
                src_ip, src_port = packet.src_ip, packet.src_port
                dst_ip, dst_port = packet.dst_ip, packet.dst_port
            flow = _FlowState(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                started_at=packet.timestamp,
                last_seen_at=packet.timestamp,
                signed_packet_sizes=[],
                time_offsets=[],
                direction_confirmed=syn,
            )
            self._flows[key] = flow
        elif packet.tcp_flags & 0x02 and not packet.tcp_flags & 0x10 and not flow.direction_confirmed:
            packet_is_forward = (
                packet.src_ip == flow.src_ip
                and packet.src_port == flow.src_port
                and packet.dst_ip == flow.dst_ip
                and packet.dst_port == flow.dst_port
            )
            if not packet_is_forward:
                flow.src_ip, flow.dst_ip = flow.dst_ip, flow.src_ip
                flow.src_port, flow.dst_port = flow.dst_port, flow.src_port
                flow.signed_packet_sizes = [-value for value in flow.signed_packet_sizes]
            flow.direction_confirmed = True

        forward = (
            packet.src_ip == flow.src_ip
            and packet.src_port == flow.src_port
            and packet.dst_ip == flow.dst_ip
            and packet.dst_port == flow.dst_port
        )
        signed_size = packet.ip_length if forward else -packet.ip_length
        flow.signed_packet_sizes.append(signed_size)
        flow.time_offsets.append(round(max(0.0, packet.timestamp - flow.started_at), 6))
        flow.last_seen_at = max(flow.last_seen_at, packet.timestamp)

        if len(flow.signed_packet_sizes) >= self.max_packets:
            completed = self._close(key, "max_packets")
            if not packet.tcp_flags & 0x05:
                self._suppressed[key] = _SuppressedFlow(
                    started_at=flow.started_at,
                    last_seen_at=flow.last_seen_at,
                )
            return completed
        if packet.tcp_flags & 0x05:
            return self._close(key, "tcp_close")
        return []

    def expire(self, now: float) -> list[CompletedFlow]:
        completed: list[CompletedFlow] = []
        for key, flow in list(self._flows.items()):
            if now - flow.last_seen_at >= self.idle_timeout:
                completed.extend(self._close(key, "idle_timeout"))
            elif now - flow.started_at >= self.active_timeout:
                completed.extend(self._close(key, "active_timeout"))
        for key, flow in list(self._suppressed.items()):
            if now - flow.last_seen_at >= self.idle_timeout or now - flow.started_at >= self.active_timeout:
                self._suppressed.pop(key, None)
        return completed

    def flush_all(self, reason: str = "shutdown") -> list[CompletedFlow]:
        completed: list[CompletedFlow] = []
        for key in list(self._flows):
            completed.extend(self._close(key, reason))
        self._suppressed.clear()
        return completed

    def snapshot(self) -> list[dict[str, Any]]:
        active = [
            {
                "state_type": "active",
                "src_ip": flow.src_ip,
                "src_port": flow.src_port,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "started_at": flow.started_at,
                "last_seen_at": flow.last_seen_at,
                "signed_packet_sizes": list(flow.signed_packet_sizes),
                "time_offsets": list(flow.time_offsets),
                "direction_confirmed": flow.direction_confirmed,
            }
            for flow in self._flows.values()
        ]
        suppressed = [
            {
                "state_type": "suppressed",
                "first_endpoint": list(key[0]),
                "second_endpoint": list(key[1]),
                "protocol": key[2],
                "started_at": flow.started_at,
                "last_seen_at": flow.last_seen_at,
            }
            for key, flow in self._suppressed.items()
        ]
        return active + suppressed

    def restore(self, records: Iterable[dict[str, Any]]) -> None:
        restored: Dict[Tuple[Tuple[str, int], Tuple[str, int], str], _FlowState] = {}
        suppressed: Dict[Tuple[Tuple[str, int], Tuple[str, int], str], _SuppressedFlow] = {}
        for record in records:
            if record.get("state_type") == "suppressed":
                try:
                    first = record["first_endpoint"]
                    second = record["second_endpoint"]
                    key = (
                        (str(first[0]), int(first[1])),
                        (str(second[0]), int(second[1])),
                        str(record["protocol"]).lower(),
                    )
                    state = _SuppressedFlow(
                        started_at=float(record["started_at"]),
                        last_seen_at=float(record["last_seen_at"]),
                    )
                except (KeyError, IndexError, TypeError, ValueError) as exc:
                    raise ValueError("invalid suppressed flow state") from exc
                if key[2] != "tcp" or state.last_seen_at < state.started_at or key in suppressed:
                    raise ValueError("invalid suppressed flow state")
                suppressed[key] = state
                continue
            try:
                sizes = [int(value) for value in record["signed_packet_sizes"]]
                offsets = [float(value) for value in record["time_offsets"]]
                flow = _FlowState(
                    src_ip=str(record["src_ip"]),
                    src_port=int(record["src_port"]),
                    dst_ip=str(record["dst_ip"]),
                    dst_port=int(record["dst_port"]),
                    protocol=str(record["protocol"]).lower(),
                    started_at=float(record["started_at"]),
                    last_seen_at=float(record["last_seen_at"]),
                    signed_packet_sizes=sizes,
                    time_offsets=offsets,
                    direction_confirmed=bool(record.get("direction_confirmed", False)),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("invalid active flow state") from exc
            if flow.protocol != "tcp" or len(sizes) != len(offsets) or not sizes or len(sizes) >= self.max_packets:
                raise ValueError("invalid active flow state")
            if flow.last_seen_at < flow.started_at:
                raise ValueError("invalid active flow timestamps")
            key = _flow_key_from_endpoints(
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
            )
            if key in restored:
                raise ValueError("duplicate active flow state")
            restored[key] = flow
        self._flows = restored
        self._suppressed = suppressed

    def _close(self, key, reason: str) -> list[CompletedFlow]:
        flow = self._flows.pop(key)
        if len(flow.signed_packet_sizes) < self.min_packets:
            return []
        return [
            CompletedFlow(
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                started_at=flow.started_at,
                ended_at=flow.last_seen_at,
                signed_packet_sizes=tuple(flow.signed_packet_sizes),
                time_offsets=tuple(flow.time_offsets),
                close_reason=reason,
            )
        ]


def _flow_key(packet: PacketObservation) -> tuple[tuple[str, int], tuple[str, int], str]:
    return _flow_key_from_endpoints(
        packet.src_ip,
        packet.src_port,
        packet.dst_ip,
        packet.dst_port,
        packet.protocol,
    )


def _flow_key_from_endpoints(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
) -> tuple[tuple[str, int], tuple[str, int], str]:
    first, second = sorted(((src_ip, src_port), (dst_ip, dst_port)))
    return first, second, protocol.lower()
