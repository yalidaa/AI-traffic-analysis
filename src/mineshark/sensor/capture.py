from __future__ import annotations

import argparse
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import dpkt

from mineshark.sensor.config import SensorConfig
from mineshark.sensor.flow import PacketObservation


class CaptureReadError(ValueError):
    pass


def capture_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start dumpcap from the MineShark sensor configuration")
    parser.add_argument("--config", default="/etc/mineshark/sensor.toml")
    args = parser.parse_args(argv)
    config = SensorConfig.load(args.config, verify_model=False)
    config.capture.spool_dir.mkdir(parents=True, exist_ok=True)
    command = build_dumpcap_command(config)
    os.execv(command[0], command)
    return 0


@dataclass(frozen=True)
class CaptureStats:
    total_packets: int
    tcp_packets: int
    skipped_packets: int
    first_timestamp: float | None
    last_timestamp: float | None
    interface_received_packets: int | None
    interface_dropped_packets: int | None
    drop_status: str


@dataclass(frozen=True)
class CaptureReadResult:
    packets: tuple[PacketObservation, ...]
    stats: CaptureStats


def build_dumpcap_command(config: SensorConfig) -> list[str]:
    return [
        str(config.capture.dumpcap_path),
        "-i",
        config.interface,
        "-f",
        config.bpf,
        "-s",
        str(config.capture.snaplen),
        "-b",
        f"duration:{config.capture.rotate_seconds}",
        "-b",
        f"files:{config.capture.ring_files}",
        "-w",
        str(config.capture.spool_dir / "mineshark.pcapng"),
        "-q",
    ]


def read_capture(path: str | Path) -> CaptureReadResult:
    capture_path = Path(path)
    packets: list[PacketObservation] = []
    total_packets = 0
    skipped_packets = 0
    first_timestamp = None
    last_timestamp = None
    is_pcapng = False
    try:
        with capture_path.open("rb") as handle:
            magic = handle.read(4)
            handle.seek(0)
            if magic == b"\x0a\x0d\x0d\x0a":
                reader = dpkt.pcapng.Reader(handle)
                is_pcapng = True
            elif magic in {
                b"\xd4\xc3\xb2\xa1",
                b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\x3c\x4d",
            }:
                reader = dpkt.pcap.Reader(handle)
            else:
                raise CaptureReadError(f"unsupported or corrupt capture file: {capture_path}")
            if reader.datalink() != dpkt.pcap.DLT_EN10MB:
                raise CaptureReadError(f"unsupported capture link type: {reader.datalink()}")

            for timestamp, frame in reader:
                total_packets += 1
                numeric_timestamp = float(timestamp)
                first_timestamp = numeric_timestamp if first_timestamp is None else first_timestamp
                last_timestamp = numeric_timestamp
                try:
                    observation = _parse_ethernet_tcp(numeric_timestamp, frame)
                except (dpkt.NeedData, dpkt.UnpackError, ValueError, IndexError, socket.error):
                    skipped_packets += 1
                    continue
                if observation is not None:
                    packets.append(observation)
    except CaptureReadError:
        raise
    except (OSError, dpkt.NeedData, dpkt.UnpackError, ValueError) as exc:
        raise CaptureReadError(f"unable to read capture {capture_path}: {exc}") from exc

    interface_received, interface_dropped = (
        _read_pcapng_interface_statistics(capture_path) if is_pcapng else (None, None)
    )
    return CaptureReadResult(
        packets=tuple(packets),
        stats=CaptureStats(
            total_packets=total_packets,
            tcp_packets=len(packets),
            skipped_packets=skipped_packets,
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
            interface_received_packets=interface_received,
            interface_dropped_packets=interface_dropped,
            drop_status="reported" if interface_dropped is not None else "unknown",
        ),
    )


def _parse_ethernet_tcp(timestamp: float, frame: bytes) -> PacketObservation | None:
    ethernet = dpkt.ethernet.Ethernet(frame)
    network = ethernet.data
    while isinstance(network, dpkt.ethernet.VLANtag8021Q):
        network = network.data

    if isinstance(network, dpkt.ip.IP):
        if network.p != dpkt.ip.IP_PROTO_TCP or not isinstance(network.data, dpkt.tcp.TCP):
            return None
        tcp = network.data
        payload_length = max(0, int(network.len) - int(network.hl) * 4 - int(tcp.off) * 4)
        src_ip = socket.inet_ntop(socket.AF_INET, network.src)
        dst_ip = socket.inet_ntop(socket.AF_INET, network.dst)
    elif isinstance(network, dpkt.ip6.IP6):
        if not isinstance(network.data, dpkt.tcp.TCP):
            return None
        tcp = network.data
        extension_length = _ipv6_extension_length(network)
        payload_length = max(0, int(network.plen) - extension_length - int(tcp.off) * 4)
        src_ip = socket.inet_ntop(socket.AF_INET6, network.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, network.dst)
    else:
        return None

    return PacketObservation(
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=int(tcp.sport),
        dst_ip=dst_ip,
        dst_port=int(tcp.dport),
        protocol="tcp",
        ip_length=payload_length + 54,
        tcp_flags=int(tcp.flags),
    )


def _ipv6_extension_length(packet: dpkt.ip6.IP6) -> int:
    headers = getattr(packet, "all_extension_headers", None) or []
    total = 0
    for header in headers:
        try:
            total += len(bytes(header))
        except (TypeError, ValueError):
            continue
    return total


def _read_pcapng_interface_statistics(path: Path) -> tuple[int | None, int | None]:
    data = path.read_bytes()
    offset = 0
    endian = "<"
    received_total = 0
    dropped_total = 0
    received_seen = False
    dropped_seen = False
    while offset + 12 <= len(data):
        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            if offset + 16 > len(data):
                break
            byte_order_magic = data[offset + 8 : offset + 12]
            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                break
        try:
            block_type, block_length = struct.unpack_from(f"{endian}II", data, offset)
        except struct.error:
            break
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            break
        if block_type == 5 and block_length >= 24:
            options_start = offset + 20
            options_end = offset + block_length - 4
            cursor = options_start
            while cursor + 4 <= options_end:
                option_code, option_length = struct.unpack_from(f"{endian}HH", data, cursor)
                cursor += 4
                if option_code == 0:
                    break
                padded_length = (option_length + 3) & ~3
                if cursor + padded_length > options_end:
                    break
                if option_length == 8 and option_code in {4, 5}:
                    value = struct.unpack_from(f"{endian}Q", data, cursor)[0]
                    if option_code == 4:
                        received_total += value
                        received_seen = True
                    else:
                        dropped_total += value
                        dropped_seen = True
                cursor += padded_length
        offset += block_length
    return (received_total if received_seen else None, dropped_total if dropped_seen else None)
