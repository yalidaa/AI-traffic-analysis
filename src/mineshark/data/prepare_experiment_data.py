import argparse
import shutil
from pathlib import Path

from mineshark.data.prepare_ppi_from_logs import convert_one_log


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BASE_SOURCES = {
    "Cridex.pcap.log",
    "Miuref.pcap.log",
    "Virut.pcap.log",
    "Zeus.pcap.log",
}


def ensure_clean_dir(path: Path):
    if path.exists():
        if any(path.iterdir()):
            raise RuntimeError(
                f"Refusing to clear non-empty directory: {path}. "
                "Please move or manually clean it before regenerating experiment data."
            )
    path.mkdir(parents=True, exist_ok=True)


def copy_logs(src_dir: Path, dst_dir: Path, keep_names: set[str] | None = None):
    copied = []
    for path in sorted(src_dir.glob("*.log")):
        if keep_names is None or path.name in keep_names:
            shutil.copy2(path, dst_dir / path.name)
            copied.append(path.name)
    return copied


def convert_dir_to_ppi(log_dir: Path, out_dir: Path, app_label: str, min_packets: int, max_len: int):
    ensure_clean_dir(out_dir)
    converted = []
    for log_path in sorted(log_dir.glob("*.log")):
        out_csv = out_dir / log_path.name.replace(".log", "_ppi.csv")
        saved, skipped = convert_one_log(
            log_path=str(log_path),
            out_csv=str(out_csv),
            app_label=app_label,
            min_packets=min_packets,
            max_len=max_len,
        )
        converted.append((log_path.name, saved, skipped))
    return converted


def copy_file(src: Path, dst: Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def print_section(title: str):
    print(f"\n[{title}]")


def main():
    parser = argparse.ArgumentParser(description="Prepare log/PPI folders for base/latest/hybrid experiments.")
    parser.add_argument("--source-malware-dir", type=str, default="datasets/raw/logs_malware")
    parser.add_argument("--source-benign-dir", type=str, default="datasets/raw/logs_benign")
    parser.add_argument("--output-root", type=str, default="datasets/experiments")
    parser.add_argument(
        "--cesnet-benign-csv",
        type=str,
        default="datasets/processed/cesnet_ppi/benign/cesnet_tls_year22_XS.csv",
        help="CESNET benign CSV copied into the hybrid PPI benign folder.",
    )
    parser.add_argument("--min-packets", type=int, default=3)
    parser.add_argument("--max-len", type=int, default=30)
    args = parser.parse_args()

    source_malware_dir = (PROJECT_ROOT / args.source_malware_dir).resolve()
    source_benign_dir = (PROJECT_ROOT / args.source_benign_dir).resolve()
    output_root = (PROJECT_ROOT / args.output_root).resolve()
    cesnet_benign_csv = (PROJECT_ROOT / args.cesnet_benign_csv).resolve()

    logs_root = output_root
    ppi_root = output_root / "ppi"
    base_log_dir = logs_root / "logs_malware_base"
    local_benign_ppi_dir = ppi_root / "local_benign"
    local_malware_base_ppi_dir = ppi_root / "local_malware_base"
    local_malware_latest_ppi_dir = ppi_root / "local_malware_latest"
    hybrid_benign_ppi_dir = ppi_root / "hybrid_benign"

    ensure_clean_dir(base_log_dir)
    base_logs = copy_logs(source_malware_dir, base_log_dir, DEFAULT_BASE_SOURCES)

    print_section("Base Malware Logs")
    print(f"Prepared: {base_log_dir}")
    for name in base_logs:
        print(f"  - {name}")

    convert_dir_to_ppi(source_benign_dir, local_benign_ppi_dir, "benign", args.min_packets, args.max_len)
    convert_dir_to_ppi(base_log_dir, local_malware_base_ppi_dir, "malware", args.min_packets, args.max_len)
    convert_dir_to_ppi(source_malware_dir, local_malware_latest_ppi_dir, "malware", args.min_packets, args.max_len)

    ensure_clean_dir(hybrid_benign_ppi_dir)
    for csv_path in sorted(local_benign_ppi_dir.glob("*.csv")):
        copy_file(csv_path, hybrid_benign_ppi_dir / csv_path.name)
    if cesnet_benign_csv.exists():
        copy_file(cesnet_benign_csv, hybrid_benign_ppi_dir / cesnet_benign_csv.name)

    print_section("PPI Folders")
    print(f"Local benign: {local_benign_ppi_dir}")
    print(f"Local malware base: {local_malware_base_ppi_dir}")
    print(f"Local malware latest: {local_malware_latest_ppi_dir}")
    print(f"Hybrid benign: {hybrid_benign_ppi_dir}")
    if cesnet_benign_csv.exists():
        print(f"Included CESNET benign CSV: {cesnet_benign_csv.name}")
    else:
        print("CESNET benign CSV not found; hybrid benign contains only local benign PPI.")


if __name__ == "__main__":
    main()
