import argparse
import os

from cesnet_datazoo.config import DatasetConfig
from cesnet_datazoo.datasets import CESNET_QUIC22, CESNET_TLS_Year22


def export_dataset(ds_name: str, ds_cls, data_root: str, size: str, out_dir: str, train_size: int):
    print(f"\n[INFO] Initializing {ds_name} size={size} at {data_root}")
    ds = ds_cls(data_root=data_root, size=size, silent=False)
    cfg = DatasetConfig(
        dataset=ds,
        need_val_set=False,
        need_test_set=False,
        disable_label_encoding=True,
        train_workers=0,
        batch_size=2048,
        train_size=train_size,
    )
    ds.set_dataset_config_and_initialize(cfg, silent_warning=True)
    df = ds.get_train_df(flatten_ppi=False)

    cols = [c for c in ["PPI", "APP"] if c in df.columns]
    if "PPI" not in cols:
        raise RuntimeError(f"{ds_name} export failed: PPI column not found. Available cols: {list(df.columns)}")

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{ds_name}_{size}.csv")
    df[cols].to_csv(out_path, index=False)
    print(f"[OK] Saved {len(df)} rows -> {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Export CESNET datasets to PPI CSV (benign corpus).")
    parser.add_argument("--data-root", type=str, required=True, help="Root for cesnet-datazoo downloads/cache.")
    parser.add_argument("--dataset", type=str, choices=["tls_year22", "quic22", "both"], default="tls_year22")
    parser.add_argument("--size", type=str, default="XS", choices=["XS", "S", "M", "L", "ORIG"])
    parser.add_argument("--train-size", type=int, default=300000, help="Number of train samples to export.")
    parser.add_argument("--out-dir", type=str, default="datasets/processed/cesnet_ppi/benign")
    args = parser.parse_args()

    if args.dataset in ("tls_year22", "both"):
        export_dataset(
            ds_name="cesnet_tls_year22",
            ds_cls=CESNET_TLS_Year22,
            data_root=os.path.join(args.data_root, "CESNET-TLS-Year22"),
            size=args.size,
            out_dir=args.out_dir,
            train_size=args.train_size,
        )

    if args.dataset in ("quic22", "both"):
        export_dataset(
            ds_name="cesnet_quic22",
            ds_cls=CESNET_QUIC22,
            data_root=os.path.join(args.data_root, "CESNET-QUIC22"),
            size=args.size,
            out_dir=args.out_dir,
            train_size=args.train_size,
        )

    print("\n[DONE] CESNET PPI benign export completed.")


if __name__ == "__main__":
    main()


