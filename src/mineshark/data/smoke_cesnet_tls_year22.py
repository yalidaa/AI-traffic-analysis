import argparse
from collections import Counter

import numpy as np
from cesnet_datazoo.config import DatasetConfig
from cesnet_datazoo.datasets import CESNET_TLS_Year22


def main():
    parser = argparse.ArgumentParser(description="Smoke test CESNET-TLS-Year22 via cesnet-datazoo")
    parser.add_argument("--data-root", type=str, required=True)
    parser.add_argument("--size", type=str, default="XS", choices=["XS", "S", "M", "L", "ORIG"])
    parser.add_argument("--train-size", type=int, default=50000)
    parser.add_argument("--batch-size", type=int, default=512)
    args = parser.parse_args()

    print("[1/4] Init dataset (will auto-download if missing)")
    ds = CESNET_TLS_Year22(data_root=args.data_root, size=args.size, silent=False)

    print("[2/4] Build config and initialize")
    cfg = DatasetConfig(
        dataset=ds,
        need_val_set=False,
        need_test_set=False,
        disable_label_encoding=True,
        train_size=args.train_size,
        train_workers=0,
        batch_size=args.batch_size,
        return_tensors=False,
    )
    ds.set_dataset_config_and_initialize(cfg, silent_warning=True)

    print("[3/4] Get one training batch")
    train_loader = ds.get_train_dataloader()
    batch_other_fields, batch_ppi, batch_flowstats, batch_labels = next(iter(train_loader))

    print(f"Batch PPI shape: {np.asarray(batch_ppi).shape}")
    print(f"Batch Flowstats shape: {np.asarray(batch_flowstats).shape}")
    print(f"Batch Labels count: {len(batch_labels)}")

    label_counter = Counter(batch_labels)
    top5 = label_counter.most_common(5)
    print(f"Top-5 labels in batch: {top5}")

    print("[4/4] Small dataframe preview (APP + PPI)")
    df = ds.get_train_df(flatten_ppi=False).head(5)
    cols = [c for c in ["APP", "PPI", "CATEGORY"] if c in df.columns]
    print(df[cols].to_string(index=False))

    print("\n[SMOKE TEST PASS] CESNET-TLS-Year22 can be downloaded and iterated.")
    print("[NOTE] APP is multi-class service label, not malware/benign binary label.")


if __name__ == "__main__":
    main()
