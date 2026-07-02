from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.data.tor_quality import inspect_tor_ppi
from mineshark.data.dataset import load_multiclass_samples_from_ppi_dirs
from mineshark.data.prepare_tor_ppi import convert_path
from mineshark.data.tor_registry import (
    load_research_registry,
    render_registry_markdown,
    validate_local_manifest,
)
from mineshark.evaluation.tor_eval import _metrics_for_rows
from mineshark.training.train_multiclass import multiclass_metrics
from mineshark.training.train import EXPERIMENT_PRESETS, apply_experiment_preset, build_parser


class TorDatasetTests(unittest.TestCase):
    def test_registry_contains_four_top_conference_tor_sources(self):
        registry = load_research_registry(ROOT / "configs" / "datasets" / "tor_research_registry.json")
        dataset_ids = {item["id"] for item in registry["datasets"]}

        self.assertIn("awf-rimmer", dataset_ids)
        self.assertIn("ares-multitab", dataset_ids)
        self.assertIn("netclr-drift", dataset_ids)
        self.assertIn("wsc-usenix24", dataset_ids)

        manifest = [
            {
                "id": "local-awf-train",
                "dataset_id": "awf-rimmer",
                "role": "main_train_eval",
                "label_type": "website_class",
                "format": "jsonl",
                "path": "datasets/raw/tor/awf/train.jsonl",
            }
        ]
        self.assertEqual(validate_local_manifest(manifest, registry), [])

        markdown = render_registry_markdown(registry, manifest)
        self.assertIn("Tor Dataset Inventory", markdown)
        self.assertIn("awf-rimmer", markdown)
        self.assertIn("local-awf-train", markdown)

    def test_tor_jsonl_trace_converts_to_ppi_csv(self):
        fixture = ROOT / "tests" / "fixtures" / "tor_traces" / "sample_tor_wf.jsonl"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "tor_ppi.csv"
            stats = convert_path(fixture, output, default_app="tor", min_packets=3, max_len=4)

            self.assertEqual(stats, {"files": 1, "saved": 2, "skipped": 0})
            with output.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        first_ppi = json.loads(rows[0]["PPI"])
        second_ppi = json.loads(rows[1]["PPI"])
        self.assertEqual(len(first_ppi[0]), 4)
        for actual, expected in zip(first_ppi[0], [0.0, 0.12, 0.19, 0.47]):
            self.assertAlmostEqual(actual, expected)
        self.assertEqual(first_ppi[1], [1.0, -1.0, 1.0, -1.0])
        self.assertEqual(first_ppi[2], [514.0, 514.0, 514.0, 514.0])
        self.assertEqual(second_ppi[1], [1.0, -1.0, 1.0, 1.0])
        self.assertEqual(second_ppi[2], [514.0, 514.0, 514.0, 514.0])
        self.assertEqual(rows[0]["APP"], "monitored_site")
        self.assertEqual(rows[1]["APP"], "multi_tab")

    def test_tor_csv_and_trace_inputs_convert_to_ppi_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_input = root / "trace.csv"
            trace_input = root / "sample.trace"
            output = root / "converted.csv"

            with csv_input.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["directions", "timestamps", "label", "source"])
                writer.writeheader()
                writer.writerow(
                    {
                        "directions": json.dumps([1, -1, 1]),
                        "timestamps": json.dumps([0.0, 0.2, 0.5]),
                        "label": "csv_site",
                        "source": "csv_source",
                    }
                )
            trace_input.write_text("0.0 1 514\n0.3 -1 514\n0.4 1 514\n", encoding="utf-8")

            stats = convert_path(root, output, default_app="trace_site", min_packets=3, max_len=8)
            self.assertEqual(stats["saved"], 2)
            with output.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        apps = {row["APP"] for row in rows}
        sources = {row["SOURCE"] for row in rows}
        self.assertIn("csv_site", apps)
        self.assertIn("trace_site", apps)
        self.assertIn("csv_source", sources)
        self.assertIn("sample.trace", sources)

    def test_tor_npy_and_npz_inputs_convert_to_ppi_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            npy_input = root / "directions.npy"
            npz_input = root / "labeled.npz"
            output = root / "numpy_ppi.csv"

            np.save(npy_input, np.array([[1, -1, 1, -1], [1, 1, -1, -1]], dtype=np.int16))
            np.savez(
                npz_input,
                X=np.array([[1, -1, 1, 0], [1, 1, -1, 0]], dtype=np.int16),
                y=np.array(["npz_site_a", "npz_site_b"]),
                timestamps=np.array([[0.0, 0.1, 0.4, 0.0], [0.0, 0.3, 0.7, 0.0]], dtype=np.float32),
            )

            stats = convert_path(root, output, default_app="npy_tor", min_packets=3, max_len=4)
            self.assertEqual(stats["saved"], 4)
            with output.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 4)
        apps = [row["APP"] for row in rows]
        self.assertEqual(apps.count("npy_tor"), 2)
        self.assertIn("npz_site_a", apps)
        self.assertIn("npz_site_b", apps)
        ppi = json.loads(next(row["PPI"] for row in rows if row["APP"] == "npz_site_a"))
        self.assertEqual(ppi[1], [1.0, -1.0, 1.0])
        self.assertEqual(len(ppi[0]), 3)

    def test_tor_npz_preserves_zero_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            npz_input = root / "zero_label.npz"
            output = root / "zero_label_ppi.csv"

            np.savez(
                npz_input,
                X=np.array([[1, -1, 1, 0]], dtype=np.int8),
                y=np.array([0], dtype=np.int64),
            )

            stats = convert_path(npz_input, output, default_app="fallback_tor", min_packets=3, max_len=4)
            self.assertEqual(stats["saved"], 1)
            with output.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(rows[0]["APP"], "0")

    def test_tor_npz_signed_timestamps_convert_to_ppi(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            npz_input = root / "signed_time.npz"
            output = root / "signed_time_ppi.csv"

            np.savez(
                npz_input,
                X=np.array([[0.05, -0.20, 0.35, 0.0]], dtype=np.float32),
                y=np.array(["site_a"]),
            )

            stats = convert_path(npz_input, output, default_app="fallback_tor", min_packets=3, max_len=4)
            self.assertEqual(stats["saved"], 1)
            with output.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        ppi = json.loads(rows[0]["PPI"])
        self.assertEqual(ppi[1], [1.0, -1.0, 1.0])
        self.assertEqual(ppi[2], [514.0, 514.0, 514.0])
        for actual, expected in zip(ppi[0], [0.0, 0.15, 0.15]):
            self.assertAlmostEqual(actual, expected, places=5)

    def test_multiclass_ppi_loader_maps_app_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ppi = root / "cw.csv"
            with ppi.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["PPI", "APP", "SOURCE"])
                writer.writeheader()
                for app in ("0", "2", "1"):
                    writer.writerow(
                        {
                            "PPI": json.dumps([[0.0, 0.1, 0.2], [1, -1, 1], [514, 514, 514]]),
                            "APP": app,
                            "SOURCE": f"trace-{app}",
                        }
                    )

            samples, class_names, class_to_idx = load_multiclass_samples_from_ppi_dirs([str(root)], max_len=4)

        self.assertEqual(class_names, ["0", "1", "2"])
        self.assertEqual(class_to_idx, {"0": 0, "1": 1, "2": 2})
        self.assertEqual([sample["label"] for sample in samples], [0, 2, 1])
        self.assertEqual([sample["label_name"] for sample in samples], ["0", "2", "1"])

    def test_multiclass_metrics_include_top5(self):
        labels = [0, 1, 2]
        probs = np.array(
            [
                [0.7, 0.2, 0.1],
                [0.1, 0.8, 0.1],
                [0.4, 0.5, 0.1],
            ],
            dtype=np.float32,
        )

        metrics = multiclass_metrics(labels, probs)

        self.assertAlmostEqual(metrics["accuracy"], 2 / 3)
        self.assertAlmostEqual(metrics["top1_accuracy"], 2 / 3)
        self.assertAlmostEqual(metrics["top5_accuracy"], 1.0)

    def test_manifest_validation_reports_invalid_records(self):
        registry = load_research_registry(ROOT / "configs" / "datasets" / "tor_research_registry.json")
        with tempfile.TemporaryDirectory() as tmp:
            missing_path = str(Path(tmp) / "missing.jsonl")
            errors = validate_local_manifest(
                [
                    {"id": "missing-fields"},
                    {
                        "id": "bad-dataset",
                        "dataset_id": "not-real",
                        "role": "not-a-role",
                        "label_type": "website_class",
                        "format": "parquet",
                        "path": missing_path,
                    },
                ],
                registry,
                require_existing_paths=True,
            )

        joined = "\n".join(errors)
        self.assertIn("missing required field 'dataset_id'", joined)
        self.assertIn("unknown dataset_id 'not-real'", joined)
        self.assertIn("unsupported format 'parquet'", joined)
        self.assertIn("unsupported role 'not-a-role'", joined)
        self.assertIn("path does not exist", joined)

    def test_tor_quality_report_counts_classes_sources_and_short_samples(self):
        fixture = ROOT / "tests" / "fixtures" / "tor_traces" / "sample_tor_wf.jsonl"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "tor_ppi.csv"
            convert_path(fixture, output, default_app="tor", min_packets=3, max_len=4)
            report = inspect_tor_ppi(output, min_packets=5)

        self.assertEqual(report["sample_count"], 2)
        self.assertEqual(report["invalid_rows"], 0)
        self.assertEqual(report["class_count"], 2)
        self.assertEqual(report["short_sample_count"], 2)
        self.assertEqual(report["empty_direction_sample_count"], 0)

    def test_tor_eval_metrics_include_fpr_fnr_and_confusion_counts(self):
        rows = [
            {"label": 0, "positive_probability": 0.1, "threshold": 0.5},
            {"label": 0, "positive_probability": 0.7, "threshold": 0.5},
            {"label": 1, "positive_probability": 0.8, "threshold": 0.5},
            {"label": 1, "positive_probability": 0.2, "threshold": 0.5},
        ]
        metrics = _metrics_for_rows(rows)

        self.assertEqual(metrics["tp"], 1)
        self.assertEqual(metrics["fp"], 1)
        self.assertEqual(metrics["tn"], 1)
        self.assertEqual(metrics["fn"], 1)
        self.assertAlmostEqual(metrics["fpr"], 0.5)
        self.assertAlmostEqual(metrics["fnr"], 0.5)

    def test_tor_binary_training_preset_sets_ppi_paths_and_labels(self):
        self.assertIn("tor_binary", EXPERIMENT_PRESETS)
        parser = build_parser()
        args = parser.parse_args(["--experiment", "tor_binary"])
        args = apply_experiment_preset(args, parser)

        self.assertEqual(args.data_format, "ppi")
        self.assertEqual(Path(args.malware_dir), (ROOT / "datasets" / "experiments" / "ppi" / "tor" / "risk").resolve())
        self.assertEqual(
            Path(args.benign_dir), (ROOT / "datasets" / "experiments" / "ppi" / "tor" / "normal").resolve()
        )
        self.assertEqual(args.save_path, str((ROOT / "checkpoints" / "tor_binary_mineshark.pt").resolve()))
        self.assertEqual(args.target_fpr, 0.02)
        self.assertEqual(args.negative_label_name, "normal_tor")
        self.assertEqual(args.positive_label_name, "tor_risk_evidence")


if __name__ == "__main__":
    unittest.main()
