import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.training.train import metrics_at_threshold, select_threshold


class TrainingThresholdTests(unittest.TestCase):
    def test_metrics_at_threshold_reports_false_positive_rate(self):
        labels = [0, 0, 1, 1]
        probs = [0.2, 0.8, 0.7, 0.9]

        metrics = metrics_at_threshold(labels, probs, threshold=0.5)

        self.assertEqual(metrics["tp"], 2)
        self.assertEqual(metrics["fp"], 1)
        self.assertEqual(metrics["tn"], 1)
        self.assertEqual(metrics["fn"], 0)
        self.assertAlmostEqual(metrics["fpr"], 0.5)

    def test_select_threshold_respects_target_fpr_when_possible(self):
        labels = [0, 0, 1, 1]
        probs = [0.2, 0.8, 0.7, 0.9]

        selected = select_threshold(labels, probs, target_fpr=0.0)

        self.assertEqual(selected["fp"], 0)
        self.assertEqual(selected["fpr"], 0.0)
        self.assertGreater(selected["threshold"], 0.8)
        self.assertEqual(selected["tp"], 1)

    def test_select_threshold_rejects_invalid_target_fpr(self):
        with self.assertRaises(ValueError):
            select_threshold([0, 1], [0.1, 0.9], target_fpr=1.5)


if __name__ == "__main__":
    unittest.main()
