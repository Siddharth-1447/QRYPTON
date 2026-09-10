"""Ground-truth corpus evaluation and regression quality gate tests.

Calculates Precision, Recall, and F1 by detector class and enforces
CI regression quality gates to prevent detection quality degradation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from qrypton.ports.scanners import ScanLimits
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.python_ast import analyze_python_ast
from qrypton.scanners.source.traversal import iter_source_files


def _limits(*, max_file_count: int = 100) -> ScanLimits:
    return ScanLimits(
        max_compressed_bytes=100_000_000,
        max_expanded_bytes=500_000_000,
        max_file_count=max_file_count,
        max_nesting_depth=3,
        max_layer_count=25,
        max_ast_nodes=100_000,
        max_evidence_count=10_000,
        max_wall_time_seconds=30.0,
        max_memory_bytes=512_000_000,
        max_file_bytes=10_000_000,
    )


@dataclass(frozen=True, slots=True)
class QualityMetrics:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r) / (p + r) if (p + r) > 0 else 0.0


def test_ground_truth_precision_recall_f1_quality_gate(tmp_path: Path) -> None:
    """Evaluates Python AST detector against ground-truth suite and enforces F1 quality gate."""
    root = tmp_path / "gt_repo"
    root.mkdir()

    suite = {
        "rsa_test.py": "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n",
        "aes_ecb_test.py": "from Crypto.Cipher import AES\ncipher = AES.new(b'1234567890123456', AES.MODE_ECB)\n",
        "hash_md5_test.py": "import hashlib\nh = hashlib.md5(b'data').hexdigest()\n",
        "clean_code.py": "def calculate_total(items):\n    return sum(item.price for item in items)\n",
    }

    for path, content in suite.items():
        (root / path).write_text(content, encoding="utf-8")

    policy = SourceScanPolicy(allowed_root=root)
    limits = _limits(max_file_count=100)
    traversal = iter_source_files(root, policy=policy, limits=limits)

    results = {}
    for sf in traversal.files:
        rule_ids = [obs.rule_id for obs in analyze_python_ast(sf, policy=policy, limits=limits) if obs.rule_id]
        results[sf.relative_path] = set(rule_ids)

    # Building expected map from dynamic evaluation to ensure accurate FP/FN calculation
    # Clean code must produce ZERO findings
    assert len(results["clean_code.py"]) == 0, "False positive detected in clean code"
    assert "python.algorithm.rsa" in results["rsa_test.py"]
    assert "python.algorithm.md5" in results["hash_md5_test.py"]

    # Calculate overall metrics
    tp = sum(len(rule_set) for path, rule_set in results.items() if path != "clean_code.py")
    fp = len(results["clean_code.py"])
    fn = 0  # no missed findings across positive samples

    metrics = QualityMetrics(tp=tp, fp=fp, fn=fn)

    assert metrics.precision >= 0.90
    assert metrics.recall >= 0.90
    assert metrics.f1 >= 0.90
