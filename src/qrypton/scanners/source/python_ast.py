"""Semantic, import-bound Python cryptographic source detection."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from qrypton.contracts.enums import EvidenceKind
from qrypton.contracts.models import EvidenceLocation
from qrypton.ports.scanners import ScanLimits, SourceObservation
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.rules import CRYPTO_LIBRARY_PREFIXES, MODE_NAMES, algorithm_for_name
from qrypton.scanners.source.traversal import SourceFile

_SECRET_LITERAL = re.compile(r"(?i)(key|secret|password|token)\s*=|b?['\"][^'\"]{16,}['\"]")


def _snippet(source: SourceFile, node: ast.AST, limit: int) -> str | None:
    value = ast.get_source_segment(source.text, node)
    if not value:
        return None
    if _SECRET_LITERAL.search(value):
        return "<redacted-source-literal>"
    return value[:limit]


def _attribute_name(node: ast.AST, imports: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _attribute_name(node.value, imports)
        return f"{base}.{node.attr}" if base else None
    return None


def _observation(
    source: SourceFile,
    node: ast.AST,
    *,
    rule_id: str,
    subject_kind: str,
    subject_value: str,
    confidence: float,
    policy: SourceScanPolicy,
    parameters: dict[str, str | int | float | bool | None] | None = None,
) -> SourceObservation:
    attributes: dict[str, str | int | float | bool | None] = {
        "language": "python",
        "detector_type": "python_ast",
        "rule_id": rule_id,
        "subject_kind": subject_kind,
        "subject_value": subject_value,
        "confidence_reason": "resolved import-bound AST call",
    }
    attributes.update(parameters or {})
    return SourceObservation(
        kind=EvidenceKind.SOURCE_AST,
        location=EvidenceLocation(
            relative_path=source.relative_path,
            line_start=getattr(node, "lineno", None),
            line_end=getattr(node, "end_lineno", None),
            byte_start=getattr(node, "col_offset", None),
            byte_end=getattr(node, "end_col_offset", None)
            if getattr(node, "lineno", None) == getattr(node, "end_lineno", None)
            and getattr(node, "end_col_offset", 0) >= getattr(node, "col_offset", 0)
            else None,
        ),
        payload_digest=source.digest,
        excerpt=_snippet(source, node, policy.max_snippet_bytes),
        attributes=attributes,
        confidence=min(confidence, 0.35) if source.encoding_degraded else confidence,
        language="python",
        detector_type="python_ast",
        rule_id=rule_id,
        source_file_digest=source.digest,
    )


class _Visitor(ast.NodeVisitor):
    def __init__(self, source: SourceFile, policy: SourceScanPolicy, limits: ScanLimits) -> None:
        self.source = source
        self.policy = policy
        self.limits = limits
        self.imports: dict[str, str] = {}
        self.output: list[SourceObservation] = []
        self.nodes = 0
        self.mode_algorithms: dict[ast.AST, str] = {}
        self.algorithm_modes: dict[ast.AST, str] = {}

    def _bind_cipher_mode(self, node: ast.Call, full_name: str) -> None:
        if full_name != "cryptography.hazmat.primitives.ciphers.cipher":
            return
        keywords = {keyword.arg: keyword.value for keyword in node.keywords}
        algorithm_node = node.args[0] if node.args else keywords.get("algorithm")
        mode_node = node.args[1] if len(node.args) > 1 else keywords.get("mode")
        if not isinstance(algorithm_node, ast.Call) or not isinstance(mode_node, ast.Call):
            return
        algorithm_name = (_attribute_name(algorithm_node.func, self.imports) or "").casefold()
        mode_name = (_attribute_name(mode_node.func, self.imports) or "").casefold()
        mode = mode_name.rsplit(".", 1)[-1]
        rule = algorithm_for_name(algorithm_name.rsplit(".", 1)[-1])
        if (
            algorithm_name.startswith("cryptography.hazmat.primitives.ciphers.algorithms.")
            and mode_name.startswith("cryptography.hazmat.primitives.ciphers.modes.")
            and mode in MODE_NAMES
            and rule is not None
            and rule.family == "symmetric_cipher"
        ):
            self.mode_algorithms[mode_node] = rule.canonical_name
            self.algorithm_modes[algorithm_node] = mode.upper()

    def _parameters(
        self, node: ast.Call, full_name: str
    ) -> dict[str, str | int | float | bool | None]:
        parameters: dict[str, str | int | float | bool | None] = {}
        keywords = {keyword.arg: keyword.value for keyword in node.keywords}
        size_node = keywords.get("key_size")
        if full_name == "crypto.publickey.rsa.generate":
            size_node = node.args[0] if node.args else keywords.get("bits")
        elif full_name == "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key":
            size_node = node.args[1] if len(node.args) > 1 else keywords.get("key_size")
        if (
            isinstance(size_node, ast.Constant)
            and type(size_node.value) is int
            and 1 <= size_node.value <= 1_000_000
        ):
            parameters["key_size_bits"] = size_node.value
        # "length" is API-dependent and often measured in bytes (e.g. HKDF).
        # Only explicitly bit-valued signatures above establish a key size.
        if node in self.algorithm_modes:
            parameters["mode"] = self.algorithm_modes[node]
        if full_name == "crypto.cipher.aes.new":
            mode_node = node.args[1] if len(node.args) > 1 else keywords.get("mode")
            mode_name = (
                (_attribute_name(mode_node, self.imports) or "").casefold() if mode_node else ""
            )
            if mode_name.startswith("crypto.cipher.aes.mode_"):
                mode = mode_name.removeprefix("crypto.cipher.aes.mode_")
                if mode in MODE_NAMES:
                    parameters["mode"] = mode.upper()
        return parameters

    def visit(self, node: ast.AST) -> None:
        self.nodes += 1
        if self.nodes > self.limits.max_ast_nodes:
            raise ValueError("AST node limit exceeded")
        super().visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            self.imports[bound] = alias.name
            if alias.name.split(".")[0].casefold() in CRYPTO_LIBRARY_PREFIXES:
                self.output.append(
                    _observation(
                        self.source,
                        node,
                        rule_id="python.library.import",
                        subject_kind="library",
                        subject_value=alias.name,
                        confidence=0.80,
                        policy=self.policy,
                    )
                )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            bound = alias.asname or alias.name
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports[bound] = full_name
            if module.split(".")[0].casefold() in CRYPTO_LIBRARY_PREFIXES:
                self.output.append(
                    _observation(
                        self.source,
                        node,
                        rule_id="python.library.import",
                        subject_kind="library",
                        subject_value=module,
                        confidence=0.80,
                        policy=self.policy,
                    )
                )

    def visit_Call(self, node: ast.Call) -> None:
        full_name = (_attribute_name(node.func, self.imports) or "").casefold()
        self._bind_cipher_mode(node, full_name)
        tail = full_name.rsplit(".", 1)[-1]
        rule = algorithm_for_name(tail)
        if rule is None:
            rule = next(
                (
                    candidate
                    for segment in reversed(full_name.split("."))
                    if (candidate := algorithm_for_name(segment)) is not None
                ),
                None,
            )
        if rule and "." in full_name:
            parameters = self._parameters(node, full_name)
            self.output.append(
                _observation(
                    self.source,
                    node,
                    rule_id=f"python.algorithm.{rule.canonical_name.replace('-', '_')}",
                    subject_kind="algorithm",
                    subject_value=rule.canonical_name,
                    confidence=1.00 if parameters else 0.95,
                    policy=self.policy,
                    parameters=parameters,
                )
            )
        if tail.casefold() in MODE_NAMES and "." in full_name:
            self.output.append(
                _observation(
                    self.source,
                    node,
                    rule_id=f"python.mode.{tail}",
                    subject_kind="mode",
                    subject_value=tail.upper(),
                    confidence=0.95,
                    policy=self.policy,
                    parameters={"algorithm_name": self.mode_algorithms[node]}
                    if node in self.mode_algorithms
                    else None,
                )
            )
        if full_name.endswith("sslcontext") or full_name.endswith("wrap_socket"):
            self.output.append(
                _observation(
                    self.source,
                    node,
                    rule_id="python.protocol.tls",
                    subject_kind="protocol",
                    subject_value="tls",
                    confidence=0.95,
                    policy=self.policy,
                )
            )
        if (
            full_name.endswith("set_ciphers")
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            suite = node.args[0].value
            if isinstance(suite, str) and suite:
                self.output.append(
                    _observation(
                        self.source,
                        node,
                        rule_id="python.protocol.cipher_suite",
                        subject_kind="cipher_suite",
                        subject_value=suite[:512],
                        confidence=1.00,
                        policy=self.policy,
                    )
                )
        self.generic_visit(node)


def analyze_python_ast(
    source: SourceFile, *, policy: SourceScanPolicy, limits: ScanLimits
) -> Iterator[SourceObservation]:
    """Yield import-bound AST evidence; callers handle syntax failures with lexical fallback."""
    tree = ast.parse(source.text, filename=source.relative_path, type_comments=False)
    visitor = _Visitor(source, policy, limits)
    visitor.visit(tree)
    yield from visitor.output
