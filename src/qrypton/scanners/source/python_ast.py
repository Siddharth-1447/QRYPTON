"""Semantic, import-bound Python cryptographic source detection."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from qrypton.contracts.enums import EvidenceKind
from qrypton.contracts.models import EvidenceLocation
from qrypton.ports.scanners import ScanLimits, SourceObservation
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.rules import (
    CRYPTO_LIBRARY_PREFIXES,
    MODE_NAMES,
    algorithm_components,
    algorithm_for_name,
)
from qrypton.scanners.source.traversal import SourceFile

_SECRET_LITERAL = re.compile(r"(?i)(key|secret|password|token)\s*=|b?['\"][^'\"]{16,}['\"]")
_MAX_RESOLVED_ALGORITHM_LENGTH = 128


class _LiteralBindings(ast.NodeVisitor):
    """Count writes in one scope; retain only unconditional literal assignments."""

    def __init__(self, max_nodes: int) -> None:
        self.max_nodes = max_nodes
        self.visited = 0
        self.writes: dict[str, list[tuple[str | None, ast.AST]]] = {}
        self.direct = False

    def visit(self, node: ast.AST) -> None:
        self.visited += 1
        if self.visited > self.max_nodes:
            raise ValueError("AST node limit exceeded")
        super().visit(node)

    def _write(self, target: ast.AST, value: str | None, statement: ast.AST) -> None:
        for child in ast.walk(target):
            if isinstance(child, ast.Name):
                self.writes.setdefault(child.id, []).append((value, statement))

    def visit_Assign(self, node: ast.Assign) -> None:
        value = (
            node.value.value
            if self.direct
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and 0 < len(node.value.value) <= _MAX_RESOLVED_ALGORITHM_LENGTH
            else None
        )
        for target in node.targets:
            self._write(target, value if isinstance(target, ast.Name) else None, node)
        previous = self.direct
        self.direct = False
        self.visit(node.value)
        self.direct = previous

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        value = (
            node.value.value
            if self.direct
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and 0 < len(node.value.value) <= _MAX_RESOLVED_ALGORITHM_LENGTH
            else None
        )
        self._write(node.target, value if isinstance(node.target, ast.Name) else None, node)
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._write(node.target, None, node)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._write(node.target, None, node)
        self.visit(node.value)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._write(node, None, node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._write(ast.Name(id=node.name, ctx=ast.Store()), None, node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._write(ast.Name(id=node.name, ctx=ast.Store()), None, node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self._write(ast.Name(id=name, ctx=ast.Store()), None, node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self._write(ast.Name(id=name, ctx=ast.Store()), None, node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self._write(ast.Name(id=node.name, ctx=ast.Store()), None, node)
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global | ast.Nonlocal) -> None:
        for name in node.names:
            self._write(ast.Name(id=name, ctx=ast.Store()), None, node)

    visit_Nonlocal = visit_Global


def _scope_bindings(
    body: list[ast.stmt], parameters: ast.arguments | None, max_nodes: int
) -> dict[str, list[tuple[str | None, ast.AST]]]:
    collector = _LiteralBindings(max_nodes)
    if parameters is not None:
        for arg in (*parameters.posonlyargs, *parameters.args, *parameters.kwonlyargs):
            collector.writes.setdefault(arg.arg, []).append((None, arg))
        for optional_arg in (parameters.vararg, parameters.kwarg):
            if optional_arg is not None:
                collector.writes.setdefault(optional_arg.arg, []).append((None, optional_arg))
    for statement in body:
        collector.direct = isinstance(statement, (ast.Assign, ast.AnnAssign))
        collector.visit(statement)
    return collector.writes


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
        self.literal_scopes: list[dict[str, list[tuple[str | None, ast.AST]]]] = []

    def visit_Module(self, node: ast.Module) -> None:
        self.literal_scopes.append(_scope_bindings(node.body, None, self.limits.max_ast_nodes))
        self.generic_visit(node)
        self.literal_scopes.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        self.literal_scopes.append(_scope_bindings(node.body, node.args, self.limits.max_ast_nodes))
        for statement in node.body:
            self.visit(statement)
        self.literal_scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        self.literal_scopes.append({})
        self.visit(node.body)
        self.literal_scopes.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self.literal_scopes.append({})
        for statement in node.body:
            self.visit(statement)
        self.literal_scopes.pop()

    def _hashlib_algorithm(self, node: ast.Call) -> None:
        argument = (
            node.args[0]
            if node.args
            else next((keyword.value for keyword in node.keywords if keyword.arg == "name"), None)
        )
        literal: str | None = None
        method = "unresolved-dynamic"
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            literal = argument.value
            method = "literal"
        elif isinstance(argument, ast.Name) and self.literal_scopes:
            writes = self.literal_scopes[-1].get(argument.id, ())
            if len(writes) == 1:
                candidate, assignment = writes[0]
                end_line = getattr(assignment, "end_lineno", None)
                end_column = getattr(assignment, "end_col_offset", None)
                if (
                    candidate is not None
                    and isinstance(assignment, (ast.Assign, ast.AnnAssign))
                    and end_line is not None
                    and end_column is not None
                    and (
                        end_line < argument.lineno
                        or end_line == argument.lineno
                        and end_column <= argument.col_offset
                    )
                ):
                    literal = candidate
                    method = "resolved-literal"
        rule = algorithm_for_name(literal.casefold()) if literal else None
        if rule is not None and rule.family != "hash":
            rule = None
        self.output.append(
            _observation(
                self.source,
                node,
                rule_id=(
                    f"python.algorithm.{rule.canonical_name.replace('-', '_')}"
                    if rule is not None
                    else "python.algorithm.hash.unknown"
                ),
                subject_kind="algorithm",
                subject_value=rule.canonical_name if rule is not None else "unknown",
                confidence=(0.95 if method == "literal" else 0.80) if rule is not None else 0.40,
                policy=self.policy,
                parameters={
                    "detection_method": method if rule is not None else "unresolved-dynamic",
                    "confidence_reason": (
                        "single prior string literal in the same scope"
                        if method == "resolved-literal" and rule is not None
                        else "direct hashlib algorithm literal"
                        if method == "literal" and rule is not None
                        else "hashlib.new call with unresolvable algorithm argument"
                    ),
                    "operation": "hashing",
                },
            )
        )

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
        if full_name in {
            "crypto.cipher.aes.new",
            "crypto.cipher.des.new",
            "crypto.cipher.des3.new",
        }:
            mode_node = node.args[1] if len(node.args) > 1 else keywords.get("mode")
            mode_name = (
                (_attribute_name(mode_node, self.imports) or "").casefold() if mode_node else ""
            )
            mode_prefix = full_name.removesuffix("new") + "mode_"
            if mode_name.startswith(mode_prefix):
                mode = mode_name.removeprefix(mode_prefix)
                if mode in MODE_NAMES:
                    parameters["mode"] = mode.upper()
            if full_name in {"crypto.cipher.des.new", "crypto.cipher.des3.new"}:
                key_node = node.args[0] if node.args else keywords.get("key")
                byte_length: int | None = None
                if isinstance(key_node, ast.Constant) and isinstance(key_node.value, bytes):
                    byte_length = len(key_node.value)
                elif (
                    isinstance(key_node, ast.BinOp)
                    and isinstance(key_node.op, ast.Mult)
                    and isinstance(key_node.left, ast.Constant)
                    and isinstance(key_node.left.value, bytes)
                    and isinstance(key_node.right, ast.Constant)
                    and type(key_node.right.value) is int
                    and key_node.right.value > 0
                ):
                    byte_length = len(key_node.left.value) * key_node.right.value
                if byte_length is not None and 1 <= byte_length * 8 <= 1_000_000:
                    parameters["key_size_bits"] = byte_length * 8
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
        if full_name == "hashlib.new":
            self._hashlib_algorithm(node)
        self._bind_cipher_mode(node, full_name)
        tail = full_name.rsplit(".", 1)[-1]
        matched_name = full_name if algorithm_for_name(full_name) else tail
        tail_components = algorithm_components(tail)
        if tail_components and (
            len(tail_components) > 1 or tail_components[0].key_size_bits is not None
        ):
            matched_name = tail
        rule = algorithm_for_name(matched_name)
        if rule is None:
            rule = next(
                (
                    candidate
                    for segment in reversed(full_name.split("."))
                    if (candidate := algorithm_for_name(segment)) is not None
                    and (matched_name := segment)
                ),
                None,
            )
        if rule and "." in full_name:
            parameters = self._parameters(node, full_name)
            components = algorithm_components(matched_name)
            subject = (
                matched_name
                if len(components) > 1 or (components and components[0].key_size_bits is not None)
                else rule.canonical_name
            )
            self.output.append(
                _observation(
                    self.source,
                    node,
                    rule_id=f"python.algorithm.{rule.canonical_name.replace('-', '_')}",
                    subject_kind="algorithm",
                    subject_value=subject,
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
