"""Dependency-free executive PDF rendering for persisted QRYPTON scans.

The renderer deliberately uses a small, deterministic PDF writer: reports remain
available in air-gapped deployments where a browser or native PDF stack is absent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def _pdf_text(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _lines(value: str, width: int = 92) -> list[str]:
    words = value.split()
    output: list[str] = []
    line = ""
    for word in words:
        if len(line) + len(word) + 1 > width and line:
            output.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    return output + ([line] if line else [])


def executive_pdf(*, scan_id: str, run: Any, posture: Any, inventory: list[Any], mosca: list[Any], roadmap: list[Any]) -> bytes:
    """Render a branded multi-page executive report from safe persisted DTOs."""
    pages: list[list[str]] = [[]]
    y = 748

    def command(value: str) -> None:
        pages[-1].append(value)

    def text(value: object, *, size: int = 9, x: int = 48, colour: str = "0.10 0.14 0.20") -> None:
        nonlocal y
        if y < 62:
            pages.append([])
            y = 748
        command(f"BT /F1 {size} Tf {colour} rg {x} {y} Td ({_pdf_text(value)}) Tj ET")
        y -= size + 5

    def heading(value: str) -> None:
        nonlocal y
        y -= 8
        text(value, size=15, colour="0.00 0.55 0.34")
        command(f"0.00 0.90 0.53 rg 48 {y + 3} 500 1 re f")
        y -= 7

    def paragraph(value: str) -> None:
        nonlocal y
        for item in _lines(value):
            text(item)
        # A little visual separation without relying on a layout library.
        y -= 3

    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    target = getattr(getattr(run, "asset", None), "external_reference", "Unavailable target")
    target_kind = getattr(getattr(getattr(run, "target", None), "kind", None), "value", "unknown")

    command("0.04 0.06 0.10 rg 0 0 612 792 re f")
    command("0.00 1.00 0.53 rg 0 694 612 98 re f")
    command("BT /F1 25 Tf 0.04 0.06 0.10 rg 48 748 Td (QRYPTON) Tj ET")
    command("BT /F1 13 Tf 0.04 0.06 0.10 rg 48 720 Td (CRYPTO-DISCOVERY & POST-QUANTUM RISK ASSESSMENT REPORT) Tj ET")
    y = 660
    text(f"Scan ID: {scan_id}", size=11, colour="0.90 0.94 0.98")
    text(f"Generated: {generated}", colour="0.75 0.82 0.89")
    heading("Executive Summary")
    text(f"Target Type: {target_kind}", colour="0.90 0.94 0.98")
    text(f"Target: {target}", colour="0.90 0.94 0.98")
    text(f"Cryptographic assets discovered: {getattr(posture, 'total_findings', 0)}", colour="0.90 0.94 0.98")
    text(f"Overall risk score: {min(100, getattr(posture, 'critical_findings_count', 0) * 25 + getattr(posture, 'high_findings_count', 0) * 12 + getattr(posture, 'medium_findings_count', 0) * 5)} / 100", colour="0.90 0.94 0.98")
    heading("Risk Distribution")
    counts = [("Critical", getattr(posture, "critical_findings_count", 0), "0.93 0.25 0.25"), ("High", getattr(posture, "high_findings_count", 0), "0.96 0.55 0.12"), ("Medium", getattr(posture, "medium_findings_count", 0), "0.95 0.78 0.18"), ("Low", getattr(posture, "low_findings_count", 0), "0.15 0.68 0.42")]
    for label, count, colour in counts:
        text(f"{label}: {count}", colour="0.90 0.94 0.98")
        command(f"{colour} rg 150 {y + 8} {min(320, int(count) * 22)} 8 re f")
    heading("Business Context & Mosca Assessment")
    if mosca:
        for point in mosca[:8]:
            paragraph(f"{getattr(point, 'finding_id', 'finding')}: X data lifetime {getattr(point, 'x_data_lifetime_years', 'n/a')}y + Y migration {getattr(point, 'y_migration_years', 'n/a')}y vs Z quantum horizon {getattr(point, 'z_crqc_horizon_years', 'n/a')}y — urgency {getattr(point, 'urgency', 'unavailable')}.")
    else:
        paragraph("Mosca timeline inputs were not recorded for this scan. Validate data lifetime, migration duration, and the organization’s CRQC planning horizon before scheduling remediation.")
    heading("Critical Findings & Plain-English Explanations")
    critical = [item for item in inventory if getattr(item, "risk_level", "") in {"critical", "high"}]
    if not critical:
        paragraph("No high or critical findings were recorded. Continue inventory validation and use the roadmap to maintain crypto agility.")
    for item in critical[:25]:
        algorithm = getattr(item, "algorithm_name", None) or "Unclassified cryptographic asset"
        detail = f"Technical detail: {algorithm}; key size {getattr(item, 'key_size_bits', None) or 'not observed'}; finding ID {getattr(item, 'finding_id', 'unknown')}."
        plain = "Why it matters: an attacker may capture protected information now and use future quantum capability to defeat vulnerable public-key cryptography, so replacement planning must start before the data’s required confidentiality period ends."
        paragraph(detail)
        paragraph(plain)
    heading("Cryptographic Asset Inventory")
    text("Algorithm | Key size | Primitive / category | Risk", size=8, colour="0.00 0.55 0.34")
    for item in inventory[:80]:
        text(f"{getattr(item, 'algorithm_name', None) or 'Unknown'} | {getattr(item, 'key_size_bits', None) or '-'} | {getattr(item, 'algorithm_family', None) or getattr(item, 'category', 'unknown')} | {getattr(item, 'risk_level', 'unknown')}", size=8)
    heading("NIST PQC Migration Roadmap")
    if roadmap:
        for item in roadmap[:30]:
            paragraph(f"Priority {getattr(item, 'priority', '-')}: {getattr(item, 'action', 'Review cryptographic role')}. Target: {', '.join(getattr(item, 'target_algorithms', ()) or ('ML-KEM (FIPS 203) or ML-DSA (FIPS 204)',))}.")
    else:
        paragraph("1. Inventory cryptographic dependencies and owners. 2. Replace RSA/ECDH key establishment with ML-KEM (FIPS 203), using hybrid deployment while interoperability requires it. 3. Replace vulnerable signatures with ML-DSA (FIPS 204). 4. Re-test protocol, certificate, HSM, and partner compatibility before rollout.")

    objects: list[bytes] = [b"<< /Type /Catalog /Pages 2 0 R >>", b""]
    page_refs: list[int] = []
    for index, content in enumerate(pages):
        stream = "\n".join(content).encode("latin-1", "replace")
        content_id = len(objects) + 1
        page_id = content_id + 1
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {len(pages) * 2 + 3} 0 R >> >> /Contents {content_id} 0 R >>".encode())
        page_refs.append(page_id)
    objects[1] = f"<< /Type /Pages /Count {len(page_refs)} /Kids [{' '.join(f'{item} 0 R' for item in page_refs)}] >>".encode()
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output)); output.extend(f"{index} 0 obj\n".encode()); output.extend(obj); output.extend(b"\nendobj\n")
    xref = len(output); output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    output.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:]))
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)
