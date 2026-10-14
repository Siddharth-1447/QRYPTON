"""Publication-grade PQC security report engine (reportlab).

Renders a multi-page PDF from persisted scan DTOs: executive PQC briefing,
vector severity/family charts, a severity-coded findings table with
per-finding locations and remediation, and Mosca timeline context.

The two locally hosted application font families are embedded for air-gapped
deployments. ``pageCompression`` stays off so audit tooling can verify
report contents deterministically.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from qrypton.api.design_tokens import load_design_tokens
from qrypton.api.report_fonts import register_report_fonts

SEVERITIES = ("critical", "high", "medium", "low", "informational", "unknown", "unassessed")
TOKENS = load_design_tokens()
FONTS = register_report_fonts()
SEVERITY_TEXT = {
    level: TOKENS[
        {
            "medium": "medium-text",
            "informational": "text-secondary",
            "unknown": "unknown-text",
            "unassessed": "unknown-text",
        }.get(level, level)
    ]
    for level in SEVERITIES
}
SEVERITY_FILL = {level: HexColor(value) for level, value in SEVERITY_TEXT.items()}
PQC = HexColor(TOKENS["pqc"])
INK = HexColor(TOKENS["text-primary"])
MUTED = HexColor(TOKENS["text-muted"])
SURFACE = HexColor(TOKENS["surface"])
SUBTLE = HexColor(TOKENS["surface-subtle"])
BOUNDARY = HexColor(TOKENS["border-strong"])


FAMILY_BUCKETS = (
    ("Asymmetric RSA/ECC", ("rsa", "ecc", "ecdsa", "ecdh", "dsa", "diffie", "ed25519", "x25519")),
    ("Symmetric AES/3DES", ("aes", "des", "3des", "chacha", "camellia")),
    ("Hashing SHA1/SHA2", ("sha", "md5", "sha-1", "sha-256", "sha-384", "sha-512", "blake")),
    ("TLS/Certificates", ("tls", "x509", "certificate", "ssl", "ssh")),
)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _severity_of(item: Any) -> str:
    if _text(getattr(item, "risk_assessment_state", "")) == "unassessed":
        return "unassessed"
    level = _text(getattr(item, "risk_level", ""), "unknown").lower()
    return level if level in SEVERITY_FILL else "unknown"


def _family_bucket(item: Any) -> str:
    family = _text(getattr(item, "algorithm_family", "")).casefold()
    return {
        "asymmetric_encryption": "Asymmetric RSA/ECC",
        "key_agreement": "Asymmetric RSA/ECC",
        "signature": "Asymmetric RSA/ECC",
        "symmetric_cipher": "Symmetric AES/3DES",
        "hash": "Hashing SHA1/SHA2",
        "protocol": "TLS/Certificates",
    }.get(family, "Other")


def _pqc_target(item: Any, roadmap_by_finding: Mapping[str, Any]) -> str:
    finding_id = _text(getattr(item, "finding_id", ""))
    row = roadmap_by_finding.get(finding_id)
    if row is not None:
        action = _text(getattr(row, "action", ""))
        label = _target_label(item, row)
        return f"{label} — {action}" if action else label
    return _target_label(item, None)


def _target_label(item: Any, row: Any) -> str:
    """Render persisted targets or explicitly labelled family-specific review guidance."""
    manual = "Validation / Manual Review Required"
    if item is None or _text(getattr(item, "identity_status", "")) != "identified":
        return manual
    family = _text(getattr(item, "algorithm_family", "")).casefold()
    if family in {"", "unknown"}:
        return manual
    targets = tuple(
        _text(target) for target in (getattr(row, "target_algorithms", ()) or ()) if _text(target)
    )
    if family in {"hash", "symmetric_cipher", "mac", "kdf", "rng"}:
        # Do not reproduce an incompatible historical asymmetric fallback either.
        targets = tuple(
            target
            for target in targets
            if not target.casefold().replace("_", "-").startswith(("ml-kem", "ml-dsa", "slh-dsa"))
        )
    if targets:
        return ", ".join(targets)
    if family == "symmetric_cipher":
        return "AEAD / key length review: AES-256-GCM"
    if family == "hash":
        return "Collision-resistance review: SHA-3 / SHA-512"
    return manual


def _remediation(item: Any, roadmap_by_finding: Mapping[str, Any]) -> str:
    finding_id = _text(getattr(item, "finding_id", ""))
    row = roadmap_by_finding.get(finding_id)
    if row is not None and _text(getattr(row, "action", "")):
        return _text(getattr(row, "action", ""))
    return "Confirm the cryptographic identity and assign a finding-specific migration action."


def _location_of(detail: Any) -> str:
    """Exact code location, binary symbol, layer, or KMS identifier for a finding."""
    if detail is None:
        return "Location not recorded"
    parts: list[str] = []
    for evidence in getattr(detail, "evidence_provenance", ()) or ():
        location = getattr(evidence, "location", None)
        if location is None:
            continue
        path = _text(getattr(location, "relative_path", ""))
        lines = ""
        start, end = getattr(location, "line_start", None), getattr(location, "line_end", None)
        if start:
            lines = f":{start}" + (f"-{end}" if end and end != start else "")
        symbol = _text(getattr(location, "symbol", ""))
        if symbol and symbol not in (path or ""):
            parts.append(f"{path}{lines} (symbol: {symbol})" if path else f"symbol: {symbol}")
        elif path:
            parts.append(f"{path}{lines}")
        else:
            blob = _text(getattr(location, "byte_start", ""))
            if blob:
                parts.append(f"byte offset {blob}")
        if len(parts) >= 2:
            break
    return "; ".join(parts) if parts else "Location not recorded"


def _protocol_summary(detail: Any) -> str:
    finding = getattr(detail, "finding", None) if detail is not None else None
    observation = getattr(finding, "protocol", None)
    protocol = getattr(observation, "value", None) if observation is not None else None
    if protocol is None:
        return "not observed"

    def observed(value: Any) -> str | None:
        state = getattr(value, "state", None)
        state = getattr(state, "value", state)
        if value is None or state != "observed":
            return None
        return _text(getattr(value, "value", None)) or None

    layer = getattr(protocol, "layer", "")
    layer = getattr(layer, "value", layer)

    fields = (
        ("name", observed(getattr(protocol, "name", None))),
        ("version", observed(getattr(protocol, "version", None))),
        ("cipher suite", observed(getattr(protocol, "cipher_suite", None))),
        ("layer", _text(layer) or None),
    )
    rendered = [f"{name} {value}" for name, value in fields if value]
    return "; ".join(rendered) if rendered else "protocol recorded; fields unknown"


def _severity_counts(inventory: Sequence[Any]) -> dict[str, int]:
    counts = {level: 0 for level in SEVERITIES}
    for item in inventory:
        counts[_severity_of(item)] += 1
    return counts


def _severity_pie(counts: Mapping[str, int]) -> Drawing:
    drawing = Drawing(245, 190, initialFontName=FONTS["sans-400"], initialFontSize=9)
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 55, 70, 120, 120
    pie.data = [counts[level] for level in SEVERITIES]
    pie.labels = [f"{level.title()} ({counts[level]})" for level in SEVERITIES]
    pie.slices.strokeWidth = 1
    pie.slices.strokeColor = SURFACE
    pie.slices.fontColor = INK
    pie.simpleLabels = False
    pie.slices.label_boxFillColor = HexColor(TOKENS["canvas"])
    pie.slices.fontName = FONTS["sans-400"]
    pie.slices.fontSize = 9
    for index, level in enumerate(SEVERITIES):
        pie.slices[index].fillColor = SEVERITY_FILL[level]
    drawing.add(pie)
    legend = Legend()
    legend.alignment = "right"
    legend.x, legend.y = 10, 45
    legend.columnMaximum = 4
    legend.deltay = 10
    legend.colorNamePairs = [(SEVERITY_FILL[level], level.title()) for level in SEVERITIES]
    legend.fontName = FONTS["sans-400"]
    legend.fontSize = 9
    legend.fillColor = INK
    drawing.add(legend)
    return drawing


def _family_bars(inventory: Sequence[Any]) -> Drawing:
    buckets = [name for name, _ in FAMILY_BUCKETS] + ["Other"]
    values = [0] * len(buckets)
    for item in inventory:
        values[buckets.index(_family_bucket(item))] += 1
    drawing = Drawing(245, 190, initialFontName=FONTS["sans-400"], initialFontSize=9)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 35, 50, 190, 120
    chart.data = [values]
    chart.categoryAxis.labels.fillColor = INK
    chart.valueAxis.labels.fillColor = MUTED
    chart.categoryAxis.strokeColor = BOUNDARY
    chart.valueAxis.strokeColor = BOUNDARY
    chart.categoryAxis.categoryNames = [name.split(" ")[0] for name in buckets]
    chart.categoryAxis.labels.fontName = FONTS["sans-400"]
    chart.categoryAxis.labels.fontSize = 9
    chart.categoryAxis.labels.angle = 45
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(4, max(values) + 1)
    chart.valueAxis.valueStep = max(1, (max(values) + 1) // 4)
    chart.valueAxis.labels.fontName = FONTS["sans-400"]
    chart.valueAxis.labels.fontSize = 9
    chart.bars[0].fillColor = HexColor(TOKENS["text-secondary"])
    chart.bars[0].strokeColor = BOUNDARY
    drawing.add(chart)
    return drawing


def _risk_bar_chart(counts: Mapping[str, int], total: int) -> Drawing:
    """Horizontal bar chart showing risk % per severity level."""
    buckets = list(SEVERITIES)
    values = [counts[s] for s in buckets]
    pcts = [round(v / total * 100, 1) if total > 0 else 0.0 for v in values]
    drawing = Drawing(260, 130, initialFontName=FONTS["sans-400"], initialFontSize=9)
    chart = HorizontalBarChart()
    chart.x, chart.y, chart.width, chart.height = 60, 10, 180, 110
    chart.data = [pcts]
    chart.categoryAxis.labels.fillColor = INK
    chart.valueAxis.labels.fillColor = MUTED
    chart.categoryAxis.strokeColor = BOUNDARY
    chart.valueAxis.strokeColor = BOUNDARY
    chart.categoryAxis.categoryNames = [s.title() for s in buckets]
    chart.categoryAxis.labels.fontName = FONTS["sans-400"]
    chart.categoryAxis.labels.fontSize = 9
    chart.categoryAxis.labels.textAnchor = "end"
    chart.categoryAxis.labels.dx = -4
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(5.0, max(pcts) + 5.0)
    chart.valueAxis.valueStep = max(5, int((max(pcts) + 5) / 4))
    chart.valueAxis.labels.fontName = FONTS["sans-400"]
    chart.valueAxis.labels.fontSize = 9
    for i, level in enumerate(buckets):
        chart.bars[0, i].fillColor = SEVERITY_FILL[level]
    drawing.add(chart)
    return drawing


class _NumberedCanvas:
    """Draw report branding and generation time on each page."""

    def __init__(self, generated: str) -> None:
        self.generated = generated

    def __call__(self, canvas: Any, document: Any) -> None:
        canvas.saveState()
        # One horizontal lockup, centered as a unit on every report page.
        cx = A4[0] / 2
        font_size = 18
        mark_size = 34
        gap = 3
        word_width = canvas.stringWidth("RYPTON", FONTS["sans-700"], font_size)
        left = cx - (mark_size + gap + word_width) / 2
        top = A4[1] - 15
        scale = mark_size / 24
        canvas.setFillColor(HexColor(TOKENS["canvas"]))
        canvas.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)
        canvas.setStrokeColor(HexColor(TOKENS["logo-frame"]))
        canvas.setFillColor(HexColor(TOKENS["logo-tail"]))
        canvas.setLineWidth(1.3)

        # Q mark uses the same frame and tail geometry as the web Logo component.
        def mark_point(x: float, y: float) -> tuple[float, float]:
            return left + x * scale, top - y * scale

        frame = canvas.beginPath()
        for index, (x, y) in enumerate(
            ((12, 2.5), (20.5, 7.2), (20.5, 15.5), (12, 21), (3.5, 15.5), (3.5, 7.2))
        ):
            px, py = mark_point(x, y)
            if index == 0:
                frame.moveTo(px, py)
            else:
                frame.lineTo(px, py)
        frame.close()
        canvas.setLineWidth(3.6 * scale)
        canvas.setLineJoin(1)
        canvas.drawPath(frame, stroke=1, fill=0)
        tail = canvas.beginPath()
        for index, (x, y) in enumerate(((13, 14.5), (19, 18.5), (19, 23), (13, 19))):
            px, py = mark_point(x, y)
            if index == 0:
                tail.moveTo(px, py)
            else:
                tail.lineTo(px, py)
        tail.close()
        canvas.drawPath(tail, stroke=0, fill=1)
        canvas.setFillColor(INK)
        canvas.setFont(FONTS["sans-700"], font_size)
        canvas.drawString(left + mark_size + gap, top - mark_size / 2 - font_size * 0.35, "RYPTON")
        canvas.setStrokeColor(BOUNDARY)
        canvas.setLineWidth(0.5)
        canvas.line(48, A4[1] - 55, A4[0] - 48, A4[1] - 55)
        canvas.setFont(FONTS["sans-400"], 9)
        canvas.setFillColor(MUTED)
        canvas.drawString(48, 28, f"QRYPTON PQC Assessment Report · Generated {self.generated}")
        canvas.restoreState()


class _PageCountCanvas(Canvas):
    """Write totals before PDF serialization so stream lengths and xrefs stay valid."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if not kwargs.get("initialFontName"):
            kwargs["initialFontName"] = FONTS["sans-400"]
        super().__init__(*args, **kwargs)
        self._page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._page_states)
        for state in self._page_states:
            self.__dict__.update(state)
            self.saveState()
            self.setFont(FONTS["sans-400"], 9)
            self.setFillColor(MUTED)
            self.drawRightString(A4[0] - 48, 28, f"Page {self._pageNumber} of {total}")
            self.restoreState()
            super().showPage()
        super().save()


def _styles() -> dict[str, ParagraphStyle]:
    sheet = getSampleStyleSheet()
    title = ParagraphStyle(
        "QryptonTitle",
        parent=sheet["Title"],
        fontName=FONTS["sans-700"],
        fontSize=22,
        leading=26,
        textColor=INK,
        alignment=TA_LEFT,
        spaceAfter=2,
    )
    subtitle = ParagraphStyle(
        "QryptonSubtitle",
        parent=sheet["Normal"],
        fontName=FONTS["sans-700"],
        fontSize=11,
        leading=14,
        textColor=PQC,
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    heading = ParagraphStyle(
        "QryptonH1",
        parent=sheet["Heading1"],
        fontName=FONTS["sans-700"],
        fontSize=14,
        leading=17,
        textColor=INK,
        spaceBefore=10,
        spaceAfter=6,
    )
    subheading = ParagraphStyle(
        "QryptonH2",
        parent=sheet["Heading2"],
        fontName=FONTS["sans-700"],
        fontSize=11,
        leading=14,
        textColor=INK,
        spaceBefore=8,
        spaceAfter=4,
    )
    body = ParagraphStyle(
        "QryptonBody",
        parent=sheet["Normal"],
        fontName=FONTS["sans-400"],
        fontSize=9,
        leading=13,
        textColor=INK,
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    small = ParagraphStyle("QryptonSmall", parent=body, fontSize=9, leading=13, textColor=MUTED)
    cell = ParagraphStyle("QryptonCell", parent=body, fontSize=9, leading=13)
    technical = ParagraphStyle("QryptonTechnical", parent=cell, fontName=FONTS["mono-400"])
    cell_bold = ParagraphStyle("QryptonCellBold", parent=cell, fontName=FONTS["sans-700"])
    return {
        "title": title,
        "subtitle": subtitle,
        "heading": heading,
        "subheading": subheading,
        "body": body,
        "small": small,
        "cell": cell,
        "technical": technical,
        "cell_bold": cell_bold,
    }


def _escape(value: Any) -> str:
    return _text(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def executive_pdf(
    *,
    scan_id: str,
    run: Any,
    posture: Any,
    inventory: list[Any],
    mosca: list[Any],
    roadmap: list[Any],
    finding_details: Mapping[str, Any] | None = None,
) -> bytes:
    """Render a branded multi-page executive report from safe persisted DTOs."""
    styles = _styles()
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    details = finding_details or {}
    ordered_roadmap = sorted(
        roadmap,
        key=lambda row: (
            -getattr(row, "priority", 0),
            _text(getattr(row, "finding_id", "")),
            _text(getattr(row, "action", "")),
        ),
    )
    roadmap_by_finding: dict[str, Any] = {}
    for row in ordered_roadmap:
        # Several actions can refer to one finding. Retain its most urgent one
        # in the summary table, without suppressing the other roadmap actions.
        roadmap_by_finding.setdefault(_text(getattr(row, "finding_id", "")), row)
    inventory_by_finding = {_text(getattr(item, "finding_id", "")): item for item in inventory}

    asset = getattr(run, "asset", None)
    target_ref = _text(getattr(asset, "external_reference", ""), "Unavailable target")
    asset_kind = _text(getattr(getattr(asset, "kind", None), "value", ""), "unknown")
    counts = _severity_counts(inventory)
    total = sum(counts.values())
    critical_urgent = sum(
        1 for point in mosca if _text(getattr(point, "urgency", "")).lower() == "critical"
    )
    policy_passed = getattr(posture, "policy_passed", None)
    run_status = _text(getattr(posture, "run_status", ""), "COMPLETED")
    unique_assets = getattr(posture, "unique_asset_ids", len(inventory))

    story: list[Any] = []

    # ===== COVER / HEADER =====
    story.append(Paragraph("Cryptographic Security Assessment", styles["title"]))
    story.append(
        Paragraph(
            "DISCOVER. ASSESS. EVOLVE.",
            ParagraphStyle(
                "tagline",
                fontName=FONTS["sans-700"],
                fontSize=9,
                leading=12,
                textColor=INK,
                spaceAfter=2,
            ),
        )
    )
    story.append(Paragraph("Post-Quantum Cryptography Assessment Report", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=PQC, spaceAfter=10))

    # 2-column summary card
    pct_critical = round(counts["critical"] / total * 100, 1) if total > 0 else 0.0
    pct_high = round(counts["high"] / total * 100, 1) if total > 0 else 0.0
    policy_txt = "PASSED" if policy_passed else "VIOLATIONS DETECTED"
    policy_color = TOKENS["safe"] if policy_passed else TOKENS["critical"]
    left_col = [
        Paragraph("<b>Scan Summary</b>", styles["subheading"]),
        Paragraph(f"Scan ID: <b>{_escape(scan_id)}</b>", styles["body"]),
        Paragraph(f"Target: <b>{_escape(target_ref)}</b>", styles["body"]),
        Paragraph(f"Asset type: <b>{_escape(asset_kind)}</b>", styles["body"]),
        Paragraph(f"Generated: {_escape(generated)}", styles["body"]),
        Paragraph(f"Run status: <b>{_escape(run_status)}</b>", styles["body"]),
    ]
    if "sample-data" in getattr(asset, "tags", ()):
        left_col.insert(1, Paragraph("<b>Sample data · Synthetic payment app</b>", styles["body"]))
    right_col = [
        Paragraph("<b>Risk Scorecard</b>", styles["subheading"]),
        Paragraph(
            f"Total findings: <b>{total}</b> across <b>{unique_assets}</b> assets", styles["body"]
        ),
        Paragraph(
            f"Critical: <font color='{TOKENS['critical']}'><b>{counts['critical']}</b></font> "
            f"({pct_critical}%) &amp; "
            f"High: <font color='{TOKENS['high']}'><b>{counts['high']}</b></font> ({pct_high}%)",
            styles["body"],
        ),
        Paragraph(
            f"Medium: <b>{counts['medium']}</b> &amp; Low: <b>{counts['low']}</b>", styles["body"]
        ),
        Paragraph(
            f"Informational: <b>{counts['informational']}</b> &amp; "
            f"Unknown: <b>{counts['unknown']}</b> &amp; "
            f"Unassessed: <b>{counts['unassessed']}</b>",
            styles["body"],
        ),
        Paragraph(f"Mosca critical-urgency: <b>{critical_urgent}</b> findings", styles["body"]),
        Paragraph(
            f"Policy: <font color='{policy_color}'><b>{_escape(policy_txt)}</b></font>",
            styles["body"],
        ),
    ]
    summary_data = [[left_col, right_col]]
    summary_table = Table(summary_data, colWidths=[240, 240])
    summary_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), FONTS["sans-400"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, 0), SUBTLE),
                ("BACKGROUND", (1, 0), (1, 0), SUBTLE),
                ("BOX", (0, 0), (-1, -1), 0.5, BOUNDARY),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BOUNDARY),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # Executive summary paragraph
    if total > 0:
        urgency_word = "immediate" if critical_urgent > 0 else "elevated"
        story.append(
            Paragraph(
                f"This assessment identified <b>{total}</b> cryptographic findings "
                f"across <b>{unique_assets}</b> assets, "
                f"of which <b>{counts['critical']}</b> are critical severity "
                f"({pct_critical}% of total). "
                + (
                    f"<b>{critical_urgent}</b> finding(s) carry critical Mosca quantum urgency, "
                    "indicating "
                    f"migration is required before the quantum computing horizon. "
                    if critical_urgent > 0
                    else ""
                )
                + f"The overall cryptographic posture requires {urgency_word} attention "
                "and a structured PQC migration program aligned with NIST FIPS 203 (ML-KEM), "
                "FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).",
                styles["body"],
            )
        )
    else:
        story.append(
            Paragraph(
                "No cryptographic findings were recorded for this scan. "
                "Verify the scan target and scanner configuration "
                "before concluding the surface is clean.",
                styles["body"],
            )
        )
    story.append(Spacer(1, 8))

    # ---- Section A: executive PQC briefing ----
    story.append(Paragraph("A. Executive PQC Briefing &amp; Relevance", styles["heading"]))
    story.append(
        Paragraph(
            "Post-quantum cryptography (PQC) is urgent today because the migration horizon "
            "is measured in years while adversaries can collect encrypted traffic now. "
            "NIST has standardized ML-KEM (FIPS 203) for key establishment, "
            "ML-DSA (FIPS 204) for digital signatures, and SLH-DSA (FIPS 205) "
            "for stateless hash-based signatures. "
            "Apply these standards to supported public-key roles. "
            "Symmetric ciphers and hashes require separate mode, key-length, and digest review.",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            "The Harvest-Now-Decrypt-Later (HNDL) model assumes attackers record ciphertext "
            "today and decrypt it once a cryptographically relevant quantum computer (CRQC) "
            "exists. Mosca's quantum risk theorem: if X (years data must stay secret) + "
            "Y (years to migrate) exceeds Z (years until CRQC), "
            "the organisation is already exposed.",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            "Legacy sunset timelines reinforce the same conclusion. RSA-2048, ECC P-256/P-384, "
            "finite-field Diffie-Hellman, SHA-1, MD5, and DES/3DES are all in managed decline: "
            "RSA and ECC fall to Shor's algorithm, while SHA-1, MD5, and DES are already "
            "classically broken. AES-128 retains a margin but AES-256 is the recommended "
            "quantum-era baseline.",
            styles["body"],
        )
    )
    if mosca:
        story.append(
            Paragraph(
                f"This scan recorded Mosca timelines for {len(mosca)} finding(s); "
                f"{critical_urgent} carry critical quantum urgency (X + Y beyond Z).",
                styles["body"],
            )
        )
    else:
        story.append(
            Paragraph(
                "Mosca timeline inputs were not recorded for this scan. "
                "Validate data lifetime, migration duration, and "
                "the organisation's CRQC planning horizon before scheduling remediation.",
                styles["body"],
            )
        )

    # ---- Section B: visual charts ----
    story.append(Paragraph("B. Severity Distribution &amp; Algorithm Families", styles["heading"]))
    if total:
        # Side-by-side pie + family bar
        pie_d = _severity_pie(counts)
        bar_d = _family_bars(inventory)
        ct = Table([[pie_d, bar_d]], colWidths=[245, 245])
        ct.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), FONTS["sans-400"]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        story.append(
            Paragraph("Severity pie (left) · Algorithm family bar (right).", styles["small"])
        )
        story.append(ct)
        story.append(Spacer(1, 6))
        # Risk % horizontal bars
        story.append(Paragraph("Risk percentage breakdown by severity.", styles["subheading"]))
        story.append(_risk_bar_chart(counts, total))
        story.append(Spacer(1, 6))
    else:
        story.append(
            Paragraph(
                "No findings recorded; distribution charts omitted.",
                styles["body"],
            )
        )

    # ---- Section C: findings table + details ----
    story.append(Paragraph("C. Risk Breakdown &amp; Comprehensive Findings", styles["heading"]))
    header = [
        "ID",
        "Target Surface",
        "Primitive / Asset",
        "Severity",
        "Mosca Urgency",
        "NIST PQC Migration Target",
    ]
    mosca_by_finding = {_text(getattr(point, "finding_id", "")): point for point in mosca}
    rows: list[list[Any]] = [
        [Paragraph(f"<b>{_escape(cell)}</b>", styles["cell_bold"]) for cell in header]
    ]
    ordered = sorted(
        inventory,
        key=lambda item: (
            SEVERITIES.index(_severity_of(item)),
            _text(getattr(item, "finding_id", "")),
        ),
    )
    for item in ordered:
        finding_id = _text(getattr(item, "finding_id", "unknown"))
        short_id = finding_id[:18] + ("…" if len(finding_id) > 18 else "")
        point = mosca_by_finding.get(finding_id)
        urgency = _text(getattr(point, "urgency", ""), "—") if point is not None else "—"
        primitive = _text(
            getattr(item, "identity_label", ""),
            "No cryptographic identity could be established",
        )
        rows.append(
            [
                Paragraph(_escape(short_id), styles["technical"]),
                Paragraph(_escape(target_ref[:64]), styles["technical"]),
                Paragraph(_escape(primitive[:64]), styles["technical"]),
                Paragraph(
                    _escape(_severity_of(item).title()),
                    ParagraphStyle(
                        "RiskCell",
                        parent=styles["cell"],
                        textColor=SEVERITY_FILL[_severity_of(item)],
                    ),
                ),
                Paragraph(_escape(urgency.title() if urgency != "—" else urgency), styles["cell"]),
                Paragraph(
                    _escape(_pqc_target(item, roadmap_by_finding)[:120]), styles["technical"]
                ),
            ]
        )
    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), SUBTLE),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK),
            ("GRID", (0, 0), (-1, -1), 0.5, BOUNDARY),
            ("FONTNAME", (0, 0), (-1, -1), FONTS["sans-400"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SURFACE, SUBTLE]),
        ]
    )
    for index, item in enumerate(ordered, start=1):
        level = _severity_of(item)
        table_style.add(
            "LINEBEFORE",
            (3, index),
            (3, index),
            2.25,
            SEVERITY_FILL[level],
            1,
            [2, 2] if level in ("unknown", "unassessed") else None,
        )
        table_style.add(
            "BACKGROUND",
            (3, index),
            (3, index),
            HexColor(
                TOKENS[
                    {
                        "informational": "surface-subtle",
                        "unknown": "unknown-tint",
                        "unassessed": "unknown-tint",
                    }.get(_severity_of(item), f"{_severity_of(item)}-tint")
                ]
            ),
        )
        table_style.add("TEXTCOLOR", (3, index), (3, index), SEVERITY_FILL[_severity_of(item)])
    findings_table = Table(rows, colWidths=[62, 92, 90, 60, 58, 130], repeatRows=1)
    findings_table.setStyle(table_style)
    story.append(findings_table)
    story.append(Spacer(1, 8))

    story.append(
        Paragraph("Finding details, evidence locations, and remediation", styles["subheading"])
    )
    if not ordered:
        story.append(Paragraph("No findings to detail for this scan.", styles["body"]))
    for item in ordered:
        finding_id = _text(getattr(item, "finding_id", "unknown"))
        severity = _severity_of(item)
        algorithm = _text(
            getattr(item, "identity_label", ""),
            "No cryptographic identity could be established",
        )
        key_size = getattr(item, "key_size_bits", None)
        location = _location_of(details.get(finding_id))
        point = mosca_by_finding.get(finding_id)
        timeline = (
            f"X={getattr(point, 'x_data_lifetime_years', 'n/a')}y + "
            f"Y={getattr(point, 'y_migration_years', 'n/a')}y "
            f"vs Z={getattr(point, 'z_crqc_horizon_years', 'n/a')}y — "
            f"urgency {_text(getattr(point, 'urgency', 'unavailable'))}."
            if point is not None
            else "No Mosca timeline recorded."
        )
        # Risk factor breakdown
        detail = details.get(finding_id)
        assessment = getattr(detail, "assessment", None) if detail else None
        factors = getattr(assessment, "factors", None) if assessment else None
        risk_factor_line = ""
        if factors is not None:

            def _fv(f: Any, attr: str) -> str:
                obj = getattr(f, attr, None)
                v = getattr(obj, "value", None) if obj else None
                return f"{v:.2f}" if isinstance(v, float) else "n/a"

            risk_factor_line = (
                f"Risk factors — "
                f"Crypto Obsolescence: {_fv(factors, 'cryptographic_obsolescence')} | "
                f"Quantum Exposure: {_fv(factors, 'quantum_exposure')} | "
                f"Exploitability: {_fv(factors, 'exploitability')} | "
                f"Business Impact: {_fv(factors, 'business_impact')}"
            )
        block: list[Any] = [
            Paragraph(
                f'<b><font color="{SEVERITY_TEXT[severity]}">[{severity.upper()}]</font> '
                f'<font name="{FONTS["mono-700"]}">{_escape(algorithm)} — '
                f"{_escape(finding_id)}</font></b>",
                styles["body"],
            ),
            Paragraph(
                "Identity state: "
                f"{_escape(_text(getattr(item, 'identity_status', ''), 'unknown'))}; "
                f"family: {_escape(_text(getattr(item, 'algorithm_family', ''), 'unknown'))}; "
                f"variant: {_escape(_text(getattr(item, 'algorithm_variant', ''), 'unknown'))}; "
                f"role: {_escape(_text(getattr(item, 'crypto_role', ''), 'unknown'))}; "
                f"library: {_escape(_text(getattr(item, 'library_name', ''), 'unknown'))}.",
                styles["body"],
            ),
            Paragraph(
                "Technical detail: key size "
                f"{_escape(str(key_size)) if key_size else 'not observed'}; "
                f"category {_escape(_text(getattr(item, 'category', ''), 'unknown'))}; "
                f"confidence {_escape(str(getattr(item, 'confidence', '')))}.",
                styles["body"],
            ),
            Paragraph(
                "Protocol observation: " + _escape(_protocol_summary(detail)) + ".",
                styles["body"],
            ),
            Paragraph(
                f'Evidence location: <font name="{FONTS["mono-400"]}">{_escape(location)}</font>.',
                styles["body"],
            ),
            Paragraph(f"Mosca timeline: {_escape(timeline)}", styles["body"]),
        ]
        if risk_factor_line:
            block.append(Paragraph(f"<i>{_escape(risk_factor_line)}</i>", styles["small"]))
        block.append(
            Paragraph(
                f"Remediation: {_escape(_remediation(item, roadmap_by_finding))}", styles["body"]
            )
        )
        story.append(KeepTogether(block))
        story.append(Spacer(1, 4))

    # ---- Roadmap tail ----
    story.append(Paragraph("NIST PQC Migration Roadmap", styles["heading"]))
    if roadmap:
        for row in ordered_roadmap[:40]:
            targets = _target_label(
                inventory_by_finding.get(_text(getattr(row, "finding_id", ""))), row
            )
            story.append(
                Paragraph(
                    f"Priority {_escape(str(getattr(row, 'priority', '-')))}: "
                    f"{_escape(str(getattr(row, 'action', 'Review cryptographic role')))} "
                    f"(target: {_escape(targets)}).",
                    styles["body"],
                )
            )
        if len(ordered_roadmap) > 40:
            story.append(
                Paragraph(
                    "Showing the 40 highest-priority actions; "
                    f"{len(ordered_roadmap) - 40} additional "
                    "actions are available in the scan roadmap.",
                    styles["small"],
                )
            )
    else:
        story.append(
            Paragraph(
                "Validation / Manual Review Required. "
                "No finding-specific migration actions were recorded.",
                styles["body"],
            )
        )

    footer = _NumberedCanvas(generated)
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=48,
        rightMargin=48,
        topMargin=76,
        bottomMargin=48,
        title="QRYPTON PQC Assessment Report",
        author="QRYPTON",
        pageCompression=0,
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer, canvasmaker=_PageCountCanvas)
    return buffer.getvalue()
