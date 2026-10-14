"""The PDF renderer consumes the same theme source as the browser."""

from pathlib import Path

from qrypton.api.design_tokens import load_design_tokens


def test_report_palette_resolves_css_aliases_and_tints():
    palette = load_design_tokens()
    assert palette["logo-tail"] == palette["pqc"]
    assert palette["low"] == palette["text-secondary"]
    assert palette["critical-tint"] != palette["critical"]
    assert palette["critical-tint"] != palette["surface"]
    assert palette["safe"] != palette["pqc"]
    assert all(len(value) == 7 and value.startswith("#") for value in palette.values())


def test_renderer_has_no_independent_colour_literals():
    source = Path("src/qrypton/api/reporting.py").read_text(encoding="utf-8")
    assert 'HexColor("#' not in source
    assert "BRAND_GREEN" not in source
