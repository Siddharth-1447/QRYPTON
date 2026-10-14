"""PDF typography stays synchronized with the browser token source."""

import re

from reportlab.pdfbase import pdfmetrics

from qrypton.api.design_tokens import load_typography_tokens
from qrypton.api.report_fonts import register_report_fonts
from qrypton.api.reporting import executive_pdf
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.api.test_report_pdf import _report_fixture


def test_report_fonts_use_exactly_two_token_families_and_real_weights():
    families = load_typography_tokens()
    fonts = register_report_fonts()
    assert set(families) == {"sans", "mono"}
    assert set(fonts) == {"sans-400", "sans-500", "sans-700", "mono-400", "mono-700"}
    for role, name in fonts.items():
        assert name.startswith(families[role.split("-")[0]])
        assert pdfmetrics.getFont(name).face.charWidths


def test_pdf_font_registration_is_idempotent():
    first = register_report_fonts()
    fonts = {key: pdfmetrics.getFont(value) for key, value in first.items()}
    assert register_report_fonts() == first
    assert all(pdfmetrics.getFont(first[key]) is font for key, font in fonts.items())


def test_pdf_embeds_only_the_two_local_font_families():
    run = _report_fixture()
    view = SqliteDashboardDataProvider.run_view_from_result(run)
    pdf = executive_pdf(
        scan_id=run.run_id,
        run=run,
        posture=view.posture,
        inventory=list(view.inventory),
        mosca=[],
        roadmap=list(view.roadmap),
    )
    names = set(re.findall(rb"/BaseFont\s+/(\S+)", pdf))
    assert names
    assert all(b"SpaceGrotesk" in name or b"SpaceMono" in name for name in names)
