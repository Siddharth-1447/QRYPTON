"""Register locally embedded PDF faces from the existing typography token source."""

from __future__ import annotations

import re
from pathlib import Path
from threading import Lock

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from qrypton.api.design_tokens import design_token_source, load_typography_tokens

_registration_lock = Lock()


def register_report_fonts() -> dict[str, str]:
    """Embed the exact vendored faces; never substitute a PDF base font."""
    families = load_typography_tokens()
    css = design_token_source().read_text(encoding="utf-8")
    packaged = Path(__file__).with_name("fonts")
    assets = packaged if packaged.exists() else Path(__file__).parents[3] / "web/public/fonts"
    faces = re.findall(
        r'@font-face\s*\{\s*font-family:\s*"([^"]+)";\s*src:\s*url\("/fonts/([^"/]+)\.woff2"\)[^}]*?font-weight:\s*(\d+);',
        css,
    )
    registered: dict[str, str] = {}
    with _registration_lock:
        for family, filename, weight in faces:
            role = next((name for name, value in families.items() if value == family), None)
            if role is None:
                raise ValueError(f"Unrecognized report font family: {family}")
            name = f"{family}-{weight}"
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, str(assets / f"{filename}.ttf")))
            registered[f"{role}-{weight}"] = name
        for role in ("sans", "mono"):
            regular, bold = registered[f"{role}-400"], registered[f"{role}-700"]
            # Reports use upright text. Mapping avoids synthetic or third-family italics.
            pdfmetrics.registerFontFamily(
                regular, normal=regular, bold=bold, italic=regular, boldItalic=bold
            )
            pdfmetrics.registerFontFamily(
                bold, normal=bold, bold=bold, italic=bold, boldItalic=bold
            )
    return registered
