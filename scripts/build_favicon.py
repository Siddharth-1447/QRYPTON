"""Render the Q mark as a favicon from the shared logo color tokens."""

import re
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "web" / "src" / "app" / "globals.css"
FAVICON = ROOT / "web" / "src" / "app" / "favicon.ico"


def token_color(css: str, name: str) -> str:
    root = css.split(":root {", 1)[1].split("\n}", 1)[0]
    match = re.search(rf"--{re.escape(name)}:\s*(#[0-9A-Fa-f]{{6}});", root)
    if match is None:
        raise ValueError(f"Missing six-digit {name} token")
    return match.group(1)


def render() -> None:
    css = CSS.read_text(encoding="utf-8")
    frame = token_color(css, "logo-frame")
    tail = token_color(css, "logo-tail")
    scale = 48
    size = 24 * scale
    image = Image.new("RGBA", (size, size))
    pen = ImageDraw.Draw(image)
    outline = [(12, 2.5), (20.5, 7.2), (20.5, 15.5), (12, 21), (3.5, 15.5), (3.5, 7.2), (12, 2.5)]
    pen.line(
        [(round(x * scale), round(y * scale)) for x, y in outline],
        fill=frame,
        width=round(3.6 * scale),
        joint="curve",
    )
    radius = round(1.8 * scale)
    for x, y in outline[:-1]:
        cx, cy = round(x * scale), round(y * scale)
        pen.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), fill=frame)
    tail_points = [(13, 14.5), (19, 18.5), (19, 23), (13, 19)]
    pen.polygon([(round(x * scale), round(y * scale)) for x, y in tail_points], fill=tail)
    image.save(
        FAVICON,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


if __name__ == "__main__":
    render()
