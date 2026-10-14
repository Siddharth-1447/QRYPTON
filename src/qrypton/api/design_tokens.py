"""Resolve PDF colours from the app's single CSS token source."""

from __future__ import annotations

import re
from pathlib import Path


def design_token_source() -> Path:
    """Use the packaged source in wheels, or the original source in a checkout."""
    packaged = Path(__file__).with_name("globals.css")
    return packaged if packaged.exists() else Path(__file__).parents[3] / "web/src/app/globals.css"


def load_typography_tokens() -> dict[str, str]:
    """Return the two font roles and local face assets declared in the CSS source."""
    css = design_token_source().read_text(encoding="utf-8")
    roles = dict(re.findall(r'--font-(sans|mono):\s*"([^"]+)"', css))
    if set(roles) != {"sans", "mono"}:
        raise ValueError("Exactly two typography roles must be defined")
    return roles


def load_design_tokens() -> dict[str, str]:
    """Resolve colour aliases and tints for PDF exports."""
    css = design_token_source().read_text(encoding="utf-8")
    blocks = [
        re.search(r":root \{([\s\S]*?)\n\}", css),
        re.search(r':root\[data-resolved-theme="dark"\] \{([\s\S]*?)\n\}', css),
    ]
    if any(block is None for block in blocks):
        raise ValueError("Missing application theme token blocks")
    tokens = dict(
        re.findall(
            r"--([\w-]+):\s*([^;]+);",
            "\n".join(block.group(1) for block in blocks if block is not None),
        )
    )

    def resolve(name: str, visiting: frozenset[str] = frozenset()) -> str:
        if name in visiting:
            raise ValueError(f"Cyclic colour token: {name}")
        value = tokens[name].strip()
        if re.fullmatch(r"#[\da-fA-F]{6}", value):
            return value
        seen = visiting | {name}
        alias = re.fullmatch(r"var\(--([\w-]+)\)", value)
        if alias:
            return resolve(alias[1], seen)
        mix = re.fullmatch(
            r"color-mix\(in srgb, var\(--([\w-]+)\) (\d+)%, var\(--([\w-]+)\)\)", value
        )
        if mix:
            foreground, background = resolve(mix[1], seen), resolve(mix[3], seen)
            proportion = int(mix[2]) / 100
            channels = [
                round(
                    int(foreground[i : i + 2], 16) * proportion
                    + int(background[i : i + 2], 16) * (1 - proportion)
                )
                for i in (1, 3, 5)
            ]
            return "#" + "".join(f"{channel:02x}" for channel in channels)
        raise ValueError(f"Unsupported colour token: {name}")

    names = (
        "canvas",
        "surface",
        "surface-subtle",
        "border",
        "border-strong",
        "text-primary",
        "text-secondary",
        "text-muted",
        "pqc",
        "pqc-tint",
        "logo-frame",
        "logo-tail",
        "critical",
        "high",
        "medium-text",
        "low",
        "safe",
        "unknown-text",
        "critical-tint",
        "high-tint",
        "medium-tint",
        "low-tint",
        "safe-tint",
        "unknown-tint",
        "heatmap-0",
        "heatmap-1",
        "heatmap-2",
        "heatmap-3",
        "heatmap-4",
    )
    return {name: resolve(name) for name in names}
