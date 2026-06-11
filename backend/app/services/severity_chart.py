"""
Severity-breakdown chart generator for the executive summary.

Produces a horizontal bar chart PNG that the Word template embeds via
{{ severity_chart }} (an InlineImage from docxtpl). Brand colors match
the severity pills used throughout the app.

Pure-stdlib drawing (no matplotlib dependency) so it works in minimal
containers. If you ever want richer charts (pie, trend over versions,
etc.), swap this for matplotlib -- the interface stays the same.
"""
from pathlib import Path
from typing import Optional
import struct
import zlib


SEVERITY_COLORS = {
    "Critical":      (192,   0,   0),   # #C00000
    "High":          (233, 113,  50),   # #E97132
    "Medium":        (255, 192,   0),   # #FFC000
    "Low":           (  0, 176,  80),   # #00B050
    "Informational": ( 68, 114, 196),   # #4472C4
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _png_chunk(typ: bytes, data: bytes) -> bytes:
    chunk = typ + data
    return struct.pack(">I", len(data)) + chunk + struct.pack(">I", zlib.crc32(chunk) & 0xffffffff)


def _write_png(pixels: list[list[tuple[int, int, int]]], path: Path):
    """Write a list-of-rows pixel buffer as a minimal RGB PNG. Pure stdlib."""
    h = len(pixels)
    w = len(pixels[0]) if h else 0
    raw = b""
    for row in pixels:
        raw += b"\x00"  # filter type: None
        for (r, g, b) in row:
            raw += bytes([r, g, b])
    compressed = zlib.compress(raw, 9)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)  # 8-bit RGB
    png = sig + _png_chunk(b"IHDR", ihdr)
    png += _png_chunk(b"IDAT", compressed)
    png += _png_chunk(b"IEND", b"")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(png)


def render_severity_chart(
    counts: dict[str, int],
    out_path: Path,
    width: int = 800,
    height: int = 280,
) -> Path:
    """Render a horizontal bar chart of severity counts and return the path.

    `counts` example: {"Critical": 2, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
    """
    bg = (255, 255, 255)
    fg_text_pseudo = (110, 110, 110)
    pixels = [[bg for _ in range(width)] for _ in range(height)]

    # Layout: left margin for labels, bars stacked vertically
    left_pad = 130
    right_pad = 60
    top_pad = 18
    bottom_pad = 18
    row_h = (height - top_pad - bottom_pad) // len(SEVERITY_ORDER)
    bar_h = max(12, int(row_h * 0.62))
    chart_w = width - left_pad - right_pad

    max_count = max(counts.get(k, 0) for k in SEVERITY_ORDER) or 1

    for i, sev in enumerate(SEVERITY_ORDER):
        n = counts.get(sev, 0)
        # Background gridline
        row_top = top_pad + i * row_h + (row_h - bar_h) // 2
        # Bar
        bar_w = int(chart_w * (n / max_count)) if n > 0 else 0
        color = SEVERITY_COLORS[sev]
        for y in range(row_top, row_top + bar_h):
            for x in range(left_pad, left_pad + bar_w):
                pixels[y][x] = color
        # Label column gets a thin colored block as a swatch (no font drawing)
        swatch_x0 = 14
        swatch_x1 = 28
        swatch_y0 = row_top + (bar_h - 14) // 2
        swatch_y1 = swatch_y0 + 14
        for y in range(swatch_y0, swatch_y1):
            for x in range(swatch_x0, swatch_x1):
                pixels[y][x] = color
        # Light divider line under each row
        for x in range(left_pad, width - right_pad):
            if pixels[row_top + bar_h + 2][x] == bg:
                pixels[row_top + bar_h + 2][x] = (235, 235, 235)

    _write_png(pixels, out_path)
    return out_path


# Why no text rendering?
# Pure-stdlib bitmap PNGs can't easily embed real font glyphs without a
# bundled font + rasterizer (FreeType etc.). For now the chart shows
# proportional colored bars + colored swatches; the Word template adds the
# textual count via the same `severity_counts` dict the chart was built from:
#
#   {% for sev in severities %}
#     {{ sev.name }}: {{ severity_counts[sev.name] }}
#   {% endfor %}
#
# This keeps the chart honest (it's purely visual) and the numbers
# authoritative (they come from the data). If the team wants a fancier
# rendered-text chart later, drop matplotlib into requirements.txt
# and rewrite render_severity_chart() to use it -- public API unchanged.
