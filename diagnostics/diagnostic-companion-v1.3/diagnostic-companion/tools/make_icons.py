#!/usr/bin/env python3
"""Generate the Windows .ico and PNG icons (spec §20).

    python3 tools/make_icons.py

Drawn programmatically rather than rasterised from the SVG, for two
reasons:

* **No rasteriser dependency.** Converting SVG to ICO needs cairosvg,
  rsvg-convert or Inkscape, none of which are reasonable to require
  just to build an icon. Pillow is already a light dependency.
* **Small sizes need different geometry, not scaling.** A 16x16 icon
  produced by shrinking a 256x256 one is mush. Below 32px this draws a
  deliberately simpler shape — no inner ring, thicker tick — because
  detail that cannot be seen is just noise that blurs what can.

The design matches launchers/icons/diag-icon.svg: a drive platter with a health
tick, chosen to be unmistakable next to a network-themed diagnostic
icon on the same desktop.
"""

import os
import sys

from PIL import Image, ImageDraw

BG_OUTER = (26, 33, 44, 255)
BG_INNER = (47, 58, 74, 255)
ACCENT = (74, 144, 217, 255)
TICK = (62, 207, 142, 255)

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)


def draw_icon(size):
    """Render at `size`, simplifying below 32px where detail turns to mush."""
    # Supersample for smooth curves, then downsample once at the end.
    scale = 4 if size >= 32 else 8
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    detailed = size >= 32

    # Rounded background panel.
    margin = s * 0.05
    radius = s * 0.19
    d.rounded_rectangle([margin, margin, s - margin, s - margin],
                        radius=radius, fill=BG_INNER,
                        outline=ACCENT, width=max(1, int(s * 0.030)))

    # Drive platter.
    cx, cy = s / 2, s * 0.47
    outer_r = s * 0.27
    ring_w = max(1, int(s * 0.038))
    d.ellipse([cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r],
              outline=ACCENT, width=ring_w)

    if detailed:
        inner_r = outer_r * 0.58
        d.ellipse([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r],
                  outline=(74, 144, 217, 150), width=max(1, int(s * 0.022)))

    hub_r = s * 0.047
    d.ellipse([cx - hub_r, cy - hub_r, cx + hub_r, cy + hub_r], fill=ACCENT)

    # Health tick. Thicker and wider at small sizes so it survives.
    tick_w = max(2, int(s * (0.075 if detailed else 0.105)))
    spread = 1.0 if detailed else 1.18
    d.line([(cx - 0.145 * s * spread, cy + 0.015 * s),
            (cx - 0.035 * s * spread, cy + 0.115 * s),
            (cx + 0.150 * s * spread, cy - 0.105 * s)],
           fill=TICK, width=tick_w, joint="curve")
    # Round the tick's ends; Pillow's line joints leave them square.
    for point in ((cx - 0.145 * s * spread, cy + 0.015 * s),
                  (cx + 0.150 * s * spread, cy - 0.105 * s)):
        r = tick_w / 2
        d.ellipse([point[0] - r, point[1] - r, point[0] + r, point[1] + r], fill=TICK)

    if detailed:
        # Stand, hinting at a machine rather than a bare disk.
        bar_w, bar_h = s * 0.36, s * 0.055
        by = s * 0.845
        d.rounded_rectangle([cx - bar_w / 2, by, cx + bar_w / 2, by + bar_h],
                            radius=bar_h / 2, fill=(74, 144, 217, 200))

    return img.resize((size, size), Image.LANCZOS)


def main():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    usb = os.path.join(here, "launchers", "icons")
    os.makedirs(usb, exist_ok=True)

    frames = [draw_icon(n) for n in ICO_SIZES]

    ico = os.path.join(usb, "diag-icon.ico")
    frames[-1].save(ico, format="ICO",
                    sizes=[(n, n) for n in ICO_SIZES])
    os.chmod(ico, 0o644)
    print(f"wrote {ico} ({os.path.getsize(ico):,} bytes, "
          f"{len(ICO_SIZES)} sizes: {', '.join(str(n) for n in ICO_SIZES)})")

    png = os.path.join(usb, "diag-icon.png")
    draw_icon(256).save(png, format="PNG")
    os.chmod(png, 0o644)
    print(f"wrote {png} ({os.path.getsize(png):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
