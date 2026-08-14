"""Draw the Huginn icon.

Odin's raven over a night sky, inside a thin ring — the same mark the
console header carries, so the desktop icon and the front page are visibly
the same product.

It replaced a shield-and-heartbeat badge on 2026-07-27, and not only for
the rename. **A shield was the wrong promise.** Huginn detects and
proposes; blocking is deliberately unbuilt and AST-enforced. An icon
showing a shield told the operator, every time they glanced at the dock,
that something was being stopped. Nothing is. A raven that flies out,
sees, and comes back to report is what actually happens.

The raven is the SVG geometry from console/console.html, sampled into
polygons here rather than re-drawn, so the two can never drift apart.
Drawn at 4x and downsampled, so edges stay clean at 32px.

Run from packaging/desktop/:  python3 make_icon.py
"""
import math

from PIL import Image, ImageDraw, ImageFilter

S = 4096                      # supersampled master

NIGHT_TOP = (14, 22, 42)
NIGHT_BOT = (6, 9, 18)
FEATHER = (232, 238, 252)     # --fg
ACCENT = (122, 162, 247)      # --accent
FROST = (79, 214, 190)        # --frost

# --- the raven, in console.html's 150x96 viewBox --------------------------
# Keep these numbers identical to the <svg> in the console.
TAIL = [(66, 58), (14, 66), (66, 74)]
BEAK = [(116, 46), (144, 52), (116, 57)]
HEAD = (111, 50, 9)                                   # cx, cy, r
BODY = (86, 58, 27, 11, -8)                           # cx, cy, rx, ry, deg
WING_NEAR = ((88, 52), (80, 18), (46, 8), (54, 42))   # Q ctrl tip, Q ctrl back
WING_FAR = ((78, 60), (61, 31), (28, 30), (45, 59))

VB_W, VB_H = 150, 96
RAVEN_BOX = (14, 8, 144, 74)                          # what actually gets inked


def quad(p0, p1, p2, steps=72):
    """Sample a quadratic bezier — PIL has no curves, so we hand it points."""
    out = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        out.append((u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
                    u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1]))
    return out


def wing(spec):
    """A wing is a lens: out along one curve, back along the other."""
    root, c_out, tip, c_back = spec
    return quad(root, c_out, tip) + quad(tip, c_back, root)


def ellipse_points(cx, cy, rx, ry, deg, steps=96):
    rad = math.radians(deg)
    cos_r, sin_r = math.cos(rad), math.sin(rad)
    pts = []
    for i in range(steps):
        a = 2 * math.pi * i / steps
        x, y = rx * math.cos(a), ry * math.sin(a)
        pts.append((cx + x * cos_r - y * sin_r, cy + x * sin_r + y * cos_r))
    return pts


# Fit the raven into the badge: scale by its inked box, not the viewBox, so
# the empty margins in the viewBox do not shrink the bird.
_SPAN = max(RAVEN_BOX[2] - RAVEN_BOX[0], RAVEN_BOX[3] - RAVEN_BOX[1])
SCALE = S * 0.56 / _SPAN
OX = S / 2 - ((RAVEN_BOX[0] + RAVEN_BOX[2]) / 2) * SCALE
OY = S / 2 - ((RAVEN_BOX[1] + RAVEN_BOX[3]) / 2) * SCALE


def T(pts):
    return [(OX + x * SCALE, OY + y * SCALE) for x, y in pts]


img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# --- rounded-square badge with a night gradient ---------------------------
pad = S // 32
radius = S // 5
grad = Image.new("RGBA", (S, S), (0, 0, 0, 0))
gd = ImageDraw.Draw(grad)
for y in range(S):
    t = y / S
    col = tuple(int(a + (b - a) * t) for a, b in zip(NIGHT_TOP, NIGHT_BOT))
    gd.line([(0, y), (S, y)], fill=col + (255,))
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle(
    [pad, pad, S - pad, S - pad], radius=radius, fill=255)
img.paste(grad, (0, 0), mask)

# --- aurora wash, matching the console's sky ------------------------------
aurora = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ad = ImageDraw.Draw(aurora)
ad.ellipse([S * 0.02, -S * 0.22, S * 0.62, S * 0.34], fill=FROST + (46,))
ad.ellipse([S * 0.42, -S * 0.26, S * 1.02, S * 0.30], fill=ACCENT + (58,))
aurora = aurora.filter(ImageFilter.GaussianBlur(S // 14))
img.alpha_composite(Image.composite(
    aurora, Image.new("RGBA", (S, S), (0, 0, 0, 0)), mask))

# --- stars ----------------------------------------------------------------
stars = Image.new("RGBA", (S, S), (0, 0, 0, 0))
sd = ImageDraw.Draw(stars)
for fx, fy, fr, alpha in (
    (0.13, 0.16, 0.0055, 210), (0.26, 0.09, 0.0040, 150), (0.38, 0.20, 0.0048, 180),
    (0.19, 0.31, 0.0034, 130), (0.62, 0.12, 0.0058, 225), (0.75, 0.22, 0.0040, 160),
    (0.86, 0.14, 0.0046, 190), (0.55, 0.28, 0.0032, 120), (0.09, 0.52, 0.0038, 140),
    (0.90, 0.44, 0.0044, 170), (0.16, 0.76, 0.0036, 130), (0.30, 0.87, 0.0042, 155),
    (0.71, 0.83, 0.0038, 140), (0.84, 0.70, 0.0050, 185), (0.47, 0.91, 0.0034, 125),
):
    cx, cy, r = fx * S, fy * S, fr * S
    sd.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, alpha))
img.alpha_composite(Image.composite(
    stars, Image.new("RGBA", (S, S), (0, 0, 0, 0)), mask))

# --- ring -----------------------------------------------------------------
ring_r = S * 0.345
d.ellipse([S / 2 - ring_r, S / 2 - ring_r, S / 2 + ring_r, S / 2 + ring_r],
          outline=ACCENT + (255,), width=S // 64)

# --- the raven ------------------------------------------------------------
# A soft glow first, so the silhouette lifts off the sky at small sizes.
glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
gdraw = ImageDraw.Draw(glow)
for pts in (T(TAIL), T(wing(WING_FAR)), T(ellipse_points(*BODY)),
            T(wing(WING_NEAR)), T(BEAK)):
    gdraw.polygon(pts, fill=ACCENT + (150,))
hx, hy, hr = HEAD
hc = T([(hx, hy)])[0]
hrs = hr * SCALE
gdraw.ellipse([hc[0] - hrs, hc[1] - hrs, hc[0] + hrs, hc[1] + hrs],
              fill=ACCENT + (150,))
img.alpha_composite(glow.filter(ImageFilter.GaussianBlur(S // 46)))

for pts in (T(TAIL), T(wing(WING_FAR)), T(ellipse_points(*BODY)),
            T(wing(WING_NEAR)), T(BEAK)):
    d.polygon(pts, fill=FEATHER + (255,))
d.ellipse([hc[0] - hrs, hc[1] - hrs, hc[0] + hrs, hc[1] + hrs],
          fill=FEATHER + (255,))

# subtle inner edge light on the badge, drawn last so it sits on top
d.rounded_rectangle([pad, pad, S - pad, S - pad], radius=radius,
                    outline=(255, 255, 255, 26), width=S // 160)

# --- export ---------------------------------------------------------------
sizes = (512, 256, 128, 64, 48, 32)
for size in sizes:
    img.resize((size, size), Image.LANCZOS).save(f"icons/huginn-{size}.png")
img.resize((512, 512), Image.LANCZOS).save("icons/huginn.png")
img.resize((256, 256), Image.LANCZOS).save(
    "icons/huginn.ico",
    sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
print("written:", sizes, "+ .ico")
