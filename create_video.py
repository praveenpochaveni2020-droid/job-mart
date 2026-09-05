import os
import math
import random
import subprocess

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFilter

from rembg import remove


# ============================================================
# SETTINGS
# ============================================================

STREET_PATH = "input/street.jpg"
GANESHA_PATH = "input/ganesha.jpg"

OUTPUT_DIR = "frames"
OUTPUT_VIDEO = "ganesh_pandal.mp4"

FPS = 24
DURATION = 15
TOTAL_FRAMES = FPS * DURATION

random.seed(2026)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# LOAD STREET IMAGE
# ============================================================

street = Image.open(STREET_PATH).convert("RGB")

W, H = street.size

# Keep reasonable output resolution
MAX_WIDTH = 1080

if W > MAX_WIDTH:
    new_h = int(H * MAX_WIDTH / W)
    street = street.resize((MAX_WIDTH, new_h), Image.LANCZOS)

W, H = street.size

print("Video resolution:", W, H)


# ============================================================
# LOAD GANESHA
# ============================================================

print("Preparing Ganesha image...")

ganesha_original = Image.open(GANESHA_PATH).convert("RGBA")

# Remove background automatically
try:
    ganesha = remove(ganesha_original)
except Exception as e:
    print("Background removal failed:", e)
    ganesha = ganesha_original

# Resize idol
target_height = int(H * 0.55)

ratio = target_height / ganesha.height

new_width = int(ganesha.width * ratio)

ganesha = ganesha.resize(
    (new_width, target_height),
    Image.LANCZOS
)


# ============================================================
# HELPERS
# ============================================================

def ease_out(x):
    x = max(0.0, min(1.0, x))
    return 1 - (1 - x) ** 3


def ease_in_out(x):
    x = max(0.0, min(1.0, x))
    return x * x * (3 - 2 * x)


def draw_glow(base, x, y, radius=30, alpha=120):
    glow = Image.new("RGBA", base.size, (0, 0, 0, 0))

    gd = ImageDraw.Draw(glow)

    for r in range(radius, 2, -3):
        a = int(alpha * (1 - r / radius) ** 2)

        gd.ellipse(
            (x-r, y-r, x+r, y+r),
            fill=(255, 210, 80, a)
        )

    glow = glow.filter(ImageFilter.GaussianBlur(5))

    base.alpha_composite(glow)


def draw_bamboo_line(draw, p1, p2, width=14, progress=1.0):
    x1, y1 = p1
    x2, y2 = p2

    ex = x1 + (x2 - x1) * progress
    ey = y1 + (y2 - y1) * progress

    draw.line(
        (x1, y1, ex, ey),
        fill=(108, 73, 34, 255),
        width=width
    )

    # Bamboo joints
    if progress > 0.15:
        dx = ex - x1
        dy = ey - y1
        length = math.sqrt(dx*dx + dy*dy)

        if length > 30:
            count = max(1, int(length / 80))

            for i in range(1, count + 1):

                t = i / (count + 1)

                xx = x1 + dx * t
                yy = y1 + dy * t

                draw.ellipse(
                    (
                        xx - 3,
                        yy - 3,
                        xx + 3,
                        yy + 3
                    ),
                    fill=(70, 45, 20, 255)
                )


def draw_particles(base, amount, center_x, center_y, spread):

    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    for _ in range(amount):

        x = center_x + random.uniform(-spread, spread)
        y = center_y + random.uniform(-spread, spread)

        r = random.choice([1, 1, 2, 3])

        d.ellipse(
            (x-r, y-r, x+r, y+r),
            fill=(255, 220, 100, random.randint(100, 240))
        )

    layer = layer.filter(ImageFilter.GaussianBlur(0.5))

    base.alpha_composite(layer)


def draw_lights(base, progress):

    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    points = []

    # Top horizontal
    for i in range(12):
        x = int(W * 0.18 + i * W * 0.055)
        y = int(H * 0.37)
        points.append((x, y))

    # Left side
    for i in range(7):
        x = int(W * 0.18)
        y = int(H * 0.37 + i * H * 0.065)
        points.append((x, y))

    # Right side
    for i in range(7):
        x = int(W * 0.82)
        y = int(H * 0.37 + i * H * 0.065)
        points.append((x, y))

    visible = int(len(points) * progress)

    for i, (x, y) in enumerate(points[:visible]):

        draw_glow(layer, x, y, radius=22, alpha=130)

        d.ellipse(
            (x-4, y-4, x+4, y+4),
            fill=(255, 235, 150, 255)
        )

    base.alpha_composite(layer)


def draw_cloth(base, progress):

    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    alpha = int(220 * progress)

    # Top decorative cloth
    top_y = int(H * 0.32)

    d.polygon(
        [
            (int(W*0.14), top_y),
            (int(W*0.86), top_y),
            (int(W*0.79), top_y + int(H*0.09)),
            (int(W*0.21), top_y + int(H*0.09))
        ],
        fill=(180, 25, 50, alpha)
    )

    # Side hanging cloth
    d.polygon(
        [
            (int(W*0.14), top_y),
            (int(W*0.22), top_y),
            (int(W*0.25), int(H*0.68)),
            (int(W*0.16), int(H*0.60))
        ],
        fill=(35, 120, 75, alpha)
    )

    d.polygon(
        [
            (int(W*0.78), top_y),
            (int(W*0.86), top_y),
            (int(W*0.84), int(H*0.60)),
            (int(W*0.75), int(H*0.68))
        ],
        fill=(35, 120, 75, alpha)
    )

    # Golden border
    border_y = top_y + int(H * 0.08)

    d.line(
        (int(W*0.21), border_y,
         int(W*0.79), border_y),
        fill=(255, 205, 60, alpha),
        width=8
    )

    base.alpha_composite(layer)


# ============================================================
# FRAME GENERATION
# ============================================================

for frame_number in range(TOTAL_FRAMES):

    t = frame_number / FPS

    # Fresh copy of original street
    frame = street.convert("RGBA")

    # --------------------------------------------------------
    # STAGE 1
    # 0 - 3 seconds
    # Empty street
    # --------------------------------------------------------

    bamboo_progress = 0

    if t >= 2:

        bamboo_progress = ease_out(
            min(1, (t - 2) / 4)
        )

    # --------------------------------------------------------
    # BAMBOO STRUCTURE
    # --------------------------------------------------------

    if bamboo_progress > 0:

        overlay = Image.new(
            "RGBA",
            (W, H),
            (0, 0, 0, 0)
        )

        d = ImageDraw.Draw(overlay)

        # Pandal geometry
        left = (int(W*0.16), int(H*0.72))
        right = (int(W*0.84), int(H*0.72))

        left_top = (int(W*0.20), int(H*0.34))
        right_top = (int(W*0.80), int(H*0.34))

        top_left = (int(W*0.28), int(H*0.25))
        top_right = (int(W*0.72), int(H*0.25))

        center_top = (int(W*0.50), int(H*0.20))

        lines = [
            (left, left_top),
            (right, right_top),

            (left_top, top_left),
            (right_top, top_right),

            (top_left, center_top),
            (center_top, top_right),

            (top_left, top_right),

            (left, right),

            (left_top, right_top)
        ]

        for i, (p1, p2) in enumerate(lines):

            local_progress = bamboo_progress * len(lines) - i

            local_progress = max(
                0,
                min(1, local_progress)
            )

            draw_bamboo_line(
                d,
                p1,
                p2,
                width=max(8, int(W/120)),
                progress=local_progress
            )

        frame.alpha_composite(overlay)

    # --------------------------------------------------------
    # STAGE 2 DECORATIONS
    # --------------------------------------------------------

    decoration_progress = 0

    if t >= 5:

        decoration_progress = ease_in_out(
            min(1, (t - 5) / 3)
        )

        draw_cloth(
            frame,
            decoration_progress
        )

    # --------------------------------------------------------
    # LIGHTS
    # --------------------------------------------------------

    light_progress = 0

    if t >= 7:

        light_progress = min(
            1,
            (t - 7) / 2
        )

        draw_lights(
            frame,
            light_progress
        )

    # --------------------------------------------------------
    # THRONE
    # --------------------------------------------------------

    throne_progress = 0

    if t >= 8:

        throne_progress = min(
            1,
            (t - 8) / 1
        )

        throne = Image.new(
            "RGBA",
            (W, H),
            (0, 0, 0, 0)
        )

        td = ImageDraw.Draw(throne)

        cx = W // 2

        y = int(H * 0.72)

        width = int(W * 0.34)

        td.rectangle(
            (
                cx-width//2,
                y,
                cx+width//2,
                y+int(H*0.08)
            ),
            fill=(150, 85, 25, int(240*throne_progress))
        )

        td.rectangle(
            (
                cx-width//2+20,
                y-int(H*0.10),
                cx+width//2-20,
                y
            ),
            fill=(180, 100, 30, int(240*throne_progress))
        )

        frame.alpha_composite(throne)

    # --------------------------------------------------------
    # DIVINE APPEARANCE
    # --------------------------------------------------------

    idol_progress = 0

    if t >= 9:

        idol_progress = ease_in_out(
            min(1, (t - 9) / 3)
        )

        # Divine glow
        glow_layer = Image.new(
            "RGBA",
            (W, H),
            (0, 0, 0, 0)
        )

        center_x = W // 2
        center_y = int(H * 0.50)

        for radius in range(
            int(W*0.30),
            20,
            -20
        ):

            alpha = int(
                45 *
                idol_progress *
                (1-radius/(W*0.30))
            )

            ImageDraw.Draw(glow_layer).ellipse(
                (
                    center_x-radius,
                    center_y-radius,
                    center_x+radius,
                    center_y+radius
                ),
                fill=(255, 220, 100, max(0, alpha))
            )

        glow_layer = glow_layer.filter(
            ImageFilter.GaussianBlur(20)
        )

        frame.alpha_composite(glow_layer)

        # Magical particles
        draw_particles(
            frame,
            int(100 * idol_progress),
            center_x,
            center_y,
            int(W*0.28)
        )

        # Idol position
        idol_x = int(
            center_x -
            ganesha.width / 2
        )

        idol_y = int(
            H * 0.28
        )

        # Vertical magical entrance
        start_y = int(H * 0.12)

        current_y = int(
            start_y +
            (idol_y-start_y) * idol_progress
        )

        # Fade in
        idol = ganesha.copy()

        alpha = idol.getchannel("A")

        alpha = alpha.point(
            lambda p:
            int(p * idol_progress)
        )

        idol.putalpha(alpha)

        frame.alpha_composite(
            idol,
            (
                idol_x,
                current_y
            )
        )

    # --------------------------------------------------------
    # EXTRA FINAL FESTIVE EFFECT
    # --------------------------------------------------------

    if t >= 12:

        final_progress = min(
            1,
            (t-12)/2
        )

        draw_particles(
            frame,
            int(180 * final_progress),
            W//2,
            int(H*0.45),
            int(W*0.40)
        )

    # --------------------------------------------------------
    # SAVE FRAME
    # --------------------------------------------------------

    frame_path = os.path.join(
        FRAMES_DIR if "FRAMES_DIR" in globals() else OUTPUT_DIR,
        f"frame_{frame_number:05d}.png"
    )

    frame.convert("RGB").save(
        frame_path,
        quality=95
    )

    if frame_number % FPS == 0:
        print(
            f"Rendered {frame_number}/{TOTAL_FRAMES} frames"
        )


# ============================================================
# CREATE MP4 USING FFMPEG
# ============================================================

print("Creating MP4...")

subprocess.run(
    [
        "ffmpeg",
        "-y",
        "-framerate",
        str(FPS),
        "-i",
        f"{OUTPUT_DIR}/frame_%05d.png",
        "-c:v",
        "libx264",
        "-preset",
        "medium",
        "-crf",
        "18",
        "-pix_fmt",
        "yuv420p",
        OUTPUT_VIDEO
    ],
    check=True
)

print()
print("====================================")
print("VIDEO CREATED SUCCESSFULLY")
print("File:", OUTPUT_VIDEO)
print("====================================")
