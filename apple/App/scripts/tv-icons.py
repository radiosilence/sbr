# Builds the tvOS brand assets (layered app icons, top shelf images) from the 1024 icon.
# Run from the repo root: uv run --with pillow python3 apple/App/scripts/tv-icons.py apple/App/App/Assets.xcassets
import json, os, sys
from PIL import Image, ImageFilter
root = sys.argv[1]
src = Image.open(os.path.join(root, "AppIcon.appiconset/icon-1024.png")).convert("RGB")
BG = src.getpixel((8, 8))
# The glyph is everything clearly brighter than the ground (arch, outline, dot).
lum = src.convert("L")
mask = lum.point(lambda v: max(0, min(255, (v - 45) * 6)))
box = mask.point(lambda v: 255 if v > 0 else 0).getbbox()
glyph = src.copy(); glyph.putalpha(mask)
glyph = glyph.crop(box)
# Where the green dot sits within the glyph, as a fraction of its box.
DOT = ((512 - box[0]) / (box[2] - box[0]), (720 - box[1]) / (box[3] - box[1]))
INFO = {"author": "xcode", "version": 1}
def back(w, h, frac):
    # The ground with a soft green glow under the dot, drawn at size.
    gh = h * frac; gw = glyph.width * gh / glyph.height
    cx = (w - gw) / 2 + DOT[0] * gw; cy = (h - gh) / 2 + DOT[1] * gh
    r = gh * 0.55
    n = round(2 * r)
    glow = Image.new("L", (n, n))
    glow.putdata([round(140 * max(0.0, 1 - (((x - r) ** 2 + (y - r) ** 2) ** 0.5) / r) ** 2) for y in range(n) for x in range(n)])
    im = Image.new("RGB", (w, h), BG)
    im.paste(Image.new("RGB", glow.size, (42, 72, 60)), (round(cx - r), round(cy - r)), glow)
    return im
def front(w, h, frac):
    gh = round(h * frac); gw = round(glyph.width * gh / glyph.height)
    g = glyph.resize((gw, gh), Image.LANCZOS)
    c = Image.new("RGBA", (w, h), (0, 0, 0, 0)); c.paste(g, ((w - gw) // 2, (h - gh) // 2), g); return c
def write(path, obj):
    os.makedirs(path, exist_ok=True)
    json.dump(obj, open(os.path.join(path, "Contents.json"), "w"), indent=2)
def stack(path, w, h, scales):
    write(path, {"info": INFO, "layers": [{"filename": "Front.imagestacklayer"}, {"filename": "Back.imagestacklayer"}]})
    for name, make in [("Front", lambda W, H: front(W, H, 0.62)), ("Back", lambda W, H: back(W, H, 0.62))]:
        layer = os.path.join(path, f"{name}.imagestacklayer"); write(layer, {"info": INFO})
        content = os.path.join(layer, "Content.imageset"); imgs = []
        for sc in scales:
            fn = f"{name.lower()}{'' if sc == 1 else f'@{sc}x'}.png"
            make(w * sc, h * sc).save(os.path.join(content, fn)) if os.makedirs(content, exist_ok=True) is None else None
            imgs.append({"filename": fn, "idiom": "tv", "scale": f"{sc}x"})
        write(content, {"images": imgs, "info": INFO})
def shelf(path, w, h):
    os.makedirs(path, exist_ok=True); imgs = []
    for sc in (1, 2):
        fn = f"shelf{'' if sc == 1 else '@2x'}.png"
        im = back(w * sc, h * sc, 0.55).convert("RGBA"); f = front(w * sc, h * sc, 0.55); im.alpha_composite(f)
        im.convert("RGB").save(os.path.join(path, fn)); imgs.append({"filename": fn, "idiom": "tv", "scale": f"{sc}x"})
    write(path, {"images": imgs, "info": INFO})
B = os.path.join(root, "App Icon & Top Shelf Image.brandassets")
stack(os.path.join(B, "App Icon - App Store.imagestack"), 1280, 768, [1])
stack(os.path.join(B, "App Icon.imagestack"), 400, 240, [1, 2])
shelf(os.path.join(B, "Top Shelf Image.imageset"), 1920, 720)
shelf(os.path.join(B, "Top Shelf Image Wide.imageset"), 2320, 720)
write(B, {"assets": [
    {"filename": "App Icon - App Store.imagestack", "idiom": "tv", "role": "primary-app-icon", "size": "1280x768"},
    {"filename": "App Icon.imagestack", "idiom": "tv", "role": "primary-app-icon", "size": "400x240"},
    {"filename": "Top Shelf Image Wide.imageset", "idiom": "tv", "role": "top-shelf-image-wide", "size": "2320x720"},
    {"filename": "Top Shelf Image.imageset", "idiom": "tv", "role": "top-shelf-image", "size": "1920x720"}], "info": INFO})
print("ok")
