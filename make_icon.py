"""Tạo icon.ico cho app (chạy 1 lần, cần Pillow)."""
from PIL import Image, ImageDraw

S = 512
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# Nền bo góc gradient xanh
grad = Image.new("RGBA", (S, S))
gd = ImageDraw.Draw(grad)
for y in range(S):
    t = y / S
    r = int(59 + (29 - 59) * t)
    g = int(130 + (78 - 130) * t)
    b = int(246 + (216 - 246) * t)
    gd.line([(0, y), (S, y)], fill=(r, g, b, 255))
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=112, fill=255)
img.paste(grad, (0, 0), mask)

# Ổ khoá trắng
white = (255, 255, 255, 255)
d.arc([166, 92, 346, 272], start=180, end=360, fill=white, width=44)
d.line([(188, 182), (188, 240)], fill=white, width=44)
d.line([(324, 182), (324, 240)], fill=white, width=44)
d.rounded_rectangle([116, 226, 396, 436], radius=40, fill=white)
# Lỗ khoá
blue = (37, 99, 235, 255)
d.ellipse([228, 284, 284, 340], fill=blue)
d.rounded_rectangle([244, 312, 268, 384], radius=10, fill=blue)

img.save("icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
img.resize((128, 128), Image.LANCZOS).save("icon_preview.png")
print("ok")
