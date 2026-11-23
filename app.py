"""2FA Code - ứng dụng desktop lấy mã 2FA (TOTP) trên Windows.

Giao diện: customtkinter. Thuật toán TOTP chỉ dùng thư viện chuẩn.
Secret được lưu ở %APPDATA%\\TwoFACode\\accounts.dat và được mã hoá bằng
Windows DPAPI (chỉ tài khoản Windows của bạn trên máy này giải mã được).
"""

import base64
import ctypes
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import tkinter as tk
from ctypes import wintypes
from tkinter import filedialog, messagebox
from urllib.parse import parse_qs, unquote, urlparse

import customtkinter as ctk
import zxingcpp

try:  # kéo-thả file (tuỳ chọn, thiếu thì app vẫn chạy)
    from tkinterdnd2 import DND_FILES, DND_TEXT, TkinterDnD
    _DnDBase = TkinterDnD.DnDWrapper
except Exception:
    TkinterDnD = None
    _DnDBase = object
from PIL import Image, ImageDraw, ImageEnhance, ImageGrab, ImageOps, ImageTk

from i18n import get_lang, set_lang, tr

APP_NAME = "2FA Code"
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "TwoFACode")
DATA_FILE = os.path.join(DATA_DIR, "accounts.dat")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")


def resource_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


# ----------------------------------------------------------------------------
# TOTP (RFC 6238)
# ----------------------------------------------------------------------------
def decode_secret(secret: str) -> bytes:
    s = secret.replace(" ", "").replace("-", "").strip().upper().rstrip("=")
    if not s:
        raise ValueError(tr("Secret key trống"))
    s += "=" * (-len(s) % 8)
    try:
        key = base64.b32decode(s)
    except Exception:
        raise ValueError(tr("Secret key không hợp lệ (phải là chuỗi Base32: A-Z, 2-7)"))
    if not key:
        raise ValueError(tr("Secret key không hợp lệ"))
    return key


def totp(secret: str, digits: int = 6, period: int = 30, algorithm: str = "SHA1", at: float | None = None) -> str:
    key = decode_secret(secret)
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm.lower())).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def parse_otpauth(uri: str) -> dict:
    """Đọc link dạng otpauth://totp/Issuer:account?secret=...&issuer=..."""
    u = urlparse(uri.strip())
    if u.scheme != "otpauth" or u.netloc.lower() != "totp":
        raise ValueError(tr("Chỉ hỗ trợ link otpauth://totp/..."))
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    if "secret" not in q:
        raise ValueError(tr("Link không có secret"))
    label = unquote(u.path.lstrip("/"))
    issuer = q.get("issuer", "")
    name = label
    if ":" in label:
        lbl_issuer, account = label.split(":", 1)
        issuer = issuer or lbl_issuer
        name = f"{issuer} ({account.strip()})"
    elif issuer and issuer not in label:
        name = f"{issuer} ({label})" if label else issuer
    return {
        "name": name or tr("Không tên"),
        "secret": q["secret"],
        "digits": int(q.get("digits", 6)),
        "period": int(q.get("period", 30)),
        "algorithm": q.get("algorithm", "SHA1").upper(),
    }


def scan_qr(img: Image.Image) -> list[tuple[str, tuple[float, float, float, float]]]:
    """Tìm mã QR trong ảnh -> [(nội dung, (x0, y0, x1, y1))] theo toạ độ ảnh gốc.
    Thử thêm vài biến thể nếu ảnh nhỏ hoặc QR sáng trên nền tối."""
    img = img.convert("RGB")
    variants = [(img, 1)]
    if max(img.size) > 1800:  # ảnh chụp bằng điện thoại: thử thêm bản thu nhỏ
        s = 1600 / max(img.size)
        variants.append((img.resize((int(img.width * s), int(img.height * s)), Image.LANCZOS), s))
    if min(img.size) < 400:
        variants.append((img.resize((img.width * 3, img.height * 3), Image.NEAREST), 3))
    variants.append((ImageOps.invert(img), 1))
    for im, s in variants:
        out = []
        for r in zxingcpp.read_barcodes(im):
            if not r.text:
                continue
            p = r.position
            pts = [p.top_left, p.top_right, p.bottom_left, p.bottom_right]
            xs, ys = [q.x / s for q in pts], [q.y / s for q in pts]
            out.append((r.text, (min(xs), min(ys), max(xs), max(ys))))
        if out:
            return out
    return []


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _pb_fields(buf: bytes):
    """Đọc protobuf tối giản: trả về (số field, giá trị)."""
    i = 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, i = _read_varint(buf, i)
        elif wire == 2:
            n, i = _read_varint(buf, i)
            val = buf[i:i + n]
            if len(val) != n:
                raise ValueError("truncated")
            i += n
        elif wire == 1:
            val, i = buf[i:i + 8], i + 8
        elif wire == 5:
            val, i = buf[i:i + 4], i + 4
        else:
            raise ValueError("wire type")
        yield field, val


def display_name(issuer: str, name: str) -> str:
    if ":" in name:
        lbl_issuer, name = name.split(":", 1)
        issuer = issuer or lbl_issuer.strip()
    name = name.strip()
    issuer = issuer.strip()
    if issuer and name and name != issuer:
        return f"{issuer} ({name})"
    return issuer or name or tr("Không tên")


def parse_migration(uri: str) -> dict:
    """Giải mã QR 'Xuất tài khoản' của Google Authenticator (otpauth-migration://offline?data=...)."""
    u = urlparse(uri.strip())
    if u.scheme.lower() != "otpauth-migration":
        raise ValueError(tr("Không phải QR xuất từ Google Authenticator"))
    data = ""
    for part in u.query.split("&"):
        k, _, v = part.partition("=")
        if k == "data":
            data = unquote(v)  # không dùng unquote_plus: '+' là ký tự base64
    if not data:
        raise ValueError(tr("QR Google Authenticator không có dữ liệu"))
    data = data.replace(" ", "+").replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    try:
        raw = base64.b64decode(data)
    except Exception:
        raise ValueError(tr("Dữ liệu QR Google Authenticator bị hỏng"))

    algos = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
    result = {"accounts": [], "skipped": [], "batch_size": 1, "batch_index": 0, "batch_id": 0}
    try:
        for field, val in _pb_fields(raw):
            if field == 1:
                p = dict(_pb_fields(val))
                secret = p.get(1, b"")
                name = display_name(p.get(3, b"").decode("utf-8", "replace"),
                                    p.get(2, b"").decode("utf-8", "replace"))
                algo = algos.get(p.get(4, 0), "SHA1")
                if p.get(6, 2) == 1:
                    result["skipped"].append((name, tr("HOTP (theo bộ đếm) — app chỉ hỗ trợ TOTP")))
                elif algo == "MD5" or not secret:
                    result["skipped"].append((name, tr("Định dạng không hỗ trợ")))
                else:
                    result["accounts"].append({
                        "name": name,
                        "secret": base64.b32encode(secret).decode().rstrip("="),
                        "digits": 8 if p.get(5) == 2 else 6,
                        "period": 30,
                        "algorithm": algo,
                    })
            elif field == 3:
                result["batch_size"] = val
            elif field == 4:
                result["batch_index"] = val
            elif field == 5:
                result["batch_id"] = val
    except (IndexError, ValueError):
        raise ValueError(tr("Dữ liệu QR Google Authenticator bị hỏng (ảnh mờ hoặc bị cắt?)"))
    return result


def norm_secret(s: str) -> str:
    return s.replace(" ", "").replace("-", "").upper().rstrip("=")


def decode_qr(img: Image.Image) -> list[str]:
    return [t for t, _ in scan_qr(img)]


def crop_qr(img: Image.Image, box, margin: int = 12) -> Image.Image:
    x0, y0, x1, y1 = box
    return img.crop((max(0, int(x0) - margin), max(0, int(y0) - margin),
                     min(img.width, int(x1) + margin), min(img.height, int(y1) + margin)))


def account_from_qr(texts: list[str]) -> dict:
    for t in texts:
        if t.lower().startswith("otpauth://totp"):
            return parse_otpauth(t)
    if any(t.lower().startswith("otpauth-migration://") for t in texts):
        raise ValueError(tr("Đây là QR xuất từ Google Authenticator (chuyển nhiều tài khoản) — chưa hỗ trợ. "
                         "Hãy dùng QR gốc do app/web cung cấp."))
    if any(t.lower().startswith("otpauth://hotp") for t in texts):
        raise ValueError(tr("QR này dùng HOTP (theo bộ đếm), app chỉ hỗ trợ TOTP (theo thời gian)."))
    if texts:
        raise ValueError(tr("Đọc được QR nhưng không phải mã 2FA (otpauth://totp)."))
    raise ValueError(tr("Không tìm thấy mã QR nào trong ảnh."))


# ----------------------------------------------------------------------------
# Lưu trữ mã hoá bằng Windows DPAPI
# ----------------------------------------------------------------------------
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        return data
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    crypt32 = ctypes.windll.crypt32
    UI_FORBIDDEN = 0x1
    if protect:
        ok = crypt32.CryptProtectData(ctypes.byref(blob_in), APP_NAME, None, None, None,
                                      UI_FORBIDDEN, ctypes.byref(blob_out))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None,
                                        UI_FORBIDDEN, ctypes.byref(blob_out))
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def load_accounts() -> list[dict]:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "rb") as f:
        raw = f.read()
    return json.loads(_dpapi(raw, protect=False).decode("utf-8"))


def save_accounts(accounts: list[dict]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    data = _dpapi(json.dumps(accounts, ensure_ascii=False).encode("utf-8"), protect=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, DATA_FILE)


def load_settings() -> dict:
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(settings: dict) -> None:
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f)
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Giao diện
# ----------------------------------------------------------------------------
# Mỗi màu là (chế độ sáng, chế độ tối)
BG = ("#eef0f4", "#0f1115")
CARD = ("#ffffff", "#1a1d24")
CARD_HOVER = ("#f6f8fc", "#20242d")
BORDER = ("#e3e6ec", "#272b35")
TEXT = ("#111827", "#f3f4f6")
MUTED = ("#6b7280", "#9aa3b2")
ACCENT = ("#2563eb", "#4f8cff")
ACCENT_HOVER = ("#1d4ed8", "#3b76f0")
WARN = ("#dc2626", "#f87171")
OK = ("#16a34a", "#4ade80")
TRACK = ("#e5e7eb", "#2b303b")
INPUT = ("#ffffff", "#1a1d24")
SECONDARY = ("#e5e7eb", "#2b303b")
SECONDARY_HOVER = ("#d1d5db", "#363c49")
ACCENT_SOFT = ("#dbe7ff", "#1c2a48")
ACCENT_SOFT_HOVER = ("#c7d9ff", "#23355c")
ZONE = ("#f8fafc", "#14171e")

AVATAR_COLORS = ["#2563eb", "#7c3aed", "#db2777", "#ea580c", "#16a34a",
                 "#0891b2", "#ca8a04", "#4f46e5", "#be123c", "#0d9488"]

FONT = "Segoe UI"
APPEARANCE_MODES = [("System", "Hệ thống"), ("Light", "Sáng"), ("Dark", "Tối")]


def pick(color):
    """Chọn màu theo chế độ sáng/tối hiện tại (cho widget tk thường như Canvas)."""
    if isinstance(color, str):
        return color
    return color[0] if ctk.get_appearance_mode() == "Light" else color[1]


def fmt_code(code: str) -> str:
    half = len(code) // 2
    return f"{code[:half]} {code[half:]}"


def avatar_color(name: str) -> str:
    h = int(hashlib.md5(name.lower().encode("utf-8")).hexdigest(), 16)
    return AVATAR_COLORS[h % len(AVATAR_COLORS)]


def ellipsize(text: str, n: int = 32) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


_circle_cache: dict = {}


def circle_image(color: str, size: int = 44) -> ctk.CTkImage:
    """Hình tròn khử răng cưa (vẽ to rồi thu nhỏ) để làm avatar."""
    key = (color, size)
    if key not in _circle_cache:
        big = 256
        img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        ImageDraw.Draw(img).ellipse([0, 0, big - 1, big - 1], fill=color)
        img = img.resize((size * 4, size * 4), Image.LANCZOS)
        _circle_cache[key] = ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))
    return _circle_cache[key]


def thumb_image(img: Image.Image, side: int) -> ctk.CTkImage:
    t = img.convert("RGB")
    t.thumbnail((side * 4, side * 4))
    ratio = t.width / t.height
    size = (side, max(1, int(side / ratio))) if ratio >= 1 else (max(1, int(side * ratio)), side)
    return ctk.CTkImage(light_image=t, dark_image=t, size=size)


def set_icon(win):
    path = resource_path("icon.ico")
    if os.path.exists(path):
        try:
            win.iconbitmap(path)
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Nguồn ảnh QR dùng chung: clipboard, file, kéo-thả, chọn vùng màn hình
# ----------------------------------------------------------------------------
def image_types():
    return [(tr("Ảnh"), "*.png *.jpg *.jpeg *.bmp *.gif *.webp"), (tr("Tất cả"), "*.*")]


def open_image(path: str) -> Image.Image:
    img = Image.open(path)
    img = ImageOps.exif_transpose(img)  # ảnh chụp điện thoại bị xoay
    img.load()
    return img


def open_images(paths) -> tuple[list, list]:
    images, errors = [], []
    for p in paths:
        try:
            images.append(open_image(p))
        except Exception as e:
            errors.append(tr("Không mở được ảnh {name}: {err}", name=os.path.basename(p), err=e))
    return images, errors


def clipboard_image():
    data = ImageGrab.grabclipboard()
    if isinstance(data, Image.Image):
        return data
    if isinstance(data, list):  # copy file ảnh trong Explorer
        for path in data:
            try:
                return open_image(path)
            except Exception:
                continue
    return None


def safe_clipboard_image():
    try:
        return clipboard_image()
    except Exception:
        return None


def clipboard_seq() -> int:
    try:
        return ctypes.windll.user32.GetClipboardSequenceNumber()
    except Exception:
        return 0


def looks_like_secret(text: str) -> bool:
    try:
        decode_secret(text)
        return len(text.replace(" ", "")) >= 16
    except ValueError:
        return False


def read_drop(widget, data: str) -> tuple[list, list, str | None]:
    """Đọc dữ liệu kéo-thả -> (ảnh, chuỗi otpauth, lỗi)."""
    images, texts = [], []
    for item in list(widget.tk.splitlist(data)) or [data]:
        item = item.strip()
        low = item.lower()
        if os.path.isfile(item):
            try:
                images.append(open_image(item))
            except Exception:
                pass
        elif low.startswith("otpauth"):
            texts.append(item)
        elif low.startswith("data:image") and "," in item:
            try:
                import io
                images.append(Image.open(io.BytesIO(base64.b64decode(item.split(",", 1)[1]))))
            except Exception:
                pass
        elif low.startswith("http"):
            return [], [], (tr("Kéo ảnh trực tiếp từ trình duyệt không lấy được file. Hãy dùng "
                            "\"Chọn vùng màn hình\" hoặc chuột phải ảnh → Copy image."))
    if not images and not texts:
        return [], [], tr("Không nhận ra dữ liệu vừa thả. Hãy thả file ảnh chứa mã QR.")
    return images, texts, None


def pick_from_screen(win, done, on_error):
    """Ẩn tạm app, chụp màn hình và mở RegionPicker. done((texts, thumb) | None)."""
    wins = [win] + ([win.master] if win.master is not None else [])
    for w in wins:
        w.attributes("-alpha", 0.0)
    win.update()

    def restore():
        for w in wins:
            w.attributes("-alpha", 1.0)
        win.lift()
        win.focus_force()
        try:
            win.grab_set()
        except tk.TclError:
            pass

    def finished(result):
        restore()
        done(result)

    def grab():
        try:
            shot = ImageGrab.grab(all_screens=True)
            u32 = ctypes.windll.user32
            origin = (u32.GetSystemMetrics(76), u32.GetSystemMetrics(77))  # góc trái-trên màn hình ảo
        except Exception as e:
            restore()
            on_error(tr("Không chụp được màn hình: {err}", err=e))
            return
        try:
            win.grab_release()
        except tk.TclError:
            pass
        RegionPicker(win, shot, origin, finished)

    win.after(300, grab)


def qr_glyph(size: int = 52) -> ctk.CTkImage:
    """Biểu tượng mã QR vẽ bằng PIL (cho ô kéo-thả)."""
    def draw(color):
        n, cell = 7, 32
        img = Image.new("RGBA", (n * cell * 3, n * cell * 3), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        u = cell
        def finder(x, y):
            d.rounded_rectangle([x, y, x + 7 * u, y + 7 * u], radius=u * 1.4, outline=color, width=u)
            d.rounded_rectangle([x + 2 * u, y + 2 * u, x + 5 * u, y + 5 * u], radius=u * 0.8, fill=color)
        W = img.width
        finder(0, 0)
        finder(W - 7 * u, 0)
        finder(0, W - 7 * u)
        for (cx, cy) in [(9, 1), (11, 3), (9, 5), (1, 9), (3, 11), (5, 9), (9, 9), (11, 11), (13, 9),
                         (9, 13), (13, 13), (17, 9), (19, 11), (15, 17), (17, 19), (19, 15), (9, 18), (12, 16)]:
            d.rounded_rectangle([cx * u, cy * u, cx * u + 1.6 * u, cy * u + 1.6 * u], radius=u * 0.4, fill=color)
        return img
    return ctk.CTkImage(light_image=draw(MUTED[0]), dark_image=draw(MUTED[1]), size=(size, size))


def _round_rect(c: tk.Canvas, x0, y0, x1, y1, r, **kw):
    pts = [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
           x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
    return c.create_polygon(pts, smooth=True, **kw)


class RegionPicker(tk.Toplevel):
    """Phủ toàn màn hình bằng ảnh chụp làm tối; người dùng kéo chuột chọn vùng có QR
    (giống Snipping Tool). Mã QR phát hiện sẵn được đóng khung xanh, click là chọn."""

    def __init__(self, master, shot: Image.Image, origin: tuple[int, int], on_done):
        super().__init__(master)
        self.on_done = on_done
        self.shot = shot.convert("RGB")
        self.ox, self.oy = origin
        w, h = self.shot.size
        self.overrideredirect(True)
        self.geometry(f"{w}x{h}+{self.ox}+{self.oy}")
        self.attributes("-topmost", True)
        self.k = self.winfo_fpixels("1i") / 96  # hệ số DPI

        self.c = tk.Canvas(self, width=w, height=h, highlightthickness=0, bd=0, bg="black", cursor="crosshair")
        self.c.pack(fill="both", expand=True)
        self._dim = ImageTk.PhotoImage(ImageEnhance.Brightness(self.shot).enhance(0.38))
        self.c.create_image(0, 0, image=self._dim, anchor="nw")

        # Màn hình chính trong toạ độ canvas (để đặt dòng hướng dẫn)
        self.px, self.py = -self.ox, -self.oy
        self.pw = ctypes.windll.user32.GetSystemMetrics(0) if sys.platform == "win32" else w
        self.start = None
        self.boxes: list[tuple] = []
        self._keep = []  # giữ tham chiếu PhotoImage
        self._sel_img = None

        self.c.bind("<ButtonPress-1>", self.on_press)
        self.c.bind("<B1-Motion>", self.on_drag)
        self.c.bind("<ButtonRelease-1>", self.on_release)
        self.c.bind("<Motion>", self.on_hover)
        self.c.bind("<Button-3>", lambda e: self.finish(None))
        self.bind("<Escape>", lambda e: self.finish(None))
        self.bind("<Return>", lambda e: self.boxes and self.pick(self._pad(self.boxes[0])))

        self.show_hint(tr("Đang tìm mã QR trên màn hình..."))
        self.after(30, self.detect)
        self.after(60, self._take_focus)

    def _take_focus(self):
        self.lift()
        self.focus_force()
        try:
            self.grab_set()
        except tk.TclError:
            pass

    def f(self, size, weight="normal"):
        return (FONT, -int(size * self.k), weight)

    def _pad(self, box, p=14):
        x0, y0, x1, y1 = box
        return (x0 - p, y0 - p, x1 + p, y1 + p)

    def show_hint(self, text, error=False):
        self.c.delete("hint")
        cx, y = self.px + self.pw / 2, self.py + 26 * self.k
        t = self.c.create_text(cx, y, text=text, fill="white", font=self.f(15), anchor="n", tags="hint")
        x0, y0, x1, y1 = self.c.bbox(t)
        px, py = 18 * self.k, 10 * self.k
        r = _round_rect(self.c, x0 - px, y0 - py, x1 + px, y1 + py, 14 * self.k,
                        fill="#b91c1c" if error else "#111827", outline="#374151" if not error else "", tags="hint")
        self.c.tag_lower(r, t)

    def _bright(self, box, tag):
        x0, y0, x1, y1 = [int(v) for v in box]
        x0, y0 = max(0, x0), max(0, y0)
        x1, y1 = min(self.shot.width, x1), min(self.shot.height, y1)
        if x1 - x0 < 2 or y1 - y0 < 2:
            return None
        img = ImageTk.PhotoImage(self.shot.crop((x0, y0, x1, y1)))
        self.c.create_image(x0, y0, image=img, anchor="nw", tags=tag)
        return img

    def detect(self):
        found = scan_qr(self.shot)
        totp_boxes = [b for t, b in found if t.lower().startswith("otpauth")]
        self.boxes = totp_boxes or [b for _, b in found]
        for b in self.boxes:
            pb = self._pad(b)
            self._keep.append(self._bright(pb, "found"))
            self.c.create_rectangle(*pb, outline="#22c55e", width=max(2, int(3 * self.k)), tags="found")
            lx, ly = pb[0], pb[1] - 6 * self.k
            t = self.c.create_text(lx + 10 * self.k, ly, text=tr("Click để chọn"), anchor="sw", fill="white",
                                   font=self.f(13, "bold"), tags="found")
            x0, y0, x1, y1 = self.c.bbox(t)
            r = self.c.create_rectangle(x0 - 8 * self.k, y0 - 4 * self.k, x1 + 8 * self.k, y1 + 4 * self.k,
                                        fill="#16a34a", outline="", tags="found")
            self.c.tag_lower(r, t)
        if self.boxes:
            self.show_hint(tr("Phát hiện {n} mã QR — click vào khung xanh để chọn (Enter)   •   "
                              "hoặc kéo chuột chọn vùng khác   •   Esc: huỷ", n=len(self.boxes)))
        else:
            self.show_hint(tr("Kéo chuột để chọn vùng có mã QR   •   Esc hoặc chuột phải: huỷ"))
        self.c.tag_raise("hint")

    def _box_at(self, x, y):
        for b in self.boxes:
            x0, y0, x1, y1 = self._pad(b)
            if x0 <= x <= x1 and y0 <= y <= y1:
                return b
        return None

    def on_hover(self, e):
        self.c.configure(cursor="hand2" if self._box_at(e.x, e.y) else "crosshair")

    def on_press(self, e):
        self.start = (e.x, e.y)
        self.c.delete("sel")

    def on_drag(self, e):
        if not self.start:
            return
        x0, y0 = self.start
        box = (min(x0, e.x), min(y0, e.y), max(x0, e.x), max(y0, e.y))
        self.c.delete("sel")
        if box[2] - box[0] < 4 or box[3] - box[1] < 4:
            return
        self._sel_img = self._bright(box, "sel")
        self.c.create_rectangle(*box, outline="#3b82f6", width=max(2, int(2 * self.k)), tags="sel")
        label = f"{int(box[2] - box[0])} × {int(box[3] - box[1])}"
        t = self.c.create_text(box[2], box[3] + 8 * self.k, text=label, anchor="ne", fill="white",
                               font=self.f(12), tags="sel")
        bx0, by0, bx1, by1 = self.c.bbox(t)
        r = self.c.create_rectangle(bx0 - 6 * self.k, by0 - 3 * self.k, bx1 + 6 * self.k, by1 + 3 * self.k,
                                    fill="#1d4ed8", outline="", tags="sel")
        self.c.tag_lower(r, t)
        self.c.tag_raise("hint")

    def on_release(self, e):
        if not self.start:
            return
        x0, y0 = self.start
        self.start = None
        if abs(e.x - x0) < 8 and abs(e.y - y0) < 8:  # chỉ là click
            b = self._box_at(e.x, e.y)
            if b:
                self.pick(self._pad(b))
            return
        self.pick((min(x0, e.x), min(y0, e.y), max(x0, e.x), max(y0, e.y)))

    def pick(self, box):
        x0, y0, x1, y1 = [int(v) for v in box]
        region = self.shot.crop((max(0, x0), max(0, y0), min(self.shot.width, x1), min(self.shot.height, y1)))
        found = scan_qr(region)
        if not found:
            self.c.delete("sel")
            self.show_hint(tr("Không thấy mã QR trong vùng vừa chọn — hãy kéo lại cho bao trọn cả mã QR   •   "
                           "Esc: huỷ"), error=True)
            return
        texts = [t for t, _ in found]
        best = next((b for t, b in found if t.lower().startswith("otpauth")), found[0][1])
        self.finish((texts, crop_qr(region, best)))

    def finish(self, result):
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
        self.on_done(result)


class AccountDialog(ctk.CTkToplevel):
    def __init__(self, master, on_save, account: dict | None = None):
        super().__init__(master)
        self.on_save = on_save
        self.title(tr("Sửa tài khoản") if account else tr("Thêm tài khoản"))
        self.configure(fg_color=BG)
        self.resizable(False, False)
        self.transient(master)
        self.after(250, lambda: set_icon(self))

        f_label = ctk.CTkFont(FONT, 13)
        f_input = ctk.CTkFont(FONT, 14)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=26, pady=22)

        ctk.CTkLabel(body, text=self.title(), font=ctk.CTkFont(FONT, 20, "bold"),
                     text_color=TEXT, anchor="w").pack(fill="x")
        ctk.CTkLabel(body, text=tr("Nhập secret key do app/web cung cấp khi bật 2FA"),
                     font=f_label, text_color=MUTED, anchor="w").pack(fill="x", pady=(0, 14))

        def field(label, placeholder):
            ctk.CTkLabel(body, text=label, font=f_label, text_color=MUTED, anchor="w").pack(fill="x", pady=(6, 4))
            e = ctk.CTkEntry(body, height=42, corner_radius=10, font=f_input, fg_color=INPUT,
                             border_color=BORDER, border_width=1, text_color=TEXT,
                             placeholder_text=placeholder, width=380)
            e.pack(fill="x")
            return e

        self.name_entry = field(tr("Tên hiển thị"), tr("VD: Gmail công ty, OpenVPN..."))
        self.secret_entry = field(tr("Secret key (hoặc link otpauth://)"), "VD: JBSW Y3DP EHPK 3PXP")

        # Lấy từ mã QR
        ctk.CTkLabel(body, text=tr("Hoặc lấy từ mã QR"), font=f_label, text_color=MUTED,
                     anchor="w").pack(fill="x", pady=(14, 4))
        self.zone = ctk.CTkFrame(body, fg_color=ZONE, corner_radius=12, border_width=2, border_color=BORDER)
        self.zone.pack(fill="x")
        self.zone.columnconfigure(1, weight=1)
        self._glyph = qr_glyph()
        self.zone_icon = ctk.CTkLabel(self.zone, text="", image=self._glyph, width=60, height=60)
        self.zone_icon.grid(row=0, column=0, rowspan=2, padx=(14, 12), pady=12)
        self.zone_title = ctk.CTkLabel(self.zone, text="", font=ctk.CTkFont(FONT, 14, "bold"),
                                       text_color=TEXT, anchor="w", height=22)
        self.zone_title.grid(row=0, column=1, sticky="sw", padx=(0, 12), pady=(12, 0))
        self.zone_sub = ctk.CTkLabel(self.zone, text="", font=ctk.CTkFont(FONT, 12), text_color=MUTED,
                                     anchor="w", justify="left", wraplength=290)
        self.zone_sub.grid(row=1, column=1, sticky="nw", padx=(0, 12), pady=(0, 12))
        for w in (self.zone, self.zone_icon, self.zone_title, self.zone_sub):
            w.bind("<Button-1>", lambda e: self.qr_from_file())
            try:
                w.configure(cursor="hand2")
            except Exception:
                pass
        self.set_zone("idle")

        qr = ctk.CTkFrame(body, fg_color="transparent")
        qr.pack(fill="x", pady=(8, 0))
        qr.columnconfigure(0, weight=2, uniform="qr")
        qr.columnconfigure((1, 2), weight=1, uniform="qr")
        ctk.CTkButton(qr, text=tr("✂  Chọn vùng màn hình"), height=40, width=10, corner_radius=10,
                      font=ctk.CTkFont(FONT, 13, "bold"), fg_color=ACCENT_SOFT, hover_color=ACCENT_SOFT_HOVER,
                      text_color=ACCENT, command=self.qr_from_screen).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(qr, text=tr("📋  Dán"), height=40, width=10, corner_radius=10, font=ctk.CTkFont(FONT, 13),
                      fg_color=SECONDARY, hover_color=SECONDARY_HOVER, text_color=TEXT,
                      command=self.qr_from_clipboard).grid(row=0, column=1, sticky="ew", padx=4)
        ctk.CTkButton(qr, text=tr("🖼  File ảnh"), height=40, width=10, corner_radius=10, font=ctk.CTkFont(FONT, 13),
                      fg_color=SECONDARY, hover_color=SECONDARY_HOVER, text_color=TEXT,
                      command=self.qr_from_file).grid(row=0, column=2, sticky="ew", padx=(4, 0))

        self.preview = ctk.CTkLabel(body, text=" ", font=ctk.CTkFont(FONT, 13), anchor="w", text_color=MUTED,
                                    wraplength=380, justify="left")
        self.preview.pack(fill="x", pady=(6, 0))

        # Tuỳ chọn nâng cao (ẩn mặc định)
        self.adv_open = False
        self.adv_btn = ctk.CTkButton(body, text=tr("Tuỳ chọn nâng cao  ▸"), font=f_label, fg_color="transparent",
                                     hover_color=SECONDARY, text_color=MUTED, anchor="w", height=30,
                                     width=10, command=self.toggle_adv)
        self.adv_btn.pack(anchor="w", pady=(6, 0))
        self.adv = ctk.CTkFrame(body, fg_color="transparent")
        acc = account or {}
        self.digits = self._option(self.adv, 0, tr("Số chữ số"), ["6", "7", "8"], str(acc.get("digits", 6)))
        self.period = self._option(self.adv, 1, tr("Chu kỳ (giây)"), ["30", "60"], str(acc.get("period", 30)))
        self.algo = self._option(self.adv, 2, tr("Thuật toán"), ["SHA1", "SHA256", "SHA512"], acc.get("algorithm", "SHA1"))
        self.adv_anchor = ctk.CTkFrame(body, fg_color="transparent", height=1)
        self.adv_anchor.pack(fill="x")

        btns = ctk.CTkFrame(body, fg_color="transparent")
        btns.pack(fill="x", pady=(20, 0))
        btns.columnconfigure((0, 1), weight=1, uniform="b")
        ctk.CTkButton(btns, text=tr("Huỷ"), height=42, corner_radius=10, font=ctk.CTkFont(FONT, 14),
                      fg_color=SECONDARY, hover_color=SECONDARY_HOVER, text_color=TEXT, width=10,
                      command=self.destroy).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(btns, text=tr("Lưu"), height=42, corner_radius=10, font=ctk.CTkFont(FONT, 14, "bold"),
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, width=10,
                      command=self.save).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        if account:
            self.name_entry.insert(0, account["name"])
            self.secret_entry.insert(0, account["secret"])
            if (acc.get("digits", 6), acc.get("period", 30), acc.get("algorithm", "SHA1")) != (6, 30, "SHA1"):
                self.toggle_adv()

        for w in (self.secret_entry, self.name_entry):
            w.bind("<KeyRelease>", lambda e: self.update_preview())
        for v in (self.digits, self.period, self.algo):
            v.configure(command=lambda _: self.update_preview())
        self.bind("<Return>", lambda e: self.save())
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Control-v>", self._on_paste)
        self.bind("<Control-V>", self._on_paste)

        # Kéo-thả ảnh / file ảnh / link otpauth vào cửa sổ
        if getattr(master, "dnd_ok", False):
            try:
                self.drop_target_register(DND_FILES, DND_TEXT)
                self.dnd_bind("<<DropEnter>>", self._on_drop_enter)
                self.dnd_bind("<<DropLeave>>", lambda e: (self.set_zone(self._zone_state), e.action)[1])
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass

        # Tự nhận ảnh QR mới xuất hiện trong clipboard (VD vừa chụp bằng Win+Shift+S)
        self._clip_seq = clipboard_seq()
        self.after(700, self._watch_clipboard)

        self.update_idletasks()
        x = master.winfo_rootx() + (master.winfo_width() - self.winfo_width()) // 2
        y = master.winfo_rooty() + 60
        y = min(y, self.winfo_screenheight() - self.winfo_height() - 60)
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.update_preview()
        self.after(150, self._focus)

    def _focus(self):
        self.lift()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        (self.secret_entry if self.name_entry.get() else self.name_entry).focus_set()

    def _option(self, parent, col, label, values, value):
        box = ctk.CTkFrame(parent, fg_color="transparent")
        box.grid(row=0, column=col, sticky="w", padx=(0, 12))
        ctk.CTkLabel(box, text=label, font=ctk.CTkFont(FONT, 12), text_color=MUTED, anchor="w").pack(fill="x")
        om = ctk.CTkOptionMenu(box, values=values, width=110, height=34, corner_radius=8,
                               font=ctk.CTkFont(FONT, 13), fg_color=SECONDARY, button_color=SECONDARY,
                               button_hover_color=SECONDARY_HOVER, text_color=TEXT,
                               dropdown_font=ctk.CTkFont(FONT, 13))
        om.set(value if value in values else values[0])
        om.pack()
        return om

    # -- QR -------------------------------------------------------------
    def _on_paste(self, _e):
        # Chỉ xử lý khi clipboard là ảnh; nếu là chữ thì để ô nhập dán bình thường
        img = safe_clipboard_image()
        if img is not None:
            self.handle_sources([img], [], "clipboard")
            return "break"

    def qr_from_clipboard(self):
        img = safe_clipboard_image()
        if img is not None:
            self.handle_sources([img], [], "clipboard")
            return
        # Không có ảnh: thử dán chữ (link otpauth:// hoặc secret key)
        try:
            text = self.clipboard_get().strip()
        except tk.TclError:
            text = ""
        if text.lower().startswith("otpauth"):
            self.handle_sources([], [text], "clipboard")
            return
        if text and looks_like_secret(text):
            self.secret_entry.delete(0, "end")
            self.secret_entry.insert(0, text)
            self.update_preview()
            return
        self.show_error(tr("Clipboard chưa có ảnh QR. Bấm Win+Shift+S chụp vùng QR (hoặc chuột phải ảnh QR → "
                        "Copy image) — app sẽ tự nhận, không cần bấm Dán."))

    def _watch_clipboard(self):
        if not self.winfo_exists():
            return
        seq = clipboard_seq()
        if seq != self._clip_seq:
            self._clip_seq = seq
            img = safe_clipboard_image()
            if img is not None:
                try:
                    texts = decode_qr(img)
                except Exception:
                    texts = []
                if any(t.lower().startswith("otpauth") for t in texts):
                    self.handle_sources([img], [], "auto")
                    if not self.winfo_exists():
                        return
        self.after(600, self._watch_clipboard)

    # -- Kéo thả ---------------------------------------------------------
    def _on_drop_enter(self, e):
        self.set_zone("drag")
        return e.action

    def _on_drop(self, e):
        self.set_zone(self._zone_state)
        images, texts, err = read_drop(self, e.data)
        if err:
            self.show_error(err)
        else:
            self.handle_sources(images, texts, "drop")
        return e.action

    # -- Vùng hiển thị QR ------------------------------------------------
    def set_zone(self, state, name="", thumb=None, note=""):
        if state != "drag":
            self._zone_state = state
        if state == "drag":
            self.zone.configure(border_color=ACCENT, fg_color=ACCENT_SOFT)
            self.zone_title.configure(text=tr("Thả ảnh vào đây"), text_color=ACCENT)
            self.zone_sub.configure(text=tr("Thả file ảnh có mã QR để đọc"))
            return
        if state == "ok":
            self.zone.configure(border_color=OK, fg_color=ZONE)
            if thumb is not None:
                self._thumb = thumb_image(thumb, 60)
                self.zone_icon.configure(image=self._thumb)
            self.zone_title.configure(text=f"✓  {ellipsize(name, 30)}", text_color=OK)
            self.zone_sub.configure(text=note or tr("Đã đọc mã QR và điền secret key"))
            return
        self.zone.configure(border_color=BORDER, fg_color=ZONE)
        self.zone_icon.configure(image=self._glyph)
        self.zone_title.configure(text=tr("Kéo thả ảnh QR vào đây"), text_color=TEXT)
        self.zone_sub.configure(text=tr("hoặc bấm để chọn file  •  Ctrl+V để dán  •  ảnh chụp bằng "
                                     "Win+Shift+S sẽ được tự nhận"))

    def qr_from_file(self):
        paths = filedialog.askopenfilenames(parent=self, title=tr("Chọn ảnh mã QR"), filetypes=image_types())
        if not paths:
            return
        images, errors = open_images(paths)
        if not images:
            self.show_error(errors[0])
            return
        self.handle_sources(images, [], "file")

    def qr_from_screen(self):
        def done(result):
            if result:
                texts, thumb = result
                self.apply_qr_texts(texts, thumb, "screen")
        pick_from_screen(self, done, self.show_error)

    def apply_qr_image(self, img, source="clipboard"):
        self.handle_sources([img], [], source)

    def handle_sources(self, images, texts, source):
        all_texts, thumb = list(texts), None
        for img in images:
            found = scan_qr(img)
            all_texts += [t for t, _ in found]
            best = next((b for t, b in found if t.lower().startswith("otpauth")), None)
            if thumb is None and best:
                thumb = crop_qr(img.convert("RGB"), best)
        self.apply_qr_texts(all_texts, thumb, source)

    def apply_qr_texts(self, texts, thumb, source):
        # QR xuất từ Google Authenticator (nhiều tài khoản) -> chuyển sang màn hình nhập hàng loạt
        if any(t.lower().startswith("otpauth-migration://") for t in texts):
            app = self.master
            try:
                self.grab_release()
            except tk.TclError:
                pass
            self.destroy()
            app.open_import(texts, source)
            return
        try:
            acc = account_from_qr(texts)
        except ValueError as e:
            self.show_error(str(e))
            return
        notes = {
            "auto": tr("Tự nhận từ ảnh vừa chụp / copy"),
            "screen": tr("Đã đọc từ vùng chọn trên màn hình"),
            "drop": tr("Đã đọc từ ảnh vừa thả vào"),
            "file": tr("Đã đọc từ file ảnh"),
            "clipboard": tr("Đã đọc từ ảnh trong clipboard"),
        }
        self.set_zone("ok", acc["name"], thumb, notes.get(source, ""))
        self.secret_entry.delete(0, "end")
        self.secret_entry.insert(0, acc["secret"])
        if not self.name_entry.get().strip():
            self.name_entry.insert(0, acc["name"])
        self.digits.set(str(acc["digits"]))
        self.period.set(str(acc["period"]))
        self.algo.set(acc["algorithm"])
        if (acc["digits"], acc["period"], acc["algorithm"]) != (6, 30, "SHA1") and not self.adv_open:
            self.toggle_adv()
        self.update_preview()
        code = fmt_code(totp(acc["secret"], acc["digits"], acc["period"], acc["algorithm"]))
        self.preview.configure(text=tr("✓  Đã đọc QR — mã hiện tại: {code}", code=code), text_color=OK)

    def show_error(self, msg):
        self.preview.configure(text=f"✕  {msg}", text_color=WARN)

    def toggle_adv(self):
        self.adv_open = not self.adv_open
        if self.adv_open:
            self.adv.pack(fill="x", pady=(4, 0), before=self.adv_anchor)
            self.adv_btn.configure(text=tr("Tuỳ chọn nâng cao  ▾"))
        else:
            self.adv.pack_forget()
            self.adv_btn.configure(text=tr("Tuỳ chọn nâng cao  ▸"))

    def gather(self) -> dict:
        secret = self.secret_entry.get().strip()
        name = self.name_entry.get().strip()
        if secret.lower().startswith("otpauth://"):
            acc = parse_otpauth(secret)
            if name:
                acc["name"] = name
        else:
            acc = {
                "name": name,
                "secret": secret.replace(" ", "").upper(),
                "digits": int(self.digits.get()),
                "period": int(self.period.get()),
                "algorithm": self.algo.get(),
            }
        totp(acc["secret"], acc["digits"], acc["period"], acc["algorithm"])
        return acc

    def update_preview(self):
        raw = self.secret_entry.get().strip()
        if not raw:
            self.preview.configure(text=" ")
            return
        try:
            acc = self.gather()
        except ValueError as e:
            self.preview.configure(text=f"✕  {e}", text_color=WARN)
            return
        if raw.lower().startswith("otpauth://") and not self.name_entry.get().strip():
            self.name_entry.insert(0, acc["name"])
        code = fmt_code(totp(acc["secret"], acc["digits"], acc["period"], acc["algorithm"]))
        self.preview.configure(text=tr("✓  Hợp lệ — mã hiện tại: {code}", code=code), text_color=OK)

    def save(self):
        try:
            acc = self.gather()
            if not acc["name"]:
                raise ValueError(tr("Vui lòng nhập tên hiển thị"))
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e), parent=self)
            return
        self.on_save(acc)
        self.destroy()


AMBER = ("#b45309", "#fbbf24")


class ImportDialog(ctk.CTkToplevel):
    """Nhập nhiều tài khoản từ QR 'Xuất tài khoản' của Google Authenticator."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title(tr("Nhập từ Google Authenticator"))
        self.configure(fg_color=BG)
        self.transient(app)
        self.after(250, lambda: set_icon(self))

        self.items: list[dict] = []
        self.skipped: list[tuple[str, str]] = []
        self.batches: dict = {}
        self._seen_secrets: set[str] = set()
        self._existing = {norm_secret(a["secret"]) for a in app.accounts}
        self._rows: list = []

        f13 = ctk.CTkFont(FONT, 13)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=20)

        ctk.CTkLabel(body, text=tr("Nhập từ Google Authenticator"), font=ctk.CTkFont(FONT, 20, "bold"),
                     text_color=TEXT, anchor="w").pack(fill="x")
        ctk.CTkLabel(body, text=tr("Chuyển nhiều tài khoản cùng lúc bằng mã QR \"Xuất tài khoản\""),
                     font=f13, text_color=MUTED, anchor="w").pack(fill="x", pady=(0, 12))

        guide = ctk.CTkFrame(body, fg_color=ZONE, corner_radius=12, border_width=1, border_color=BORDER)
        guide.pack(fill="x")
        steps = [
            tr("Trên điện thoại: Google Authenticator → ☰ → Chuyển tài khoản → Xuất tài khoản"),
            tr("Chọn tài khoản cần chuyển → app hiện mã QR (nhiều tài khoản sẽ có nhiều QR, "
            "bấm \"Tiếp theo\" để xem QR kế)"),
            tr("Chụp màn hình QR rồi bấm \"Dán\" (Ctrl+V), hoặc chọn \"File ảnh\" / kéo thả ảnh vào đây. "
               "Một số máy Android có thể chặn chụp màn hình trang này — khi đó hãy chụp ảnh QR bằng máy khác"),
        ]
        for i, s in enumerate(steps, 1):
            row = ctk.CTkFrame(guide, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=(10 if i == 1 else 2, 10 if i == len(steps) else 2))
            ctk.CTkLabel(row, text=str(i), width=22, height=22, corner_radius=11, fg_color=ACCENT_SOFT,
                         text_color=ACCENT, font=ctk.CTkFont(FONT, 12, "bold")).pack(side="left", anchor="n",
                                                                                    pady=(1, 0))
            ctk.CTkLabel(row, text=s, font=ctk.CTkFont(FONT, 12), text_color=TEXT, anchor="w", justify="left",
                         wraplength=400).pack(side="left", fill="x", padx=(10, 0))

        src = ctk.CTkFrame(body, fg_color="transparent")
        src.pack(fill="x", pady=(12, 0))
        src.columnconfigure(0, weight=2, uniform="s")
        src.columnconfigure((1, 2), weight=1, uniform="s")
        ctk.CTkButton(src, text=tr("🖼  File ảnh"), height=40, width=10, corner_radius=10,
                      font=ctk.CTkFont(FONT, 13, "bold"), fg_color=ACCENT_SOFT, hover_color=ACCENT_SOFT_HOVER,
                      text_color=ACCENT, command=self.from_file).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(src, text=tr("✂  Chọn vùng"), height=40, width=10, corner_radius=10, font=f13,
                      fg_color=SECONDARY, hover_color=SECONDARY_HOVER, text_color=TEXT,
                      command=self.from_screen).grid(row=0, column=1, sticky="ew", padx=4)
        ctk.CTkButton(src, text=tr("📋  Dán"), height=40, width=10, corner_radius=10, font=f13,
                      fg_color=SECONDARY, hover_color=SECONDARY_HOVER, text_color=TEXT,
                      command=self.from_clipboard).grid(row=0, column=2, sticky="ew", padx=(4, 0))

        self.status = ctk.CTkLabel(body, text=" ", font=f13, anchor="w", justify="left", wraplength=440,
                                   text_color=MUTED)
        self.status.pack(fill="x", pady=(10, 4))

        head = ctk.CTkFrame(body, fg_color="transparent")
        head.pack(fill="x", pady=(0, 4))
        self.all_var = tk.BooleanVar(value=True)
        self.all_cb = ctk.CTkCheckBox(head, text=tr("Chọn tất cả"), variable=self.all_var, command=self.toggle_all,
                                      font=f13, text_color=TEXT, checkbox_width=20, checkbox_height=20,
                                      corner_radius=6, fg_color=ACCENT, hover_color=ACCENT_HOVER)
        self.all_cb.pack(side="left", padx=(4, 0))
        self.count_lbl = ctk.CTkLabel(head, text="", font=f13, text_color=MUTED)
        self.count_lbl.pack(side="right")

        self.list = ctk.CTkScrollableFrame(body, height=220, fg_color=CARD, corner_radius=12, border_width=1,
                                           border_color=BORDER, scrollbar_button_color=SECONDARY,
                                           scrollbar_button_hover_color=SECONDARY_HOVER)
        self.list.pack(fill="both", expand=True)
        self.empty = ctk.CTkLabel(self.list, text=tr("Chưa có tài khoản nào.\nHãy đưa mã QR xuất từ Google "
                                                  "Authenticator vào bằng các nút ở trên."),
                                  font=f13, text_color=MUTED, justify="center")

        ctk.CTkLabel(body, text=tr("🔒  Nhập xong hãy xoá ảnh QR khỏi điện thoại và máy tính — ảnh đó chứa "
                                "toàn bộ mã 2FA của bạn."), font=ctk.CTkFont(FONT, 12), text_color=MUTED,
                     anchor="w", justify="left", wraplength=440).pack(fill="x", pady=(8, 0))

        btns = ctk.CTkFrame(body, fg_color="transparent")
        btns.pack(fill="x", pady=(12, 0))
        btns.columnconfigure((0, 1), weight=1, uniform="b")
        ctk.CTkButton(btns, text=tr("Huỷ"), height=42, width=10, corner_radius=10, font=ctk.CTkFont(FONT, 14),
                      fg_color=SECONDARY, hover_color=SECONDARY_HOVER, text_color=TEXT,
                      command=self.destroy).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.import_btn = ctk.CTkButton(btns, text=tr("Nhập"), height=42, width=10, corner_radius=10,
                                        font=ctk.CTkFont(FONT, 14, "bold"), fg_color=ACCENT,
                                        hover_color=ACCENT_HOVER, command=self.do_import)
        self.import_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Control-v>", self._on_paste)
        self.bind("<Control-V>", self._on_paste)
        if getattr(app, "dnd_ok", False):
            try:
                self.drop_target_register(DND_FILES, DND_TEXT)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass
        self._clip_seq = clipboard_seq()
        self.after(700, self._watch_clipboard)

        self.render()
        self.update_idletasks()
        x = app.winfo_rootx() + (app.winfo_width() - self.winfo_width()) // 2
        y = min(app.winfo_rooty() + 30, self.winfo_screenheight() - self.winfo_height() - 60)
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.after(150, self._focus)
        self.after(1000, self._tick)

    def _focus(self):
        self.lift()
        self.focus_force()
        try:
            self.grab_set()
        except tk.TclError:
            pass

    # -- nguồn QR -------------------------------------------------------
    def from_file(self):
        paths = filedialog.askopenfilenames(parent=self, title=tr("Chọn ảnh QR xuất từ Google Authenticator"),
                                            filetypes=image_types())
        if not paths:
            return
        images, errors = open_images(paths)
        if errors and not images:
            self.set_status("✕  " + errors[0], WARN)
            return
        self.add_images(images, "file")

    def from_screen(self):
        pick_from_screen(self, lambda r: r and self.add_texts(r[0], "screen"),
                         lambda msg: self.set_status("✕  " + msg, WARN))

    def from_clipboard(self):
        img = safe_clipboard_image()
        if img is not None:
            self.add_images([img], "clipboard")
            return
        try:
            text = self.clipboard_get().strip()
        except tk.TclError:
            text = ""
        if text.lower().startswith("otpauth"):
            self.add_texts([text], "clipboard")
        else:
            self.set_status(tr("✕  Clipboard chưa có ảnh QR."), WARN)

    def _on_paste(self, _e):
        self.from_clipboard()
        return "break"

    def _on_drop(self, e):
        images, texts, err = read_drop(self, e.data)
        if err:
            self.set_status("✕  " + err, WARN)
        else:
            self.add_images(images, "drop", texts)
        return e.action

    def _watch_clipboard(self):
        if not self.winfo_exists():
            return
        seq = clipboard_seq()
        if seq != self._clip_seq:
            self._clip_seq = seq
            img = safe_clipboard_image()
            if img is not None:
                texts = decode_qr(img)
                if any(t.lower().startswith("otpauth") for t in texts):
                    self.add_texts(texts, "auto")
        self.after(600, self._watch_clipboard)

    # -- xử lý ----------------------------------------------------------
    def add_images(self, images, source, texts=None):
        texts = list(texts or [])
        failed = 0
        for img in images:
            found = decode_qr(img)
            if not found:
                failed += 1
            texts += found
        self.add_texts(texts, source, failed)

    def add_texts(self, texts, source, failed_images=0):
        migr = [t for t in texts if t.lower().startswith("otpauth-migration://")]
        singles = [t for t in texts if t.lower().startswith("otpauth://totp")]
        if not migr and not singles:
            if source != "auto":
                msg = (tr("Không tìm thấy mã QR nào trong ảnh. Hãy chụp lại rõ nét, đủ sáng, thấy trọn mã QR.")
                       if not texts else tr("QR này không phải mã xuất từ Google Authenticator."))
                self.set_status("✕  " + msg, WARN)
            return
        added, errors = 0, []
        for t in migr:
            try:
                r = parse_migration(t)
            except ValueError as e:
                errors.append(str(e))
                continue
            b = self.batches.setdefault(r["batch_id"], {"size": r["batch_size"], "seen": set()})
            b["seen"].add(r["batch_index"])
            for acc in r["accounts"]:
                added += self._add(acc)
            for s in r["skipped"]:
                if s not in self.skipped:
                    self.skipped.append(s)
        for t in singles:
            try:
                added += self._add(parse_otpauth(t))
            except ValueError as e:
                errors.append(str(e))
        self.render()

        parts, color = [], OK
        missing_all = []
        for b in self.batches.values():
            if b["size"] > 1:
                missing = [i + 1 for i in range(b["size"]) if i not in b["seen"]]
                missing_all += missing
        if added:
            parts.append(tr("✓  Đọc thêm {n} tài khoản.", n=added))
        else:
            parts.append(tr("Các tài khoản trong QR này đã có trong danh sách."))
            color = MUTED
        if missing_all:
            parts.append(tr("Còn thiếu QR số {nums} — bấm \"Tiếp theo\" trên điện thoại và đưa QR đó vào.",
                            nums=", ".join(map(str, missing_all))))
            color = AMBER
        elif any(b["size"] > 1 for b in self.batches.values()):
            parts.append(tr("Đã đọc đủ tất cả mã QR."))
        if failed_images:
            parts.append(tr("{n} ảnh không đọc được QR.", n=failed_images))
            color = AMBER
        if errors:
            parts.append(errors[0])
            color = WARN
        self.set_status("  ".join(parts), color)

    def _add(self, acc) -> int:
        key = norm_secret(acc["secret"])
        if key in self._seen_secrets:
            return 0
        self._seen_secrets.add(key)
        dup = key in self._existing
        self.items.append({"acc": acc, "var": tk.BooleanVar(value=not dup), "dup": dup})
        return 1

    def set_status(self, text, color=MUTED):
        self.status.configure(text=text, text_color=color)

    # -- danh sách ------------------------------------------------------
    def render(self):
        for r in self._rows:
            r.destroy()
        self._rows = []
        self.empty.pack_forget()
        if not self.items and not self.skipped:
            self.empty.pack(fill="x", pady=50)
        for it in self.items:
            self._rows.append(self._row(it))
        for name, reason in self.skipped:
            self._rows.append(self._row({"acc": {"name": name}, "skip": reason}))
        self.update_count()
        self.refresh_codes()

    def _row(self, it):
        acc = it["acc"]
        row = ctk.CTkFrame(self.list, fg_color="transparent")
        row.pack(fill="x", padx=4, pady=2)
        row.columnconfigure(2, weight=1)
        skip = it.get("skip")
        if skip:
            ctk.CTkLabel(row, text="", width=28).grid(row=0, column=0, rowspan=2, padx=(8, 4))
        else:
            ctk.CTkCheckBox(row, text="", width=24, variable=it["var"], command=self.update_count,
                            checkbox_width=22, checkbox_height=22, corner_radius=6, fg_color=ACCENT,
                            hover_color=ACCENT_HOVER).grid(row=0, column=0, rowspan=2, padx=(8, 4))
        color = "#9ca3af" if skip else avatar_color(acc["name"])
        av = ctk.CTkLabel(row, text=(acc["name"][:1] or "?").upper(), image=circle_image(color, 34),
                          compound="center", text_color="#ffffff", font=ctk.CTkFont(FONT, 14, "bold"))
        av.grid(row=0, column=1, rowspan=2, padx=(0, 10), pady=6)
        name = ctk.CTkLabel(row, text=ellipsize(acc["name"], 34), font=ctk.CTkFont(FONT, 14),
                            text_color=MUTED if skip else TEXT, anchor="w", height=20)
        name.grid(row=0, column=2, sticky="sw")
        if skip:
            sub_text, sub_color = skip, WARN
        elif it["dup"]:
            sub_text, sub_color = tr("Đã có trong app — bỏ chọn sẵn để tránh trùng"), AMBER
        else:
            extra = [] if (acc["digits"], acc["algorithm"]) == (6, "SHA1") else [tr("{n} số", n=acc["digits"]),
                                                                              acc["algorithm"]]
            sub_text, sub_color = "  •  ".join(["TOTP"] + extra), MUTED
        ctk.CTkLabel(row, text=sub_text, font=ctk.CTkFont(FONT, 12), text_color=sub_color, anchor="w",
                     height=16).grid(row=1, column=2, sticky="nw")
        if not skip:
            it["code_lbl"] = ctk.CTkLabel(row, text="", font=ctk.CTkFont(FONT, 17, "bold"), text_color=ACCENT)
            it["code_lbl"].grid(row=0, column=3, rowspan=2, padx=(8, 12))
            for w in (row, av, name):
                w.bind("<Button-1>", lambda e, v=it["var"]: (v.set(not v.get()), self.update_count()))
        return row

    def refresh_codes(self):
        now = time.time()
        for it in self.items:
            lbl = it.get("code_lbl")
            if lbl is not None:
                a = it["acc"]
                try:
                    lbl.configure(text=fmt_code(totp(a["secret"], a["digits"], a["period"], a["algorithm"], now)))
                except Exception:
                    lbl.configure(text=tr("lỗi"))

    def _tick(self):
        if not self.winfo_exists():
            return
        self.refresh_codes()
        self.after(1000, self._tick)

    def update_count(self):
        n = sum(1 for it in self.items if it["var"].get())
        self.import_btn.configure(text=tr("Nhập {n} tài khoản", n=n) if n else tr("Nhập"),
                                  state="normal" if n else "disabled")
        self.all_var.set(bool(self.items) and n == len(self.items))
        self.count_lbl.configure(text=tr("Đã chọn {n}/{total}", n=n, total=len(self.items)) if self.items else "")

    def toggle_all(self):
        v = self.all_var.get()
        for it in self.items:
            it["var"].set(v)
        self.update_count()

    def do_import(self):
        selected = [it["acc"] for it in self.items if it["var"].get()]
        if not selected:
            return
        self.app.import_accounts(selected)
        self.destroy()


class AccountCard(ctk.CTkFrame):
    RING = 46

    def __init__(self, master, app, acc):
        super().__init__(master, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
        self.app = app
        self.acc = acc
        self.copied_until = 0.0

        self.columnconfigure(1, weight=1)
        self.avatar = ctk.CTkLabel(self, text=(acc["name"][:1] or "?").upper(), image=circle_image(avatar_color(acc["name"])),
                                   compound="center", fg_color="transparent", text_color="#ffffff",
                                   font=ctk.CTkFont(FONT, 18, "bold"))
        self.avatar.grid(row=0, column=0, rowspan=2, padx=(16, 14), pady=14)

        self.name = ctk.CTkLabel(self, text=ellipsize(acc["name"]), font=ctk.CTkFont(FONT, 14),
                                 text_color=MUTED, anchor="w", height=20)
        self.name.grid(row=0, column=1, sticky="sw", pady=(14, 0))
        self.code = ctk.CTkLabel(self, text="", font=ctk.CTkFont(FONT, 30, "bold"), text_color=ACCENT,
                                 anchor="w", height=40)
        self.code.grid(row=1, column=1, sticky="nw", pady=(0, 12))

        try:
            s = self._get_widget_scaling()
        except Exception:
            s = 1.0
        self.scale = s
        size = int(self.RING * s)
        self.ring = tk.Canvas(self, width=size, height=size, highlightthickness=0, bd=0, bg=pick(CARD))
        self.ring.grid(row=0, column=2, rowspan=2, padx=(8, 4))

        self.more = ctk.CTkButton(self, text="⋮", width=32, height=32, corner_radius=8,
                                  font=ctk.CTkFont(FONT, 18, "bold"), fg_color="transparent",
                                  hover_color=SECONDARY, text_color=MUTED, command=self.show_menu)
        self.more.grid(row=0, column=3, rowspan=2, padx=(0, 10))

        self.menu = tk.Menu(self, tearoff=0, font=(FONT, 10))
        self.menu.add_command(label=tr("  Copy mã"), command=lambda: app.copy(self))
        self.menu.add_command(label=tr("  Sửa"), command=lambda: app.edit(acc))
        self.menu.add_command(label=tr("  Lên trên"), command=lambda: app.move(acc, -1))
        self.menu.add_command(label=tr("  Xuống dưới"), command=lambda: app.move(acc, 1))
        self.menu.add_separator()
        self.menu.add_command(label=tr("  Xoá"), command=lambda: app.delete(acc))

        for w in (self, self.avatar, self.name, self.code, self.ring):
            w.bind("<Button-1>", lambda e: app.copy(self))
            w.bind("<Button-3>", lambda e: self.menu.tk_popup(e.x_root, e.y_root))
            w.bind("<Enter>", lambda e: self.hover(True))
            w.bind("<Leave>", self._on_leave)
            try:
                w.configure(cursor="hand2")
            except Exception:
                pass

    def show_menu(self):
        self.menu.tk_popup(self.more.winfo_rootx(), self.more.winfo_rooty() + self.more.winfo_height())

    def _on_leave(self, _e):
        x, y = self.winfo_pointerxy()
        w = self.winfo_containing(x, y)
        while w is not None:
            if w is self:
                return
            w = w.master
        self.hover(False)

    def hover(self, on: bool):
        color = CARD_HOVER if on else CARD
        if self.cget("fg_color") != color:
            self.configure(fg_color=color)
            self.ring.configure(bg=pick(color))

    def mark_copied(self):
        self.copied_until = time.time() + 1.2
        self.code.configure(text=tr("Đã copy ✓"), text_color=OK)

    def refresh(self, now: float):
        a = self.acc
        period = a["period"]
        left = period - int(now) % period
        warn = left <= 5
        if now >= self.copied_until:
            try:
                text = fmt_code(totp(a["secret"], a["digits"], period, a["algorithm"], now))
            except Exception:
                text = tr("lỗi key")
            self.code.configure(text=text, text_color=WARN if warn else ACCENT)

        c = self.ring
        c.configure(bg=pick(CARD_HOVER if self.cget("fg_color") == CARD_HOVER else CARD))
        c.delete("all")
        s = self.scale
        size = int(self.RING * s)
        pad = 4 * s
        width = 4 * s
        c.create_oval(pad, pad, size - pad, size - pad, outline=pick(TRACK), width=width)
        extent = 359.9 * left / period
        c.create_arc(pad, pad, size - pad, size - pad, start=90, extent=extent, style="arc",
                     outline=pick(WARN if warn else ACCENT), width=width)
        c.create_text(size / 2, size / 2, text=str(left), fill=pick(WARN if warn else MUTED),
                      font=(FONT, -int(14 * s), "bold"))


class App(ctk.CTk, _DnDBase):
    def __init__(self):
        self.settings = load_settings()
        ctk.set_appearance_mode(self.settings.get("appearance", "System"))
        super().__init__(fg_color=BG)
        self.title(APP_NAME)
        self.geometry(self.settings.get("geometry", "480x680"))
        self.minsize(400, 420)
        set_icon(self)
        try:
            TkinterDnD._require(self)
            self.dnd_ok = True
            self.drop_target_register(DND_FILES, DND_TEXT)
            self.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:
            self.dnd_ok = False

        try:
            self.accounts = load_accounts()
        except Exception as e:
            messagebox.showerror(APP_NAME, tr("Không đọc được dữ liệu:\n{err}", err=e))
            self.accounts = []
        self.cards: list[AccountCard] = []
        set_lang(self.settings.get("lang", "vi"))

        self.build_ui()
        self.bind("<Control-f>", lambda e: self.search.focus_set())
        self.bind("<Control-n>", lambda e: self.add())
        self.bind("<Control-v>", self._on_paste)
        self.bind("<Control-V>", self._on_paste)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.rebuild()
        self.tick()

    def build_ui(self):
        """Dựng toàn bộ giao diện (gọi lại khi đổi ngôn ngữ)."""
        # --- Header ---
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(18, 0))
        titles = ctk.CTkFrame(header, fg_color="transparent")
        titles.pack(side="left")
        ctk.CTkLabel(titles, text="2FA Code", font=ctk.CTkFont(FONT, 24, "bold"),
                     text_color=TEXT, anchor="w", height=30).pack(anchor="w")
        self.count_label = ctk.CTkLabel(titles, text="", font=ctk.CTkFont(FONT, 13),
                                        text_color=MUTED, anchor="w", height=18)
        self.count_label.pack(anchor="w")
        ctk.CTkButton(header, text=tr("＋  Thêm"), height=42, width=110, corner_radius=12,
                      font=ctk.CTkFont(FONT, 14, "bold"), fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      command=self.add).pack(side="right")
        ctk.CTkButton(header, text=tr("⇩  Google Auth"), height=42, width=10, corner_radius=12,
                      font=ctk.CTkFont(FONT, 13), fg_color=SECONDARY, hover_color=SECONDARY_HOVER,
                      text_color=TEXT, command=self.open_import).pack(side="right", padx=(0, 8))

        # --- Search ---
        self.search = ctk.CTkEntry(self, height=44, corner_radius=12, font=ctk.CTkFont(FONT, 14),
                                   fg_color=INPUT, border_color=BORDER, border_width=1, text_color=TEXT,
                                   placeholder_text=tr("🔍  Tìm tài khoản...  (Enter để copy mã đầu tiên)"))
        self.search.pack(fill="x", padx=20, pady=(16, 8))
        self.search.bind("<KeyRelease>", lambda e: self.apply_filter() if e.keysym != "Return" else None)
        self.search.bind("<Return>", lambda e: self.copy_first())
        self.search.bind("<Escape>", lambda e: (self.search.delete(0, "end"), self.apply_filter(), self.focus()))

        # --- List ---
        self.list = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0,
                                           scrollbar_button_color=SECONDARY,
                                           scrollbar_button_hover_color=SECONDARY_HOVER)
        self.list.pack(fill="both", expand=True, padx=(12, 6), pady=(4, 0))

        self.empty = ctk.CTkFrame(self.list, fg_color="transparent")
        ctk.CTkLabel(self.empty, text="🔐", font=ctk.CTkFont(FONT, 48)).pack(pady=(50, 6))
        self.empty_title = ctk.CTkLabel(self.empty, text="", font=ctk.CTkFont(FONT, 16, "bold"), text_color=TEXT)
        self.empty_title.pack()
        self.empty_sub = ctk.CTkLabel(self.empty, text="", font=ctk.CTkFont(FONT, 13), text_color=MUTED)
        self.empty_sub.pack(pady=(2, 14))
        self.empty_btn = ctk.CTkButton(self.empty, text=tr("＋  Thêm tài khoản đầu tiên"), height=40, corner_radius=10,
                                       font=ctk.CTkFont(FONT, 14, "bold"), fg_color=ACCENT,
                                       hover_color=ACCENT_HOVER, command=self.add)
        self.empty_btn2 = ctk.CTkButton(self.empty, text=tr("⇩  Nhập từ Google Authenticator"), height=40,
                                        corner_radius=10, font=ctk.CTkFont(FONT, 14), fg_color=SECONDARY,
                                        hover_color=SECONDARY_HOVER, text_color=TEXT, command=self.open_import)

        # --- Footer ---
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=20, pady=(6, 14))
        seg = dict(height=32, font=ctk.CTkFont(FONT, 12), selected_color=CARD, selected_hover_color=CARD,
                   unselected_color=SECONDARY, unselected_hover_color=SECONDARY_HOVER, fg_color=SECONDARY,
                   text_color=TEXT, corner_radius=8)
        self._mode_map = {tr(label): code for code, label in APPEARANCE_MODES}
        self.mode = ctk.CTkSegmentedButton(footer, values=list(self._mode_map), command=self.set_mode, **seg)
        current = self.settings.get("appearance", "System")
        self.mode.set(next((k for k, v in self._mode_map.items() if v == current), list(self._mode_map)[0]))
        self.mode.pack(side="left")
        self.lang = ctk.CTkSegmentedButton(footer, values=["VI", "EN"], command=self.set_language, **seg)
        self.lang.set(get_lang().upper())
        self.lang.pack(side="right")
        ctk.CTkLabel(footer, text="🌐", font=ctk.CTkFont(FONT, 14), text_color=MUTED).pack(side="right",
                                                                                           padx=(0, 6))

        # Toast thông báo
        self.toast = ctk.CTkLabel(self, text="", height=36, corner_radius=10, font=ctk.CTkFont(FONT, 13),
                                  fg_color=("#111827", "#f3f4f6"), text_color=("#ffffff", "#111827"))
        self._toast_job = None

    # -- helpers ---------------------------------------------------------
    def show_toast(self, text):
        self.toast.configure(text=f"   {text}   ")
        self.toast.place(relx=0.5, rely=1.0, y=-66, anchor="s")
        self.toast.lift()
        if self._toast_job:
            self.after_cancel(self._toast_job)
        self._toast_job = self.after(1600, self.toast.place_forget)

    def persist(self):
        try:
            save_accounts(self.accounts)
        except Exception as e:
            messagebox.showerror(APP_NAME, tr("Không lưu được dữ liệu:\n{err}", err=e))

    def set_mode(self, label):
        mode = self._mode_map[label]
        ctk.set_appearance_mode(mode)
        self.settings["appearance"] = mode
        save_settings(self.settings)
        self.after(50, self.update_codes)

    def set_language(self, label):
        code = label.lower()
        if code == get_lang():
            return
        set_lang(code)
        self.settings["lang"] = code
        self.settings.pop("topmost", None)
        save_settings(self.settings)
        query = self.search.get()
        for w in self.winfo_children():  # đóng cả các hộp thoại đang mở
            w.destroy()
        self.cards = []
        self.build_ui()
        if query:
            self.search.insert(0, query)
        self.rebuild()

    def on_close(self):
        self.settings["geometry"] = self.geometry()
        save_settings(self.settings)
        self.destroy()

    # -- actions ---------------------------------------------------------
    def add(self):
        def on_save(acc):
            self.accounts.append(acc)
            self.persist()
            self.rebuild()
            self.show_toast(tr("Đã thêm {name}", name=ellipsize(acc["name"], 28)))
        return AccountDialog(self, on_save)

    def _on_paste(self, _e):
        """Ctrl+V ảnh QR ở cửa sổ chính -> mở hộp thoại thêm và điền sẵn."""
        img = safe_clipboard_image()
        if img is None:
            return None  # clipboard là chữ -> dán vào ô tìm kiếm như bình thường
        self.add().apply_qr_image(img, source="clipboard")
        return "break"

    def _on_drop(self, e):
        dlg = self.add()
        dlg.after(50, lambda: dlg._on_drop(e))
        return e.action

    def open_import(self, texts=None, source=""):
        dlg = ImportDialog(self)
        if texts:
            dlg.add_texts(texts, source)
        return dlg

    def import_accounts(self, accounts):
        self.accounts.extend(accounts)
        self.persist()
        self.rebuild()
        self.show_toast(tr("Đã nhập {n} tài khoản", n=len(accounts)))

    def edit(self, acc):
        def on_save(new):
            acc.clear()
            acc.update(new)
            self.persist()
            self.rebuild()
            self.show_toast(tr("Đã lưu thay đổi"))
        AccountDialog(self, on_save, acc)

    def delete(self, acc):
        if messagebox.askyesno(APP_NAME, tr("Xoá '{name}'?\n\nHãy chắc là bạn còn cách khác để đăng nhập!", name=acc["name"]),
                               icon="warning"):
            self.accounts.remove(acc)
            self.persist()
            self.rebuild()
            self.show_toast(tr("Đã xoá"))

    def move(self, acc, step):
        i = self.accounts.index(acc)
        j = i + step
        if 0 <= j < len(self.accounts):
            self.accounts[i], self.accounts[j] = self.accounts[j], self.accounts[i]
            self.persist()
            self.rebuild()

    def copy(self, card: AccountCard):
        a = card.acc
        code = totp(a["secret"], a["digits"], a["period"], a["algorithm"])
        self.clipboard_clear()
        self.clipboard_append(code)
        card.mark_copied()
        self.show_toast(tr("Đã copy mã {name}", name=ellipsize(a["name"], 24)))

    def copy_first(self):
        visible = [c for c in self.cards if c.winfo_manager()]
        if visible:
            self.copy(visible[0])

    # -- render ----------------------------------------------------------
    def rebuild(self):
        for c in self.cards:
            c.destroy()
        self.cards = [AccountCard(self.list, self, acc) for acc in self.accounts]
        n = len(self.accounts)
        self.count_label.configure(text=tr("{n} tài khoản", n=n) if n else tr("Chưa có tài khoản"))
        self.apply_filter()
        self.update_codes()

    def apply_filter(self):
        q = self.search.get().strip().lower()
        shown = 0
        for c in self.cards:
            c.pack_forget()
        self.empty.pack_forget()
        for c in self.cards:
            if q in c.acc["name"].lower():
                c.pack(fill="x", padx=(8, 8), pady=6)
                shown += 1
        if shown == 0:
            if self.accounts:
                self.empty_title.configure(text=tr("Không tìm thấy"))
                self.empty_sub.configure(text=tr("Không có tài khoản nào khớp \"{q}\"", q=q))
                self.empty_btn.pack_forget()
                self.empty_btn2.pack_forget()
            else:
                self.empty_title.configure(text=tr("Chưa có tài khoản nào"))
                self.empty_sub.configure(text=tr("Thêm secret key để bắt đầu lấy mã 2FA"))
                self.empty_btn.pack()
                self.empty_btn2.pack(pady=(8, 0))
            self.empty.pack(fill="x")

    def update_codes(self):
        now = time.time()
        for c in self.cards:
            c.refresh(now)

    def tick(self):
        self.update_codes()
        self.after(1000 - int(time.time() * 1000) % 1000 + 5, self.tick)


if __name__ == "__main__":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass
    App().mainloop()
