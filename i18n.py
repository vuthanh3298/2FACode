"""Đa ngôn ngữ (VI / EN) cho 2FA Code.

Chuỗi tiếng Việt trong code chính là khoá; EN là bản dịch tương ứng.
Thêm chuỗi mới: bọc bằng tr("...") trong app.py rồi thêm bản dịch vào EN.
Biến trong chuỗi dùng cú pháp {ten} và truyền qua tr("...{ten}...", ten=...).
"""

LANGS = ("vi", "en")
_lang = "vi"


def set_lang(code: str) -> None:
    global _lang
    _lang = code if code in LANGS else "vi"


def get_lang() -> str:
    return _lang


def tr(text: str, **kw) -> str:
    s = EN.get(text, text) if _lang == "en" else text
    return s.format(**kw) if kw else s


EN = {
    # --- Chung ---
    "Huỷ": "Cancel",
    "Lưu": "Save",
    "Nhập": "Import",
    "lỗi": "error",
    "lỗi key": "bad key",
    "Không tên": "Unnamed",
    "Ảnh": "Images",
    "Tất cả": "All files",
    "Hệ thống": "System",
    "Sáng": "Light",
    "Tối": "Dark",

    # --- Cửa sổ chính ---
    "＋  Thêm": "＋  Add",
    "⇩  Google Auth": "⇩  Google Auth",
    "🔍  Tìm tài khoản...  (Enter để copy mã đầu tiên)": "🔍  Search accounts...  (Enter to copy the first code)",
    "{n} tài khoản": "{n} accounts",
    "Chưa có tài khoản": "No accounts yet",
    "Chưa có tài khoản nào": "No accounts yet",
    "Thêm secret key để bắt đầu lấy mã 2FA": "Add a secret key to start getting 2FA codes",
    "＋  Thêm tài khoản đầu tiên": "＋  Add your first account",
    "⇩  Nhập từ Google Authenticator": "⇩  Import from Google Authenticator",
    "Không tìm thấy": "No results",
    "Không có tài khoản nào khớp \"{q}\"": "No accounts match \"{q}\"",
    "Đã copy ✓": "Copied ✓",
    "Đã copy mã {name}": "Copied code for {name}",
    "Đã thêm {name}": "Added {name}",
    "Đã nhập {n} tài khoản": "Imported {n} accounts",
    "Đã lưu thay đổi": "Changes saved",
    "Đã xoá": "Deleted",
    "  Copy mã": "  Copy code",
    "  Sửa": "  Edit",
    "  Lên trên": "  Move up",
    "  Xuống dưới": "  Move down",
    "  Xoá": "  Delete",
    "Xoá '{name}'?\n\nHãy chắc là bạn còn cách khác để đăng nhập!":
        "Delete '{name}'?\n\nMake sure you still have another way to sign in!",
    "Không đọc được dữ liệu:\n{err}": "Could not read data:\n{err}",
    "Không lưu được dữ liệu:\n{err}": "Could not save data:\n{err}",

    # --- Hộp thoại thêm / sửa ---
    "Thêm tài khoản": "Add account",
    "Sửa tài khoản": "Edit account",
    "Nhập secret key do app/web cung cấp khi bật 2FA": "Enter the secret key the app/site gives you when enabling 2FA",
    "Tên hiển thị": "Display name",
    "VD: Gmail công ty, OpenVPN...": "e.g. Work Gmail, OpenVPN...",
    "Secret key (hoặc link otpauth://)": "Secret key (or otpauth:// link)",
    "Hoặc lấy từ mã QR": "Or get it from a QR code",
    "Kéo thả ảnh QR vào đây": "Drop a QR image here",
    "hoặc bấm để chọn file  •  Ctrl+V để dán  •  ảnh chụp bằng Win+Shift+S sẽ được tự nhận":
        "or click to choose a file  •  Ctrl+V to paste  •  Win+Shift+S snips are picked up automatically",
    "Thả ảnh vào đây": "Drop the image here",
    "Thả file ảnh có mã QR để đọc": "Drop an image file containing a QR code",
    "Đã đọc mã QR và điền secret key": "QR code read and secret key filled in",
    "✂  Chọn vùng màn hình": "✂  Select screen area",
    "✂  Chọn vùng": "✂  Select area",
    "📋  Dán": "📋  Paste",
    "🖼  File ảnh": "🖼  Image file",
    "Tuỳ chọn nâng cao  ▸": "Advanced options  ▸",
    "Tuỳ chọn nâng cao  ▾": "Advanced options  ▾",
    "Số chữ số": "Digits",
    "Chu kỳ (giây)": "Period (sec)",
    "Thuật toán": "Algorithm",
    "Chọn ảnh mã QR": "Choose a QR code image",
    "Tự nhận từ ảnh vừa chụp / copy": "Picked up from the image you just snipped / copied",
    "Đã đọc từ vùng chọn trên màn hình": "Read from the selected screen area",
    "Đã đọc từ ảnh vừa thả vào": "Read from the dropped image",
    "Đã đọc từ file ảnh": "Read from the image file",
    "Đã đọc từ ảnh trong clipboard": "Read from the clipboard image",
    "✓  Đã đọc QR — mã hiện tại: {code}": "✓  QR read — current code: {code}",
    "✓  Hợp lệ — mã hiện tại: {code}": "✓  Valid — current code: {code}",
    "Vui lòng nhập tên hiển thị": "Please enter a display name",
    "Clipboard chưa có ảnh QR. Bấm Win+Shift+S chụp vùng QR (hoặc chuột phải ảnh QR → Copy image) — app sẽ tự nhận, không cần bấm Dán.":
        "No QR image in the clipboard. Press Win+Shift+S to snip the QR (or right-click the QR image → "
        "Copy image) — the app picks it up automatically, no need to click Paste.",

    # --- Lỗi secret / QR ---
    "Secret key trống": "Secret key is empty",
    "Secret key không hợp lệ (phải là chuỗi Base32: A-Z, 2-7)": "Invalid secret key (must be Base32: A-Z, 2-7)",
    "Secret key không hợp lệ": "Invalid secret key",
    "Chỉ hỗ trợ link otpauth://totp/...": "Only otpauth://totp/... links are supported",
    "Link không có secret": "The link has no secret",
    "Đây là QR xuất từ Google Authenticator (chuyển nhiều tài khoản) — chưa hỗ trợ. Hãy dùng QR gốc do app/web cung cấp.":
        "This is a Google Authenticator export QR (multiple accounts) — not supported here. "
        "Use the original QR from the app/site.",
    "QR này dùng HOTP (theo bộ đếm), app chỉ hỗ trợ TOTP (theo thời gian).":
        "This QR uses HOTP (counter-based); the app only supports TOTP (time-based).",
    "Đọc được QR nhưng không phải mã 2FA (otpauth://totp).": "QR read, but it is not a 2FA code (otpauth://totp).",
    "Không tìm thấy mã QR nào trong ảnh.": "No QR code found in the image.",
    "Không mở được ảnh {name}: {err}": "Could not open image {name}: {err}",
    "Không chụp được màn hình: {err}": "Could not capture the screen: {err}",
    "Kéo ảnh trực tiếp từ trình duyệt không lấy được file. Hãy dùng \"Chọn vùng màn hình\" hoặc chuột phải ảnh → Copy image.":
        "Dragging an image straight from the browser doesn't provide a file. Use \"Select screen area\" "
        "or right-click the image → Copy image.",
    "Không nhận ra dữ liệu vừa thả. Hãy thả file ảnh chứa mã QR.":
        "Unrecognized drop. Please drop an image file containing a QR code.",

    # --- Chọn vùng màn hình ---
    "Đang tìm mã QR trên màn hình...": "Looking for QR codes on screen...",
    "Click để chọn": "Click to select",
    "Phát hiện {n} mã QR — click vào khung xanh để chọn (Enter)   •   hoặc kéo chuột chọn vùng khác   •   Esc: huỷ":
        "Found {n} QR code(s) — click a green box to select (Enter)   •   or drag to select another area   "
        "•   Esc: cancel",
    "Kéo chuột để chọn vùng có mã QR   •   Esc hoặc chuột phải: huỷ":
        "Drag to select the area with the QR code   •   Esc or right-click: cancel",
    "Không thấy mã QR trong vùng vừa chọn — hãy kéo lại cho bao trọn cả mã QR   •   Esc: huỷ":
        "No QR code in the selected area — drag again to cover the whole QR code   •   Esc: cancel",

    # --- Google Authenticator ---
    "Không phải QR xuất từ Google Authenticator": "Not a Google Authenticator export QR",
    "QR Google Authenticator không có dữ liệu": "The Google Authenticator QR has no data",
    "Dữ liệu QR Google Authenticator bị hỏng": "The Google Authenticator QR data is corrupted",
    "Dữ liệu QR Google Authenticator bị hỏng (ảnh mờ hoặc bị cắt?)":
        "The Google Authenticator QR data is corrupted (blurry or cropped image?)",
    "HOTP (theo bộ đếm) — app chỉ hỗ trợ TOTP": "HOTP (counter-based) — the app only supports TOTP",
    "Định dạng không hỗ trợ": "Unsupported format",
    "Nhập từ Google Authenticator": "Import from Google Authenticator",
    "Chuyển nhiều tài khoản cùng lúc bằng mã QR \"Xuất tài khoản\"":
        "Move many accounts at once using the \"Export accounts\" QR code",
    "Trên điện thoại: Google Authenticator → ☰ → Chuyển tài khoản → Xuất tài khoản":
        "On your phone: Google Authenticator → ☰ → Transfer accounts → Export accounts",
    "Chọn tài khoản cần chuyển → app hiện mã QR (nhiều tài khoản sẽ có nhiều QR, bấm \"Tiếp theo\" để xem QR kế)":
        "Select the accounts to move → the app shows a QR code (many accounts means several QR codes, "
        "tap \"Next\" to see the next one)",
    "Chụp màn hình QR rồi bấm \"Dán\" (Ctrl+V), hoặc chọn \"File ảnh\" / kéo thả ảnh vào đây. Một số máy Android có thể chặn chụp màn hình trang này — khi đó hãy chụp ảnh QR bằng máy khác":
        "Screenshot the QR and click \"Paste\" (Ctrl+V), or use \"Image file\" / drop the image here. "
        "Some Android phones may block screenshots on this screen — if so, take a photo of the QR with "
        "another device",
    "Chọn tất cả": "Select all",
    "Đã chọn {n}/{total}": "Selected {n}/{total}",
    "Nhập {n} tài khoản": "Import {n} accounts",
    "Chưa có tài khoản nào.\nHãy đưa mã QR xuất từ Google Authenticator vào bằng các nút ở trên.":
        "No accounts yet.\nAdd the Google Authenticator export QR using the buttons above.",
    "🔒  Nhập xong hãy xoá ảnh QR khỏi điện thoại và máy tính — ảnh đó chứa toàn bộ mã 2FA của bạn.":
        "🔒  After importing, delete the QR photos from your phone and computer — they contain all your "
        "2FA secrets.",
    "Chọn ảnh QR xuất từ Google Authenticator": "Choose Google Authenticator export QR images",
    "✕  Clipboard chưa có ảnh QR.": "✕  No QR image in the clipboard.",
    "Không tìm thấy mã QR nào trong ảnh. Hãy chụp lại rõ nét, đủ sáng, thấy trọn mã QR.":
        "No QR code found in the image. Retake it sharp, well lit, with the whole QR code visible.",
    "QR này không phải mã xuất từ Google Authenticator.": "This QR is not a Google Authenticator export.",
    "✓  Đọc thêm {n} tài khoản.": "✓  Read {n} more accounts.",
    "Các tài khoản trong QR này đã có trong danh sách.": "The accounts in this QR are already in the list.",
    "Còn thiếu QR số {nums} — bấm \"Tiếp theo\" trên điện thoại và đưa QR đó vào.":
        "Still missing QR #{nums} — tap \"Next\" on your phone and add that QR.",
    "Đã đọc đủ tất cả mã QR.": "All QR codes have been read.",
    "{n} ảnh không đọc được QR.": "{n} image(s) had no readable QR.",
    "Đã có trong app — bỏ chọn sẵn để tránh trùng": "Already in the app — unchecked to avoid duplicates",
    "{n} số": "{n} digits",
}
