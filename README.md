# 2FA Code

Ứng dụng desktop lấy mã 2FA (TOTP) cho **Windows** và **macOS**, viết bằng Python + customtkinter.

- Thêm tài khoản bằng secret key, link `otpauth://`, hoặc mã QR (dán ảnh, kéo-thả, chọn file, chọn vùng màn hình).
- Nhập hàng loạt từ Google Authenticator (QR "Chuyển tài khoản / Xuất tài khoản").
- Click vào tài khoản để copy mã; ô tìm kiếm, Enter copy mã đầu tiên.
- **Ghép mật khẩu khi copy** (Thêm/Sửa tài khoản → "Ghép mật khẩu khi copy"): điền chuỗi vào prefix/suffix,
  click sẽ copy `<prefix><OTP><suffix>`. Dùng cho OpenVPN và các app chỉ có 1 ô password (mật khẩu + OTP).
  Tài khoản có ghép hiện biểu tượng 🔑; chuột phải → "Copy chỉ mã OTP" để lấy riêng mã.
  Tick "Hiện mật khẩu (cả ở màn hình chính)" thì thẻ ở màn hình chính hiện đúng chuỗi sẽ copy
  (chuỗi dài được cắt bớt phần đầu, luôn thấy trọn mã OTP); không tick thì thẻ chỉ hiện mã OTP.
  Chuỗi này được mã hoá cùng secret.
- Giao diện Sáng / Tối / Theo hệ thống, tiếng Việt / English.

Secret được mã hoá trên máy, không gửi đi đâu:

| | Nơi lưu | Mã hoá |
|---|---|---|
| Windows | `%APPDATA%\TwoFACode\accounts.dat` | Windows DPAPI (chỉ user Windows đó giải mã được) |
| macOS | `~/Library/Application Support/TwoFACode/accounts.dat` | Fernet, khoá ngẫu nhiên lưu trong Keychain (mục `TwoFACode`) |

---

## Build trên macOS

### 1. Cài Python 3.10+ có Tk 8.6

**Không dùng** `/usr/bin/python3` của Apple: bản đó đi kèm Tk 8.5 cũ, giao diện sẽ lỗi. Chọn một trong hai:

- **python.org** (đơn giản nhất): tải bản macOS universal installer mới nhất ở https://www.python.org/downloads/macos/ rồi cài. Lệnh là `python3`.
- **Homebrew**:
  ```bash
  brew install python@3.12 python-tk@3.12
  ```
  Lệnh là `python3.12`.

Kiểm tra:
```bash
python3 -c "import sys, tkinter; print(sys.version, tkinter.Tcl().eval('info patchlevel'))"
```
Phải ra Python ≥ 3.10 và Tk ≥ 8.6.

### 2. Build

```bash
git clone <url-repo> 2fa-code
cd 2fa-code
bash build_mac.sh
```

Nếu Python của bạn không phải `python3` (vd. Homebrew):
```bash
PYTHON=python3.12 bash build_mac.sh
```

Script sẽ tạo `.venv`, cài thư viện trong `requirements.txt`, rồi đóng gói bằng PyInstaller.
Kết quả: **`dist/2FA Code.app`**. Kéo vào thư mục Applications là dùng được.

App build theo kiến trúc của máy đang build (Apple Silicon → arm64, Intel → x86_64).

### 3. Lần chạy đầu

- **Keychain**: macOS hỏi "2FA Code wants to use your confidential information stored in "TwoFACode" in your keychain" → nhập mật khẩu máy và bấm **Always Allow**.
  Mỗi lần build lại, app có chữ ký mới nên macOS sẽ hỏi lại một lần nữa — bình thường.
  Nếu lỡ bấm **Deny**, app sẽ báo không đọc được dữ liệu và không cho lưu (để tránh ghi đè dữ liệu cũ); mở lại app và bấm Allow.
- **Ghi màn hình** (chỉ cần nếu dùng nút "✂ Chọn vùng màn hình"): vào **System Settings → Privacy & Security → Screen Recording**, bật cho **2FA Code**, rồi mở lại app. Nếu chưa cấp quyền, ảnh chụp chỉ có hình nền nên sẽ không tìm thấy QR.

### Phím tắt trên macOS

| Windows | macOS | Tác dụng |
|---|---|---|
| Ctrl+N | ⌘N | Thêm tài khoản |
| Ctrl+F | ⌘F | Tìm kiếm |
| Ctrl+V | ⌘V | Dán ảnh QR / secret |
| Win+Shift+S | ⌘⌃⇧4 | Chụp vùng màn hình vào clipboard (app tự nhận QR) |
| Chuột phải | Chuột phải / Ctrl+click | Menu của tài khoản |

### Lưu ý trên macOS

- "Chọn vùng màn hình" chỉ chụp **màn hình chính** (Windows chụp được mọi màn hình).
- Gửi file `.app` đã build cho người khác: app không được ký bằng Apple Developer ID nên Gatekeeper sẽ chặn. Người nhận chạy lệnh sau một lần (hoặc chuột phải → Open):
  ```bash
  xattr -dr com.apple.quarantine "/Applications/2FA Code.app"
  ```
  Cách khuyến nghị vẫn là mỗi người tự build từ source.
- Dữ liệu macOS và Windows không dùng chung được (khoá mã hoá gắn với máy). Chuyển máy bằng cách thêm lại tài khoản hoặc xuất QR từ Google Authenticator.

---

## Build trên Windows

Cần Python 3.10+ (python.org, tick "Add to PATH").

```powershell
.\build_windows.ps1
```

Kết quả: `dist\2FA Code.exe` (một file, không cần cài).

---

## Chạy trực tiếp từ source (để phát triển)

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Tạo lại `icon.ico` (cần Pillow): `python make_icon.py`.
