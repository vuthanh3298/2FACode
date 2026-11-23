#!/usr/bin/env bash
# Build "2FA Code.app" cho macOS. Chạy từ thư mục repo:  ./build_mac.sh
# Kết quả: dist/2FA Code.app
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"

# Kiểm tra Python >= 3.10 và Tk >= 8.6 (Python hệ thống của Apple dùng Tk 8.5 cũ, không chạy được)
"$PY" - <<'EOF'
import sys
if sys.version_info < (3, 10):
    sys.exit(f"Cần Python >= 3.10 (đang dùng {sys.version.split()[0]}). Xem README.")
try:
    import tkinter
    tk_ver = tkinter.Tcl().eval("info patchlevel")
except Exception as e:
    sys.exit(f"Python này không có tkinter ({e}). Với Homebrew: brew install python-tk@3.12")
if tuple(int(x) for x in tk_ver.split(".")[:2]) < (8, 6):
    sys.exit(f"Tk {tk_ver} quá cũ, cần >= 8.6. Dùng Python từ python.org hoặc Homebrew.")
print(f"Python {sys.version.split()[0]}, Tk {tk_ver}")
EOF

if [ ! -d .venv ]; then
    "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

rm -rf build "dist/2FA Code.app"
pyinstaller --noconfirm --clean --windowed \
    --name "2FA Code" \
    --icon icon.ico \
    --osx-bundle-identifier com.twofacode.app \
    --add-data "icon.ico:." \
    --collect-data customtkinter \
    --collect-all tkinterdnd2 \
    --hidden-import keyring.backends.macOS \
    app.py

echo
echo "Xong: dist/2FA Code.app"
echo "Cài: kéo vào Applications, hoặc:  cp -R \"dist/2FA Code.app\" /Applications/"
