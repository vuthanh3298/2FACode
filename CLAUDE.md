# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

"2FA Code" is a desktop TOTP authenticator for Windows and macOS, written in Python with customtkinter. It is a single-script app (`app.py`) plus a translation table (`i18n.py`). There is no test suite or linter config. Code comments, docstrings, UI strings and the README are in Vietnamese.

## Commands

```bash
pip install -r requirements.txt   # keyring + cryptography are installed on macOS only (env markers)
python app.py                     # run from source (Python 3.10+; macOS needs Tk 8.6, not Apple's /usr/bin/python3)
python make_icon.py               # regenerate icon.ico (also writes icon_preview.png)

.\build_windows.ps1               # -> dist\2FA Code.exe (onefile, windowed)
bash build_mac.sh                 # -> dist/2FA Code.app (PYTHON=python3.12 to pick an interpreter)
```

Both build scripts create `.venv`, install `requirements.txt`, and call PyInstaller with the same data flags. `icon.ico` must be bundled because `resource_path()` reads from `sys._MEIPASS`. If you change the PyInstaller flags, keep the two scripts in sync. `dist/2FA Code.exe` is committed. The Mac `.app` is not; each Mac user builds their own.

## Platform branching

Platform-specific code is gated on `IS_WIN` / `IS_MAC` in `app.py`. The Windows paths are the original behavior and must stay unchanged. Each concern has a branch:

- **Storage:** `_protect` / `_unprotect` dispatch to Windows DPAPI (`_dpapi` via ctypes `crypt32`) or, on macOS, to Fernet with a random key in the Keychain (`_mac_fernet`, service `TwoFACode`, via the explicit `keyring.backends.macOS` backend so PyInstaller needs no entry-point discovery). A new Keychain key is created only when `accounts.dat` doesn't exist yet. If loading fails on macOS, `App.read_only` blocks `persist()` so an empty list can't overwrite the existing file.
- **Data dir:** `%APPDATA%\TwoFACode` on Windows, `~/Library/Application Support/TwoFACode` on macOS. `accounts.dat` (encrypted JSON list, written atomically via tmp + `os.replace`) and plain `settings.json` live there.
- **Clipboard change detection** (`clipboard_seq`, used by the dialogs' `_watch_clipboard`): `GetClipboardSequenceNumber` on Windows, `NSPasteboard.changeCount` through raw `objc_msgSend` ctypes calls on macOS. There is no PyObjC dependency.
- **Screen capture** (`pick_from_screen` → `RegionPicker`): Windows grabs all monitors at the virtual-screen origin. macOS grabs the main display only, at Retina pixel size. `RegionPicker` keeps `self.full` (scanned and cropped) separate from `self.shot` (displayed at screen points) and converts coordinates between them with `scale`. With `scale == 1` they are the same image.
- **Input:** `MOD` (`Control`/`Command`) is used for shortcut bindings, and `RIGHT_CLICK` lists the right-click event sequences for each platform. Use these instead of hard-coding `<Control-…>` or `<Button-3>`.
- **Fonts/icon:** `FONT` is Segoe UI on Windows and Helvetica Neue on macOS. `set_icon` uses `iconbitmap(.ico)` on Windows and `iconphoto` elsewhere. On Mac, PyInstaller converts the `.ico` to `.icns`.

## Architecture (app.py)

The file is split into sections by `# ---` banner comments:

- **TOTP / parsing (pure functions):** `totp()` implements RFC 6238 using only the stdlib (`hmac`/`hashlib`). `parse_otpauth()` handles `otpauth://` URIs. `parse_migration()` decodes Google Authenticator export QR codes (`otpauth-migration://offline?data=...`) with a small hand-written protobuf reader (`_read_varint`, `_pb_fields`) and returns batch info so multi-QR exports can be merged. `scan_qr()`/`decode_qr()` use `zxingcpp`.
- **Account dict:** `name`, `secret`, `digits`, `period`, `algorithm`, and optionally `prefix`/`suffix`, plus `show_joined` (when true, the main-screen card displays the full joined string instead of only the OTP; it is saved only when a prefix or suffix is set). These are stored unstripped and only when non-empty, so read them with `.get(..., "")`. `App.copy()` puts `prefix + OTP + suffix` on the clipboard (used for VPN logins that take password+OTP in one field). `copy(card, code_only=True)` copies the bare OTP.
- **Theming:** every color constant is a `(light, dark)` tuple that customtkinter consumes directly. Use `pick(color)` when you need the resolved value for raw tk/PIL drawing.
- **UI classes:**
  - `App` (main window, `ctk.CTk` + optional `TkinterDnD.DnDWrapper`) holds `self.accounts` and a list of `AccountCard` widgets. It refreshes codes from a `tick()` loop aligned to the wall-clock second.
  - `AccountDialog` (add/edit) and `ImportDialog` (Google Authenticator import) are `CTkToplevel`s. They accept secrets from typed text, drag-and-drop, clipboard polling, image files, or a screen-region capture.
- **Optional dependency:** `tkinterdnd2` is wrapped in try/except. Drag-and-drop must degrade gracefully when it is missing (`TkinterDnD is None`).

## i18n

- The Vietnamese source string is the translation key: wrap UI text in `tr("...")` and add the English translation to the `EN` dict in `i18n.py`. Placeholders use `{name}` with keyword args: `tr("Đã thêm {name}", name=...)`.
- Keys must match exactly, including leading spaces and emoji/glyph prefixes (e.g. `"  Copy mã"`, `"＋  Thêm"`). An untranslated key silently falls back to Vietnamese.
- Write shortcut hints in their Windows form (`Ctrl+V`, `Win+Shift+S`). On macOS, `tr()` rewrites them to `⌘V` and `⌘⌃⇧4` via `_MAC_KEYS`, so keys stay platform-neutral.
- Switching language (`App.set_language`) destroys every child widget, including open dialogs, and calls `build_ui()` again. So any UI state that must survive a language switch has to be stored on `App` and restored afterward, the way the search query is.
