# Build "2FA Code.exe" cho Windows. Chạy từ thư mục repo:  .\build_windows.ps1
# Kết quả: dist\2FA Code.exe (1 file, không có cửa sổ console)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

& .\.venv\Scripts\pyinstaller.exe --noconfirm --clean --onefile --windowed `
    --name "2FA Code" `
    --icon icon.ico `
    --add-data "icon.ico;." `
    --collect-data customtkinter `
    --collect-all tkinterdnd2 `
    app.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Xong: dist\2FA Code.exe"
