@echo off
:: chay_attacker_gui.bat - Khởi chạy Giao diện Desktop Đồ họa của Máy Tấn Công
chcp 65001 >nul
cd /d "%~dp0"
title RED TEAM EXPLOIT CONSOLE

:: Tự động kiểm tra thư viện CustomTkinter trên máy tấn công mới
python -c "import customtkinter" >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Đang cài đặt tự động thư viện giao diện CustomTkinter cho Máy Tấn Công...
    pip install customtkinter
)

python part1_attacker\attacker_gui.py
pause
