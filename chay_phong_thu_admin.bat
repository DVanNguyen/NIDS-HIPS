@echo off
:: chay_phong_thu_admin.bat - Tự động xin quyền Administrator và khởi chạy Trung Tâm Phòng Thủ SOC (NIDS + HIPS)
chcp 65001 >nul
title TRUNG TÂM PHÒNG THỦ MẠNG SOC: NIDS & HIPS CONTROLLER

:: Kiểm tra quyền Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Đang yêu cầu quyền Administrator (UAC) để điều khiển Tường lửa Windows Defender...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ======================================================================
echo    🛡️ TRUNG TÂM PHÒNG THỦ MẠNG SOC: NIDS & HIPS (ADMINISTRATOR)
echo ======================================================================
echo [*] Đang khởi chạy Giao Diện Điều Hành SOC và Bộ Phản Đòn...
python gui_launcher.py
pause
