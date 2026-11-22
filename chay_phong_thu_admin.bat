@echo off
:: chay_phong_thu_admin.bat - Tự động xin quyền Administrator và khởi chạy toàn bộ Phân hệ Phòng thủ (NIDS + HIPS)
chcp 65001 >nul
title KHỞI CHẠY HỆ THỐNG PHÒNG THỦ NIDS & HIPS

:: Kiểm tra quyền Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Đang kích hoạt hộp thoại nâng quyền Administrator (UAC)...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ======================================================================
echo    🛡️ KHỞI CHẠY HỆ THỐNG BẢO MẬT & PHÒNG THỦ (NIDS & HIPS GUARDS)
echo ======================================================================
echo [*] Quyền hạn hiện tại: ADMINISTRATOR (Đã sẵn sàng mở Raw Socket và Firewall)
echo.

echo [1/2] Đang mở tiến trình HIPS Guard (Cổng thi hành Tường lửa Kernel UDP 9999)...
start "🛡️ [1] HIPS GUARD - BÀN TAY THI HÀNH TƯỜNG LỬA" cmd /k "python part2_defense\hips_guard.py"

timeout /t 2 /nobreak >nul

echo [2/2] Đang mở tiến trình NIDS Engine (Mắt thần Sniffer gói tin mạng)...
start "📡 [2] NIDS ENGINE - MẮT THẦN BẮT GÓI THỤ ĐỘNG" cmd /k "python part2_defense\nids_engine.py"

echo.
echo [✓] CẢ 2 TIẾN TRÌNH PHÒNG THỦ ĐÃ KHỞI CHẠY THÀNH CÔNG TRONG 2 CỬA SỔ ADMIN!
echo [*] Bạn có thể mở giao diện Attacker (chay_attacker_gui.bat) để bắt đầu kiểm thử.
echo ======================================================================
pause
