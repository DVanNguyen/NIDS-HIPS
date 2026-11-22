@echo off
:: chay_attacker_gui.bat - Khởi chạy Giao diện Desktop Đồ họa của Kẻ tấn công
chcp 65001 >nul
cd /d "%~dp0"
title RED TEAM EXPLOIT CONSOLE
python part1_attacker\attacker_gui.py
pause
